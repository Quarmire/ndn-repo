//! Cross-repo **erasure coding** (G6): stripe an object into N = K+R shards across
//! cluster nodes (one shard per node, via [`ClusterState::shard_holders`]) and recover
//! the whole object from **any K** — so the cluster survives R node losses per object at
//! a fraction of the storage of R+1 full replicas.
//!
//! Pure synergy of existing pieces: the F1 systematic K-of-N codec
//! ([`ndn_coding`]'s `Encoder`/`Decoder`) over a single object's bytes, plus a manifest
//! that indexes the shards. The object is split into K equal source segments (padded to a
//! multiple of K); the codec adds R parity segments; each segment is one shard. The K
//! source shards are the object itself sliced K ways (systematic), so a reader holding all
//! K sources reassembles with no decode.
//!
//! This module is the placement-agnostic mechanism (encode / reconstruct / manifest);
//! [`ClusterState::shard_holders`] is the cluster-side shard→node map. Wiring it into the
//! claim/fetch/store loop (a node stores *its* shard on claim; a read gathers K shards) is
//! the embedder's integration, exactly as whole-object ingest is today.
//!
//! [`ClusterState::shard_holders`]: crate::coord::ClusterState::shard_holders

use bytes::Bytes;
use ndn_coding::{CodingError, Decoder, Encoder};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};

/// Name component marking an erasure shard: `<object>/EC/<index>`.
pub const EC_KEYWORD: &str = "EC";

/// Indexes an object's erasure shards: the K-of-N parameters + what's needed to trim the
/// reassembled segments back to the exact original object. Published as named Data so any
/// reader can discover the shard names and reconstruct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureManifest {
    pub object: Name,
    /// Source segments (any K of the N shards reconstruct the object).
    pub k: u16,
    /// Total shards = K + redundancy.
    pub n: u16,
    /// Exact original object length (segments are padded; this trims the tail).
    pub original_len: u64,
    /// Per-segment length (all segments are equal-length for the codec).
    pub shard_len: u32,
    /// SHA-256 of each shard's coded bytes, in index order (`n` entries). Reconstruction
    /// verifies every shard against its hash before using it, so a single corrupted or
    /// malicious holder can't silently poison the recovered object (systematic RS recovery
    /// trusts its K inputs). NB: the manifest itself must be authenticated out-of-band
    /// (bound to the object's trust) — a forged manifest can still lie about hashes.
    pub shard_hashes: Vec<[u8; 32]>,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

impl ErasureManifest {
    /// The name of shard `index`: `<object>/EC/<index>`.
    pub fn shard_name(&self, index: u16) -> Name {
        self.object
            .clone()
            .append(EC_KEYWORD)
            .append(index.to_string())
    }

    /// All N shard names, in index order.
    pub fn shard_names(&self) -> Vec<Name> {
        (0..self.n).map(|i| self.shard_name(i)).collect()
    }

    /// Compact wire form:
    /// `k(2) n(2) original_len(8) shard_len(4) name_len(4) ‖ name-TLV ‖ n×32 shard-hashes`,
    /// all big-endian. The object name is encoded as **TLV** (not a URI) so name components
    /// with arbitrary bytes round-trip faithfully.
    pub fn to_bytes(&self) -> Bytes {
        let name_tlv = self.object.encode_to_tlv();
        let name_tlv = name_tlv.as_ref();
        let mut v = Vec::with_capacity(20 + name_tlv.len() + 32 * self.shard_hashes.len());
        v.extend_from_slice(&self.k.to_be_bytes());
        v.extend_from_slice(&self.n.to_be_bytes());
        v.extend_from_slice(&self.original_len.to_be_bytes());
        v.extend_from_slice(&self.shard_len.to_be_bytes());
        v.extend_from_slice(&(name_tlv.len() as u32).to_be_bytes());
        v.extend_from_slice(name_tlv);
        for h in &self.shard_hashes {
            v.extend_from_slice(h);
        }
        Bytes::from(v)
    }

    /// Parse [`to_bytes`](Self::to_bytes). `None` if truncated or malformed.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 20 {
            return None;
        }
        let k = u16::from_be_bytes([b[0], b[1]]);
        let n = u16::from_be_bytes([b[2], b[3]]);
        let original_len = u64::from_be_bytes(b[4..12].try_into().ok()?);
        let shard_len = u32::from_be_bytes(b[12..16].try_into().ok()?);
        let name_len = u32::from_be_bytes(b[16..20].try_into().ok()?) as usize;
        let name_end = 20usize.checked_add(name_len)?;
        let name_tlv = b.get(20..name_end)?;
        let object = Name::decode_from_tlv(Bytes::copy_from_slice(name_tlv)).ok()?;
        let hashes = b.get(name_end..)?;
        if hashes.len() != 32 * n as usize {
            return None;
        }
        let shard_hashes = hashes.chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
        Some(Self {
            object,
            k,
            n,
            original_len,
            shard_len,
            shard_hashes,
        })
    }
}

/// One erasure shard: its index (0..K source, K..N parity), derived name, and bytes.
#[derive(Clone, Debug)]
pub struct Shard {
    pub index: u16,
    pub name: Name,
    pub bytes: Bytes,
}

/// Erasure-code `data` for `object` into N = K + `redundancy` systematic shards (sources
/// `0..K`, parity `K..N`); any K reconstruct the object. Returns the shards + the manifest
/// indexing them.
pub fn encode_object(
    object: &Name,
    data: &[u8],
    k: u16,
    redundancy: u16,
) -> Result<(Vec<Shard>, ErasureManifest), CodingError> {
    let n = k.checked_add(redundancy).filter(|n| *n <= 255 && k >= 1);
    let n = match n {
        Some(n) => n,
        None => return Err(CodingError::InvalidParameters { k, n: k }),
    };

    // Split into K equal source segments, padding the object up to K * shard_len.
    let shard_len = data.len().div_ceil(k as usize).max(1);
    let mut padded = data.to_vec();
    padded.resize(shard_len * k as usize, 0);

    let mut manifest = ErasureManifest {
        object: object.clone(),
        k,
        n,
        original_len: data.len() as u64,
        shard_len: shard_len as u32,
        shard_hashes: Vec::with_capacity(n as usize),
    };

    let mut enc = Encoder::new(k, n)?;
    let mut shards = Vec::with_capacity(n as usize);
    for i in 0..k {
        let start = i as usize * shard_len;
        let seg = Bytes::copy_from_slice(&padded[start..start + shard_len]);
        enc.feed(seg.clone())?;
        manifest.shard_hashes.push(sha256(&seg));
        shards.push(Shard {
            index: i,
            name: manifest.shard_name(i),
            bytes: seg,
        });
    }
    for index in k..n {
        let parity = enc.parity(index)?;
        manifest.shard_hashes.push(sha256(&parity));
        shards.push(Shard {
            index,
            name: manifest.shard_name(index),
            bytes: parity,
        });
    }
    Ok((shards, manifest))
}

/// Reconstruct the object from **any K** of its shards (each `(index, bytes)`). Each shard
/// is verified against the manifest's per-shard hash before use — a shard that fails (wrong
/// bytes, forged, or malformed) is skipped, and reconstruction proceeds from the remaining
/// good ones — so a corrupted holder can't silently produce wrong data. Returns `None` if
/// fewer than K *verified* shards are supplied.
pub fn reconstruct(manifest: &ErasureManifest, shards: &[(u16, Bytes)]) -> Option<Bytes> {
    let mut dec = Decoder::new(manifest.k, manifest.n).ok()?;
    for (index, bytes) in shards {
        // Integrity gate: only a shard whose bytes match the manifest hash for its index
        // is fed to the codec.
        if manifest.shard_hashes.get(*index as usize).map(|h| sha256(bytes) == *h) != Some(true) {
            continue;
        }
        if dec.absorb(*index, bytes.clone()).is_err() {
            continue; // malformed for the codec — skip, try the rest
        }
        if dec.is_complete() {
            break;
        }
    }
    if !dec.is_complete() {
        return None;
    }
    let segs = dec.recover().ok()?;
    let mut out = Vec::with_capacity(manifest.original_len as usize);
    for seg in segs.iter().take(manifest.k as usize) {
        out.extend_from_slice(seg);
    }
    out.truncate(manifest.original_len as usize);
    Some(Bytes::from(out))
}

/// The named Data for a shard: `<object>/EC/<index>` with the coded bytes as Content,
/// digest-signed. The data plane stores it (`ndn_repo::Repo::store_data`) / serves it like
/// any Data — a holder keeps just its one shard, a tenth of an R+1-replica footprint.
pub fn shard_data(shard: &Shard) -> Bytes {
    DataBuilder::new(shard.name.clone(), &shard.bytes).sign_digest_sha256()
}

/// Reconstruct the object by fetching its shards via `fetch` — a closure returning a
/// shard's Data **wire** for a name (e.g. `Repo::get`, or a network fetch over the
/// forwarder), or `None` if that holder doesn't have it. Gathers all reachable shards and
/// hands them to [`reconstruct`], which verifies each against the manifest hash and uses
/// the first K good ones — so it tolerates both the R unreachable shards *and* corrupted
/// holders (a bad shard is skipped, not trusted).
pub fn reconstruct_with(
    manifest: &ErasureManifest,
    mut fetch: impl FnMut(&Name) -> Option<Bytes>,
) -> Option<Bytes> {
    let mut shards: Vec<(u16, Bytes)> = Vec::new();
    for i in 0..manifest.n {
        if let Some(wire) = fetch(&manifest.shard_name(i))
            && let Ok(data) = Data::decode(wire)
            && let Some(content) = data.content()
        {
            shards.push((i, content.clone()));
        }
    }
    reconstruct(manifest, &shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj() -> Name {
        "/repo/dataset/v=1".parse().unwrap()
    }

    #[test]
    fn round_trips_from_any_k_shards() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let (shards, manifest) = encode_object(&obj(), &data, 4, 2).unwrap();
        assert_eq!(shards.len(), 6, "K=4 + R=2 shards");
        assert_eq!(shards[0].name, "/repo/dataset/v=1/EC/0".parse().unwrap());

        // Recover from shards {1,3,4,5} — i.e. lose two sources (0 and 2), use parity.
        let subset: Vec<(u16, Bytes)> = shards
            .iter()
            .filter(|s| s.index != 0 && s.index != 2)
            .map(|s| (s.index, s.bytes.clone()))
            .collect();
        assert_eq!(subset.len(), 4);
        let got = reconstruct(&manifest, &subset).expect("K shards reconstruct");
        assert_eq!(got.as_ref(), data.as_slice(), "exact object recovered");
    }

    #[test]
    fn systematic_sources_reassemble_without_parity() {
        let data: Vec<u8> = (0..1234u32).map(|i| i as u8).collect();
        let (shards, manifest) = encode_object(&obj(), &data, 5, 3).unwrap();
        // Hold exactly the K source shards (0..5): no decode needed, just reassembly.
        let sources: Vec<(u16, Bytes)> = shards
            .iter()
            .take(manifest.k as usize)
            .map(|s| (s.index, s.bytes.clone()))
            .collect();
        let got = reconstruct(&manifest, &sources).expect("sources reassemble");
        assert_eq!(got.as_ref(), data.as_slice());
    }

    #[test]
    fn fewer_than_k_cannot_reconstruct() {
        let data = vec![7u8; 300];
        let (shards, manifest) = encode_object(&obj(), &data, 4, 2).unwrap();
        // Only 3 < K=4 shards → no recovery.
        let too_few: Vec<(u16, Bytes)> =
            shards.iter().take(3).map(|s| (s.index, s.bytes.clone())).collect();
        assert!(reconstruct(&manifest, &too_few).is_none());
    }

    #[test]
    fn data_plane_round_trips_through_distributed_shards() {
        use std::collections::HashMap;
        // Producer encodes + stores each shard as named Data (one per holder).
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 7) as u8).collect();
        let (shards, manifest) = encode_object(&obj(), &data, 4, 2).unwrap();
        let mut cluster: HashMap<Name, Bytes> = HashMap::new();
        for s in &shards {
            cluster.insert(s.name.clone(), shard_data(s));
        }

        // Reader gathers shards over the "network" (here the map) and reconstructs.
        let got = reconstruct_with(&manifest, |name| cluster.get(name).cloned())
            .expect("reconstructs from the stored shards");
        assert_eq!(got.as_ref(), data.as_slice(), "object recovered from distributed shards");

        // Lose R=2 holders (drop two shard Data) — any K=4 of the 6 still recover.
        cluster.remove(&manifest.shard_name(0));
        cluster.remove(&manifest.shard_name(3));
        let got = reconstruct_with(&manifest, |name| cluster.get(name).cloned())
            .expect("K shards remain");
        assert_eq!(got.as_ref(), data.as_slice(), "recovered despite two lost holders");

        // Lose a third (only 3 < K reachable) — reconstruction fails (no false data).
        cluster.remove(&manifest.shard_name(1));
        assert!(
            reconstruct_with(&manifest, |name| cluster.get(name).cloned()).is_none(),
            "fewer than K reachable ⇒ no reconstruction"
        );
    }

    #[test]
    fn manifest_codec_round_trips() {
        let (_, manifest) = encode_object(&obj(), &[1, 2, 3], 4, 2).unwrap();
        let decoded = ErasureManifest::from_bytes(&manifest.to_bytes()).expect("parses");
        assert_eq!(decoded, manifest);
        assert!(ErasureManifest::from_bytes(&[0u8; 4]).is_none(), "truncated rejected");
    }

    #[test]
    fn manifest_carries_a_hash_per_shard() {
        let (shards, manifest) = encode_object(&obj(), &[9u8; 800], 4, 2).unwrap();
        assert_eq!(manifest.shard_hashes.len(), shards.len(), "one hash per shard");
        for s in &shards {
            assert_eq!(
                manifest.shard_hashes[s.index as usize],
                sha256(&s.bytes),
                "the manifest hash matches the shard bytes"
            );
        }
    }

    #[test]
    fn corrupted_shard_is_skipped_not_trusted() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let (shards, manifest) = encode_object(&obj(), &data, 4, 2).unwrap();

        // Forge shard 1's bytes (a malicious / bit-rotted holder). With it included we
        // still have 5 candidates ⇒ K=4 good ones remain, so recovery must (a) reject the
        // forged shard and (b) still return the *correct* object — never the wrong bytes.
        let mut tampered: Vec<(u16, Bytes)> =
            shards.iter().map(|s| (s.index, s.bytes.clone())).collect();
        tampered[1].1 = Bytes::from(vec![0xFFu8; tampered[1].1.len()]);

        let got = reconstruct(&manifest, &tampered).expect("K good shards remain");
        assert_eq!(got.as_ref(), data.as_slice(), "a forged shard never corrupts the output");

        // If corrupting it leaves only 3 good shards (< K), recovery fails closed rather
        // than absorbing bad bytes.
        let mut starved: Vec<(u16, Bytes)> =
            shards.iter().take(4).map(|s| (s.index, s.bytes.clone())).collect();
        starved[0].1 = Bytes::from(vec![0xFFu8; starved[0].1.len()]);
        assert!(
            reconstruct(&manifest, &starved).is_none(),
            "with too few verified shards, reconstruction fails rather than trusting forged bytes"
        );
    }
}

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
use ndn_packet::Name;

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

    /// Compact wire form: `k(2 BE) n(2 BE) original_len(8 BE) shard_len(4 BE) ‖ object-URI`.
    pub fn to_bytes(&self) -> Bytes {
        let uri = self.object.to_string();
        let mut v = Vec::with_capacity(16 + uri.len());
        v.extend_from_slice(&self.k.to_be_bytes());
        v.extend_from_slice(&self.n.to_be_bytes());
        v.extend_from_slice(&self.original_len.to_be_bytes());
        v.extend_from_slice(&self.shard_len.to_be_bytes());
        v.extend_from_slice(uri.as_bytes());
        Bytes::from(v)
    }

    /// Parse [`to_bytes`](Self::to_bytes). `None` if truncated or the URI is invalid.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 16 {
            return None;
        }
        let k = u16::from_be_bytes([b[0], b[1]]);
        let n = u16::from_be_bytes([b[2], b[3]]);
        let original_len = u64::from_be_bytes(b[4..12].try_into().ok()?);
        let shard_len = u32::from_be_bytes(b[12..16].try_into().ok()?);
        let object: Name = std::str::from_utf8(&b[16..]).ok()?.parse().ok()?;
        Some(Self {
            object,
            k,
            n,
            original_len,
            shard_len,
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

    let manifest = ErasureManifest {
        object: object.clone(),
        k,
        n,
        original_len: data.len() as u64,
        shard_len: shard_len as u32,
    };

    let mut enc = Encoder::new(k, n)?;
    let mut shards = Vec::with_capacity(n as usize);
    for i in 0..k {
        let start = i as usize * shard_len;
        let seg = Bytes::copy_from_slice(&padded[start..start + shard_len]);
        enc.feed(seg.clone())?;
        shards.push(Shard {
            index: i,
            name: manifest.shard_name(i),
            bytes: seg,
        });
    }
    for index in k..n {
        shards.push(Shard {
            index,
            name: manifest.shard_name(index),
            bytes: enc.parity(index)?,
        });
    }
    Ok((shards, manifest))
}

/// Reconstruct the object from **any K** of its shards (each `(index, bytes)`). Returns
/// `None` if fewer than K distinct shards are supplied or decoding fails.
pub fn reconstruct(manifest: &ErasureManifest, shards: &[(u16, Bytes)]) -> Option<Bytes> {
    let mut dec = Decoder::new(manifest.k, manifest.n).ok()?;
    for (index, bytes) in shards {
        dec.absorb(*index, bytes.clone()).ok()?;
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
    fn manifest_codec_round_trips() {
        let (_, manifest) = encode_object(&obj(), &[1, 2, 3], 4, 2).unwrap();
        let decoded = ErasureManifest::from_bytes(&manifest.to_bytes()).expect("parses");
        assert_eq!(decoded, manifest);
        assert!(ErasureManifest::from_bytes(&[0u8; 4]).is_none(), "truncated rejected");
    }
}

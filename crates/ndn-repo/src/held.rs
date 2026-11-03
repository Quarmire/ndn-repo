//! Storage for a **custody holder**: the device's own state kept plainly,
//! everything it holds for others erasure-coded across stripes.
//!
//! [`HolderStore`] is the [`DataStore`] an `ndn_data::Device` running as a
//! holder keeps its packets in. It splits by name:
//!
//! * **own** — names under the device's own name `<D>` (its log, summaries,
//!   leases) and under `/localhost`: a plain [`FjallStore`] at `<dir>/own`.
//! * **held** — every other name (the log entries, manifests and chunks it
//!   keeps for other devices): an [`ErasureStore`] at `<dir>/held`, `n`
//!   stripe stores `<dir>/held/<i>` of which any `k` suffice.
//!
//! The `k/n` the held packets were coded with is recorded in `<dir>/erasure`
//! and a store opened with other parameters is refused, saying which to use.
//!
//! # Per-packet coding
//!
//! Each held packet's wire is split into `k` equal source shards (the last
//! padded with zeros) and `n - k` parity shards by the workspace's systematic
//! Reed-Solomon codec ([`ndn_coding`]); shard `i` is stored under the
//! packet's own name in stripe `i`, as
//! `index(1) ‖ wire length(4, BE) ‖ SHA-256(wire)(32) ‖ SHA-256(shard)(32) ‖ shard`.
//! A read gathers the stripes' shards, drops any whose own digest or index
//! does not match (bit rot, a stripe put back in the wrong place), decodes
//! from any `k` that agree on the wire digest, checks the result against it
//! and rewrites every stripe that lacked a good shard (repair). Fewer than
//! `k` good shards: the packet is missing — the store answers nothing, so an
//! audit of it finds it missing rather than served from guesswork.
//!
//! # Losing a stripe
//!
//! A stripe is one directory `<dir>/held/<i>`; put each on its own disk
//! (mount it there) to make "a stripe" mean "a disk". Losing up to `n - k`
//! whole stripes (the directory deleted, the disk replaced by an empty one)
//! loses nothing: the next read of each packet rebuilds it from the others
//! and repairs the empty stripes. Losing more makes the packets they held
//! missing.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};

use bytes::Bytes;
use ndn_coding::{CodingError, Decoder, Encoder};
use ndn_packet::Name;
use ndn_storage::name_key;
use ndn_sync::DataStore;

use crate::FjallStore;

/// Octets before a shard's bytes: index, wire length, wire digest, shard digest.
const HEADER: usize = 1 + 4 + 32 + 32;

/// The file under a [`HolderStore`]'s directory recording its [`Erasure`].
const ERASURE_RECORD: &str = "erasure";

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// The `k`-of-`n` parameters: every packet becomes `n` shards, any `k` of
/// which rebuild it, so `n - k` stripes may be lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Erasure {
    k: u16,
    n: u16,
}

impl Erasure {
    /// `k` of `n`, with `1 ≤ k ≤ n ≤ 255` (the codec works over GF(2^8)).
    pub fn new(k: u16, n: u16) -> Result<Self, HeldError> {
        if k == 0 || n < k || n > 255 {
            return Err(HeldError::Parameters { k, n });
        }
        Ok(Self { k, n })
    }

    /// Shards that rebuild a packet.
    pub fn k(&self) -> u16 {
        self.k
    }

    /// Shards (and stripes) per packet.
    pub fn n(&self) -> u16 {
        self.n
    }
}

impl Default for Erasure {
    /// 2 of 3: one stripe may be lost, at 1.5× the packets' size.
    fn default() -> Self {
        Self { k: 2, n: 3 }
    }
}

impl fmt::Display for Erasure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.k, self.n)
    }
}

impl FromStr for Erasure {
    type Err = HeldError;

    /// `<k>/<n>`, e.g. `2/3`.
    fn from_str(s: &str) -> Result<Self, HeldError> {
        let syntax = || HeldError::Syntax(s.to_string());
        let (k, n) = s.trim().split_once('/').ok_or_else(syntax)?;
        let k = k.trim().parse().map_err(|_| syntax())?;
        let n = n.trim().parse().map_err(|_| syntax())?;
        Self::new(k, n)
    }
}

/// Why a holder store did not open.
#[derive(Debug, thiserror::Error)]
pub enum HeldError {
    /// `k`/`n` out of range.
    #[error(
        "erasure {k}/{n}: need 1 <= k <= n <= 255 (any k of the n stripes rebuild a packet); \
         pick e.g. 2/3"
    )]
    Parameters {
        /// Shards that rebuild a packet.
        k: u16,
        /// Shards per packet.
        n: u16,
    },
    /// Not written `<k>/<n>`.
    #[error("erasure {0:?}: write it as <k>/<n>, e.g. 2/3")]
    Syntax(String),
    /// A directory or the erasure record could not be read or written.
    #[error("{}: {source}; check the store directory's permissions and disk", path.display())]
    Io {
        /// What was being read or written.
        path: PathBuf,
        /// The failure.
        source: std::io::Error,
    },
    /// A stripe's or the own store's engine did not open.
    #[error("open store {}: {source}; check the directory, or move it aside to start it empty", path.display())]
    Open {
        /// The store's directory.
        path: PathBuf,
        /// The engine's failure.
        source: fjall::Error,
    },
    /// The held packets were coded with other parameters.
    #[error(
        "{} records that the held packets were coded {stored}; open it with erasure {stored} \
         (as {asked} they would not decode), or move the store aside to start empty",
        path.display()
    )]
    Mismatch {
        /// The erasure record.
        path: PathBuf,
        /// The parameters the record holds.
        stored: Erasure,
        /// The parameters asked for.
        asked: Erasure,
    },
    /// The erasure record is not `<k>/<n>`.
    #[error(
        "{}: {text:?} is not an erasure record <k>/<n>; write the parameters the store was \
         coded with into it",
        path.display()
    )]
    Record {
        /// The erasure record.
        path: PathBuf,
        /// What it holds.
        text: String,
    },
}

/// One stripe's shard of a packet, checked against its own digest.
struct Shard {
    index: u16,
    len: usize,
    digest: [u8; 32],
    body: Bytes,
}

/// A packet rebuilt from its shards, with the stripes that lacked a good
/// shard of it.
struct Assembled {
    wire: Bytes,
    stale: Vec<usize>,
}

/// A [`DataStore`] that erasure-codes every packet across `n` stripe stores,
/// any `k` of which rebuild it (see the [module docs](self)).
pub struct ErasureStore {
    erasure: Erasure,
    stripes: Vec<FjallStore>,
    /// Serialises writes (insert, remove, repair), so a repair never writes
    /// shards of a wire an insert has just replaced.
    writes: Mutex<()>,
}

impl ErasureStore {
    /// Open (or create) the stripes `<dir>/<i>` for `i` in `0..n`.
    pub fn open(dir: impl AsRef<Path>, erasure: Erasure) -> Result<Self, HeldError> {
        let dir = dir.as_ref();
        let stripes = (0..erasure.n)
            .map(|i| {
                let path = dir.join(i.to_string());
                FjallStore::open(&path).map_err(|source| HeldError::Open { path, source })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            erasure,
            stripes,
            writes: Mutex::new(()),
        })
    }

    /// The parameters packets are coded with.
    pub fn erasure(&self) -> Erasure {
        self.erasure
    }

    /// The `n` shard records of `wire` (at most `u32::MAX` octets), stripe order.
    fn encode(&self, wire: &[u8]) -> Result<Vec<Bytes>, CodingError> {
        let (k, n) = (self.erasure.k as usize, self.erasure.n as usize);
        let len = wire.len() as u32;
        let shard_len = wire.len().div_ceil(k).max(1);
        let digest = sha256(wire);
        let record = |index: usize, shard: &[u8]| {
            let mut r = Vec::with_capacity(HEADER + shard.len());
            r.push(index as u8);
            r.extend_from_slice(&len.to_be_bytes());
            r.extend_from_slice(&digest);
            r.extend_from_slice(&sha256(shard));
            r.extend_from_slice(shard);
            Bytes::from(r)
        };
        let mut enc = Encoder::new(self.erasure.k, self.erasure.n)?;
        let mut out = Vec::with_capacity(n);
        for i in 0..k {
            let start = (i * shard_len).min(wire.len());
            let end = ((i + 1) * shard_len).min(wire.len());
            let mut seg = vec![0u8; shard_len];
            seg[..end - start].copy_from_slice(&wire[start..end]);
            out.push(record(i, &seg));
            enc.feed(Bytes::from(seg))?;
        }
        for i in k..n {
            out.push(record(i, &enc.parity(i as u16)?));
        }
        Ok(out)
    }

    /// Stripe `stripe`'s record of a packet, if it is a good shard of index
    /// `stripe`.
    fn shard(&self, stripe: usize, record: &Bytes) -> Option<Shard> {
        let head = record.get(..HEADER)?;
        if head[0] as usize != stripe {
            return None;
        }
        let len = u32::from_be_bytes(head[1..5].try_into().ok()?) as usize;
        let digest: [u8; 32] = head[5..37].try_into().ok()?;
        let body = record.slice(HEADER..);
        if body.len() != len.div_ceil(self.erasure.k as usize).max(1)
            || sha256(&body) != head[37..69]
        {
            return None;
        }
        Some(Shard {
            index: stripe as u16,
            len,
            digest,
            body,
        })
    }

    /// Rebuild a packet from its stripes' records, or `None` when fewer than
    /// `k` good shards agree on one wire.
    fn assemble(&self, records: &[Option<Bytes>]) -> Option<Assembled> {
        // Good shards grouped by the wire they are shards of.
        let mut groups: Vec<(usize, [u8; 32], Vec<Shard>)> = Vec::new();
        for (i, r) in records.iter().enumerate() {
            let Some(shard) = r.as_ref().and_then(|r| self.shard(i, r)) else {
                continue;
            };
            match groups
                .iter_mut()
                .find(|(len, digest, _)| *len == shard.len && *digest == shard.digest)
            {
                Some((_, _, members)) => members.push(shard),
                None => groups.push((shard.len, shard.digest, vec![shard])),
            }
        }
        let (len, digest, members) = groups
            .into_iter()
            .filter(|(_, _, m)| m.len() >= self.erasure.k as usize)
            .max_by_key(|(_, _, m)| m.len())?;
        let mut dec = Decoder::new(self.erasure.k, self.erasure.n).ok()?;
        for s in &members {
            if dec.absorb(s.index, s.body.clone()).is_err() {
                continue;
            }
            if dec.is_complete() {
                break;
            }
        }
        let segments = dec.recover().ok()?;
        let mut wire = Vec::with_capacity(segments.iter().map(Bytes::len).sum());
        for seg in &segments {
            wire.extend_from_slice(seg);
        }
        wire.truncate(len);
        if sha256(&wire) != digest {
            return None;
        }
        let stale = (0..records.len())
            .filter(|i| !members.iter().any(|s| s.index as usize == *i))
            .collect();
        Some(Assembled {
            wire: Bytes::from(wire),
            stale,
        })
    }

    fn records(&self, name: &Name) -> Vec<Option<Bytes>> {
        self.stripes.iter().map(|s| s.get(name)).collect()
    }

    /// Rewrite the shards of `name` the stripes lack, judged again under
    /// the write lock against what the stripes hold now.
    fn repair(&self, name: &Name) {
        let _w = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(now) = self.assemble(&self.records(name)) else {
            return;
        };
        if now.stale.is_empty() {
            return;
        }
        match self.encode(&now.wire) {
            Ok(records) => {
                for &i in &now.stale {
                    self.stripes[i].insert(name.clone(), records[i].clone());
                }
                tracing::info!(target: "ndn_repo", %name, stripes = ?now.stale, "repaired held shards");
            }
            Err(e) => {
                tracing::warn!(target: "ndn_repo", %name, error = %e, "cannot re-encode a held packet to repair it")
            }
        }
    }

    /// Rebuild, repairing on the way.
    fn rebuild(&self, name: &Name, records: &[Option<Bytes>]) -> Option<Bytes> {
        let got = self.assemble(records)?;
        if !got.stale.is_empty() {
            self.repair(name);
        }
        Some(got.wire)
    }

    /// The first `limit` (0 = all) rebuildable packets under `prefix`, each
    /// stripe scanned up to `stripe_limit` (0 = all). `None` when a stripe's
    /// scan was cut short before `limit` packets were judged on a complete
    /// view; the caller scans again unlimited.
    fn scan(&self, prefix: &Name, stripe_limit: usize, limit: usize) -> Option<Vec<(Name, Bytes)>> {
        let n = self.stripes.len();
        let mut rows: BTreeMap<Vec<u8>, (Name, Vec<Option<Bytes>>)> = BTreeMap::new();
        // Keys up to the smallest last key of a cut-short stripe are seen in
        // every stripe that holds them.
        let mut complete_to: Option<Vec<u8>> = None;
        for (i, stripe) in self.stripes.iter().enumerate() {
            let got = stripe.scan_under(prefix, stripe_limit);
            if stripe_limit > 0
                && got.len() >= stripe_limit
                && let Some((last, _)) = got.last()
            {
                let last = name_key(last);
                if complete_to.as_ref().is_none_or(|c| last < *c) {
                    complete_to = Some(last);
                }
            }
            for (name, record) in got {
                rows.entry(name_key(&name))
                    .or_insert_with(|| (name, vec![None; n]))
                    .1[i] = Some(record);
            }
        }
        let mut out = Vec::new();
        for (key, (name, records)) in rows {
            if limit > 0 && out.len() >= limit {
                break;
            }
            if complete_to.as_ref().is_some_and(|c| key > *c) {
                return None;
            }
            if let Some(wire) = self.rebuild(&name, &records) {
                out.push((name, wire));
            }
        }
        Some(out)
    }
}

impl DataStore for ErasureStore {
    fn insert(&self, name: Name, wire: Bytes) {
        if u32::try_from(wire.len()).is_err() {
            tracing::warn!(target: "ndn_repo", %name, len = wire.len(), "a held packet over 4 GiB cannot be erasure-coded; not stored");
            return;
        }
        let records = match self.encode(&wire) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(target: "ndn_repo", %name, error = %e, "cannot erasure-code a held packet; not stored");
                return;
            }
        };
        let _w = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        for (stripe, record) in self.stripes.iter().zip(records) {
            stripe.insert(name.clone(), record);
        }
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.rebuild(name, &self.records(name))
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.scan_under(prefix, 1)
            .into_iter()
            .next()
            .map(|(_, w)| w)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.scan(prefix, limit, limit)
            .or_else(|| self.scan(prefix, 0, limit))
            .unwrap_or_default()
    }

    fn remove(&self, name: &Name) {
        let _w = self.writes.lock().unwrap_or_else(PoisonError::into_inner);
        for stripe in &self.stripes {
            stripe.remove(name);
        }
    }
}

/// A holder device's [`DataStore`]: its own names in a plain store, what it
/// holds for others in an [`ErasureStore`] (see the [module docs](self)).
pub struct HolderStore {
    device: Name,
    localhost: Name,
    own: FjallStore,
    held: ErasureStore,
}

impl HolderStore {
    /// Open (or create) the store of device `device` at `dir`: `<dir>/own`,
    /// `<dir>/held/<i>`, and the erasure record `<dir>/erasure` (written on
    /// the first open; a later open with other parameters is refused).
    pub fn open(dir: impl AsRef<Path>, device: Name, erasure: Erasure) -> Result<Self, HeldError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(|source| HeldError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let record = dir.join(ERASURE_RECORD);
        match std::fs::read_to_string(&record) {
            Ok(text) => {
                let stored: Erasure = text.parse().map_err(|_| HeldError::Record {
                    path: record.clone(),
                    text: text.clone(),
                })?;
                if stored != erasure {
                    return Err(HeldError::Mismatch {
                        path: record,
                        stored,
                        asked: erasure,
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::write(&record, format!("{erasure}\n")).map_err(|source| {
                    HeldError::Io {
                        path: record.clone(),
                        source,
                    }
                })?;
            }
            Err(source) => {
                return Err(HeldError::Io {
                    path: record,
                    source,
                });
            }
        }
        let own_dir = dir.join("own");
        let own = FjallStore::open(&own_dir).map_err(|source| HeldError::Open {
            path: own_dir,
            source,
        })?;
        let held = ErasureStore::open(dir.join("held"), erasure)?;
        Ok(Self {
            device,
            localhost: Name::root().append("localhost"),
            own,
            held,
        })
    }

    /// The device's own names.
    pub fn own(&self) -> &FjallStore {
        &self.own
    }

    /// What the device holds for others.
    pub fn held(&self) -> &ErasureStore {
        &self.held
    }

    fn is_own(&self, name: &Name) -> bool {
        name.has_prefix(&self.device) || name.has_prefix(&self.localhost)
    }
}

impl DataStore for HolderStore {
    fn insert(&self, name: Name, wire: Bytes) {
        if self.is_own(&name) {
            self.own.insert(name, wire)
        } else {
            self.held.insert(name, wire)
        }
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        if self.is_own(name) {
            self.own.get(name)
        } else {
            self.held.get(name)
        }
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.scan_under(prefix, 1)
            .into_iter()
            .next()
            .map(|(_, w)| w)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        if self.is_own(prefix) {
            return self.own.scan_under(prefix, limit);
        }
        let held = self.held.scan_under(prefix, limit);
        if !self.device.has_prefix(prefix) && !self.localhost.has_prefix(prefix) {
            return held;
        }
        // The prefix spans own names and held ones: merge in name order.
        let own = self.own.scan_under(prefix, limit);
        let mut out = Vec::with_capacity(own.len() + held.len());
        let (mut own, mut held) = (own.into_iter().peekable(), held.into_iter().peekable());
        while limit == 0 || out.len() < limit {
            let next = match (own.peek(), held.peek()) {
                (Some((a, _)), Some((b, _))) => match name_key(a).cmp(&name_key(b)) {
                    Ordering::Greater => held.next(),
                    _ => own.next(),
                },
                (Some(_), None) => own.next(),
                (None, Some(_)) => held.next(),
                (None, None) => None,
            };
            match next {
                Some(row) => out.push(row),
                None => break,
            }
        }
        out
    }

    fn remove(&self, name: &Name) {
        if self.is_own(name) {
            self.own.remove(name)
        } else {
            self.held.remove(name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// A packet-sized wire whose bytes depend on `seed`.
    fn wire(seed: u8, len: usize) -> Bytes {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect::<Vec<u8>>()
            .into()
    }

    fn lose(dir: &Path, stripes: &[u16]) {
        for i in stripes {
            std::fs::remove_dir_all(dir.join(i.to_string())).unwrap();
        }
    }

    #[test]
    fn erasure_parses_and_refuses_out_of_range() {
        assert_eq!(
            "3/5".parse::<Erasure>().unwrap(),
            Erasure::new(3, 5).unwrap()
        );
        assert!("0/3".parse::<Erasure>().is_err());
        assert!("4/3".parse::<Erasure>().is_err());
        assert!("2/256".parse::<Erasure>().is_err());
        assert!("2-3".parse::<Erasure>().is_err());
    }

    #[test]
    fn round_trip_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let e = Erasure::new(3, 5).unwrap();
        // Lengths around the shard boundaries, and a tiny one.
        let items: Vec<(Name, Bytes)> = [1usize, 2, 3, 4, 4096, 8801]
            .iter()
            .enumerate()
            .map(|(i, &len)| (n(&format!("/a/p/{i}")), wire(i as u8, len)))
            .collect();
        {
            let s = ErasureStore::open(dir.path(), e).unwrap();
            for (name, w) in &items {
                s.insert(name.clone(), w.clone());
            }
            for (name, w) in &items {
                assert_eq!(s.get(name).as_ref(), Some(w));
            }
        }
        let s = ErasureStore::open(dir.path(), e).unwrap();
        for (name, w) in &items {
            assert_eq!(s.get(name).as_ref(), Some(w));
        }
        assert!(s.get(&n("/a/p/none")).is_none());
    }

    #[test]
    fn survives_lost_stripes_and_repairs_them() {
        let dir = tempfile::tempdir().unwrap();
        let e = Erasure::new(3, 5).unwrap();
        let name = n("/a/p/1");
        let w = wire(7, 5000);
        ErasureStore::open(dir.path(), e)
            .unwrap()
            .insert(name.clone(), w.clone());
        // n - k = 2 stripes lost: still there, and the read repairs them.
        lose(dir.path(), &[0, 3]);
        assert_eq!(
            ErasureStore::open(dir.path(), e).unwrap().get(&name),
            Some(w.clone())
        );
        // The repaired stripes carry good shards: lose two others.
        lose(dir.path(), &[1, 4]);
        assert_eq!(
            ErasureStore::open(dir.path(), e).unwrap().get(&name),
            Some(w)
        );
    }

    #[test]
    fn more_lost_stripes_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let e = Erasure::default();
        let name = n("/a/p/1");
        ErasureStore::open(dir.path(), e)
            .unwrap()
            .insert(name.clone(), wire(1, 300));
        lose(dir.path(), &[0, 2]);
        let s = ErasureStore::open(dir.path(), e).unwrap();
        assert!(s.get(&name).is_none());
        assert!(s.find_under(&n("/a")).is_none());
        assert!(s.scan_under(&n("/a"), 0).is_empty());
    }

    #[test]
    fn corrupt_shard_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let s = ErasureStore::open(dir.path(), Erasure::default()).unwrap();
        let name = n("/a/p/1");
        let w = wire(3, 900);
        s.insert(name.clone(), w.clone());
        let mut bad = s.stripes[0].get(&name).unwrap().to_vec();
        *bad.last_mut().unwrap() ^= 1;
        s.stripes[0].insert(name.clone(), bad.into());
        assert_eq!(s.get(&name), Some(w.clone()));
        // Repaired: stripe 0 holds a good shard again, so it and stripe 2 suffice.
        s.stripes[1].remove(&name);
        assert_eq!(s.get(&name), Some(w));
    }

    #[test]
    fn remove_deletes_every_shard() {
        let dir = tempfile::tempdir().unwrap();
        let s = ErasureStore::open(dir.path(), Erasure::default()).unwrap();
        let name = n("/a/p/1");
        s.insert(name.clone(), wire(2, 100));
        s.remove(&name);
        assert!(s.get(&name).is_none());
        assert!(s.stripes.iter().all(|st| st.get(&name).is_none()));
    }

    #[test]
    fn scan_is_in_name_order_across_stripes() {
        let dir = tempfile::tempdir().unwrap();
        let s = ErasureStore::open(dir.path(), Erasure::default()).unwrap();
        for (i, p) in ["/a/c", "/a/a", "/b/x", "/a/b/1", "/a/b"]
            .iter()
            .enumerate()
        {
            s.insert(n(p), wire(i as u8, 50 + i));
        }
        // One stripe lost /a/a: still listed (and repaired).
        s.stripes[1].remove(&n("/a/a"));
        // /a/b lost two stripes: missing, not listed.
        s.stripes[0].remove(&n("/a/b"));
        s.stripes[2].remove(&n("/a/b"));
        let names = |rows: Vec<(Name, Bytes)>| rows.into_iter().map(|(n, _)| n).collect::<Vec<_>>();
        assert_eq!(
            names(s.scan_under(&n("/a"), 0)),
            vec![n("/a/a"), n("/a/b/1"), n("/a/c")]
        );
        assert_eq!(
            names(s.scan_under(&n("/a"), 2)),
            vec![n("/a/a"), n("/a/b/1")]
        );
        assert_eq!(s.find_under(&n("/a/b")), Some(wire(3, 53)));
        assert!(s.stripes[1].get(&n("/a/a")).is_some());
    }

    #[test]
    fn holder_keeps_own_names_plain_and_refuses_other_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let device = n("/ph/member/repo");
        let own = n("/ph/member/repo/32=log/x");
        let other = n("/ph/member/phone/32=log/x");
        {
            let s = HolderStore::open(dir.path(), device.clone(), Erasure::default()).unwrap();
            s.insert(own.clone(), wire(1, 10));
            s.insert(other.clone(), wire(2, 10));
            assert!(s.own().get(&other).is_none());
            assert!(s.held().get(&own).is_none());
            assert_eq!(
                s.scan_under(&n("/ph"), 0)
                    .into_iter()
                    .map(|(n, _)| n)
                    .collect::<Vec<_>>(),
                vec![other.clone(), own.clone()]
            );
        }
        assert!(matches!(
            HolderStore::open(dir.path(), device.clone(), Erasure::new(3, 5).unwrap()),
            Err(HeldError::Mismatch { .. })
        ));
        // Losing every held stripe loses what it held for others, not its own.
        std::fs::remove_dir_all(dir.path().join("held")).unwrap();
        let s = HolderStore::open(dir.path(), device, Erasure::default()).unwrap();
        assert_eq!(s.get(&own), Some(wire(1, 10)));
        assert!(s.get(&other).is_none());
    }
}

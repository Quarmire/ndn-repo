//! Durable [`DataStore`] backends for the repo. The repo is built over the
//! `ndn_sync::DataStore` trait, so storage is **pluggable** — `MemoryStore`
//! (process-lifetime) ships in `ndn-sync`; [`FjallStore`] here adds on-disk
//! persistence so a repo survives restarts. Any `DataStore` impl works; an
//! embedder can supply its own (S3, sqlite, …).

#[cfg(feature = "fjall-store")]
pub use fjall_store::FjallStore;

/// Encode a [`Name`](ndn_packet::Name) to a storage key: the concatenated
/// component TLVs (the Name TLV value, without the outer `0x07`). NDN's
/// canonical component ordering is preserved byte-for-byte, so a parent
/// prefix's key is a byte-prefix of every descendant's key — making
/// `CanBePrefix` lookups range scans (matches `ndn-store`'s CS key codec).
#[cfg(feature = "fjall-store")]
fn name_to_key(name: &ndn_packet::Name) -> Vec<u8> {
    use ndn_tlv::TlvWriter;
    let mut w = TlvWriter::new();
    for c in name.components() {
        w.write_tlv(c.typ, &c.value);
    }
    w.finish().to_vec()
}

#[cfg(feature = "fjall-store")]
mod fjall_store {
    use bytes::Bytes;
    use ndn_packet::Name;
    use ndn_sync::DataStore;

    use super::name_to_key;

    /// On-disk [`DataStore`] backed by [fjall](https://docs.rs/fjall) (an LSM
    /// key-value store). Stores each Data packet's full wire under its name, so
    /// the repo re-serves it verbatim across process restarts.
    pub struct FjallStore {
        keyspace: fjall::Keyspace,
        // Keeps the database open for the keyspace's lifetime.
        #[allow(dead_code)]
        db: fjall::Database,
    }

    impl FjallStore {
        /// Open (or create) a repo store rooted at `path`.
        pub fn open(path: impl AsRef<std::path::Path>) -> fjall::Result<Self> {
            let db = fjall::Database::builder(path).open()?;
            let keyspace = db.keyspace("repo", fjall::KeyspaceCreateOptions::default)?;
            Ok(Self { keyspace, db })
        }

        /// Number of stored Data packets (full scan — diagnostics/tests).
        pub fn len(&self) -> usize {
            self.keyspace.iter().count()
        }

        pub fn is_empty(&self) -> bool {
            self.keyspace.iter().next().is_none()
        }
    }

    impl DataStore for FjallStore {
        fn insert(&self, name: Name, wire: Bytes) {
            let key = name_to_key(&name);
            let _ = self.keyspace.insert(&key, wire.as_ref());
        }

        fn get(&self, name: &Name) -> Option<Bytes> {
            let key = name_to_key(name);
            let slice = self.keyspace.get(&key).ok()??;
            Some(Bytes::copy_from_slice(&slice))
        }

        fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            // Range scan: keys are sorted by NDN canonical order, so the first
            // under the prefix is the lexicographically-smallest descendant —
            // the answer to a CanBePrefix Interest.
            let prefix_key = name_to_key(prefix);
            for guard in self.keyspace.prefix(&prefix_key) {
                if let Ok((_key, val)) = guard.into_inner() {
                    return Some(Bytes::copy_from_slice(&val));
                }
            }
            None
        }
    }
}

#[cfg(all(test, feature = "fjall-store"))]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::Name;
    use ndn_sync::DataStore;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn name_key_is_prefix_preserving() {
        let parent = n("/a/b");
        let child = n("/a/b/c");
        assert!(name_to_key(&child).starts_with(&name_to_key(&parent)));
    }

    #[test]
    fn insert_get_and_prefix_scan() {
        let dir = tempfile::tempdir().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let name = n("/g/obj/v=1/seg=0");
        store.insert(name.clone(), Bytes::from_static(b"wire"));
        assert_eq!(store.get(&name).as_deref(), Some(&b"wire"[..]));
        // CanBePrefix: a Data under /g/obj is found by its prefix.
        assert_eq!(store.find_under(&n("/g/obj")).as_deref(), Some(&b"wire"[..]));
        assert!(store.find_under(&n("/other")).is_none());
    }

    #[test]
    fn data_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let name = n("/persist/v=1");
        {
            let store = FjallStore::open(dir.path()).unwrap();
            store.insert(name.clone(), Bytes::from_static(b"durable"));
            assert_eq!(store.len(), 1);
        }
        // Reopen the same path → data is still there.
        let store = FjallStore::open(dir.path()).unwrap();
        assert_eq!(store.get(&name).as_deref(), Some(&b"durable"[..]));
    }
}

//! Durable [`DataStore`] backends for the repo. The repo is built over the
//! `ndn_sync::DataStore` trait, so storage is **pluggable** — `MemoryStore`
//! (process-lifetime) ships in `ndn-sync`; [`FjallStore`] here adds on-disk
//! persistence so a repo survives restarts. Any `DataStore` impl works; an
//! embedder can supply its own (S3, sqlite, …).
//!
//! The on-disk engine + name→key codec are **not** hand-rolled here: they come
//! from ndn-rs's `ndn-storage` substrate. `FjallStore` is a thin bridge from
//! `ndn_storage::FjallBackend` (consumed through its **synchronous** facet, so
//! the `DataStore` path needs no async runtime) to `ndn_sync::DataStore`.

#[cfg(feature = "fjall-store")]
pub use fjall_store::FjallStore;

#[cfg(feature = "fjall-store")]
mod fjall_store {
    use bytes::Bytes;
    use ndn_packet::Name;
    // `name_key` is ndn-storage's shared key codec (component-TLVs in NDN
    // canonical order — byte-identical to ndn-repo's former `name_to_key`, so a
    // parent name is a byte-prefix of its descendants and `CanBePrefix` lookups
    // are prefix scans). `SyncBackend` is the synchronous core that fjall impls
    // directly — `DataStore` is sync, so we drive the store without any async.
    use ndn_storage::{FjallBackend, SyncBackend, name_key};
    use ndn_sync::DataStore;

    /// On-disk [`DataStore`] backed by [`ndn_storage::FjallBackend`] (fjall's LSM
    /// key-value engine). Stores each Data packet's full wire under its name, so
    /// the repo re-serves it verbatim across process restarts.
    pub struct FjallStore(FjallBackend);

    impl FjallStore {
        /// Open (or create) a repo store rooted at `path`.
        pub fn open(path: impl AsRef<std::path::Path>) -> fjall::Result<Self> {
            Ok(Self(FjallBackend::open(path)?))
        }

        /// Number of stored Data packets (full scan — diagnostics/tests). The
        /// empty prefix matches every key.
        pub fn len(&self) -> usize {
            self.0.scan_prefix(&[], 0).map(|v| v.len()).unwrap_or(0)
        }

        pub fn is_empty(&self) -> bool {
            self.0.first_under(&[]).map(|o| o.is_none()).unwrap_or(true)
        }
    }

    // `ndn_sync::DataStore` is infallible, so this bridge is the one place a storage
    // error must be collapsed to a miss/no-op — but it is now *logged* rather than
    // silently swallowed (the whole point of the fallible `ndn_storage` API): a disk
    // failure surfaces in the logs instead of looking like missing data.
    impl DataStore for FjallStore {
        fn insert(&self, name: Name, wire: Bytes) {
            if let Err(e) = self.0.put(&name_key(&name), wire) {
                tracing::warn!(target: "ndn_repo", %name, error = %e, "fjall store insert failed");
            }
        }

        fn get(&self, name: &Name) -> Option<Bytes> {
            match self.0.get(&name_key(name)) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(target: "ndn_repo", %name, error = %e, "fjall store get failed");
                    None
                }
            }
        }

        fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            // Prefix scan: keys are sorted by NDN canonical order, so the
            // lexicographically-smallest descendant is the answer to a
            // CanBePrefix Interest.
            match self.0.first_under(&name_key(prefix)) {
                Ok(o) => o.map(|(_, v)| v),
                Err(e) => {
                    tracing::warn!(target: "ndn_repo", %prefix, error = %e, "fjall store scan failed");
                    None
                }
            }
        }
    }
}

#[cfg(all(test, feature = "fjall-store"))]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::Name;
    use ndn_storage::name_key;
    use ndn_sync::DataStore;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn name_key_is_prefix_preserving() {
        let parent = n("/a/b");
        let child = n("/a/b/c");
        assert!(name_key(&child).starts_with(&name_key(&parent)));
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

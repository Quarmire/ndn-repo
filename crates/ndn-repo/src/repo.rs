//! The repository engine: process [`RepoCmd`]s, durably store Data, and serve
//! it by name. Transport-agnostic — an embedder wires the command interface to
//! a forwarder face (a `Producer`/command handler) and, for `SyncJoin`, points
//! an [`SvSync`](ndn_sync::SvSync) at [`Repo::store`] so the same store both
//! ingests (fetched publications) and serves (SVS demux answers from it). This
//! mirrors ndnd's repo: join a group, durably hold what's published, serve it
//! after the producer leaves.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ndn_packet::{Data, Name};
use ndn_sync::DataStore;

use crate::tlv::{RepoCmd, RepoCmdRes, SyncJoin, SyncLeave, sync_protocol_svs_v3};

/// Minimum history-snapshot threshold (ndnd `repo_svs.go`: `t < 10` rejected).
const MIN_HISTORY_THRESHOLD: u64 = 10;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("data packet could not be decoded")]
    MalformedData,
}

/// A persistent named-data repository over a pluggable [`DataStore`].
#[derive(Clone)]
pub struct Repo {
    inner: Arc<RepoInner>,
}

struct RepoInner {
    store: Arc<dyn DataStore>,
    /// SVS group prefixes this repo has joined (ingests + serves).
    groups: Mutex<BTreeSet<Name>>,
    /// Names requested by `BlobFetch` (by name) that the embedder must fetch
    /// from the network and feed back via [`Repo::store_data`].
    pending_fetches: Mutex<Vec<Name>>,
}

impl Repo {
    pub fn new(store: Arc<dyn DataStore>) -> Self {
        Self {
            inner: Arc::new(RepoInner {
                store,
                groups: Mutex::new(BTreeSet::new()),
                pending_fetches: Mutex::new(Vec::new()),
            }),
        }
    }

    /// The backing store — hand this to an `SvSync` so a joined group's
    /// fetched publications land here and the SVS demux serves them.
    pub fn store(&self) -> Arc<dyn DataStore> {
        Arc::clone(&self.inner.store)
    }

    /// Process a command (`ApplicationParameters` value) and return the reply.
    pub fn handle_command(&self, cmd_value: &[u8]) -> RepoCmdRes {
        let Some(cmd) = RepoCmd::decode(Bytes::copy_from_slice(cmd_value)) else {
            return RepoCmdRes::err(400, "malformed repo command");
        };
        match cmd {
            RepoCmd::SyncJoin(j) => self.handle_sync_join(j),
            RepoCmd::SyncLeave(l) => self.handle_sync_leave(l),
            RepoCmd::BlobFetch(b) => self.handle_blob_fetch(b),
        }
    }

    fn handle_sync_join(&self, j: SyncJoin) -> RepoCmdRes {
        // Only SVS-v3 is supported (as ndnd); a missing protocol defaults to it.
        if let Some(p) = &j.protocol
            && *p != sync_protocol_svs_v3()
        {
            return RepoCmdRes::err(400, "unknown sync protocol");
        }
        let Some(group) = j.group else {
            return RepoCmdRes::err(400, "missing group name");
        };
        if let Some(t) = j.history_threshold
            && t < MIN_HISTORY_THRESHOLD
        {
            return RepoCmdRes::err(400, "invalid history snapshot threshold");
        }
        self.inner.groups.lock().expect("groups poisoned").insert(group);
        RepoCmdRes::ok()
    }

    fn handle_sync_leave(&self, l: SyncLeave) -> RepoCmdRes {
        let Some(group) = l.group else {
            return RepoCmdRes::err(400, "missing group name");
        };
        let removed = self.inner.groups.lock().expect("groups poisoned").remove(&group);
        if removed {
            RepoCmdRes::ok()
        } else {
            // Matches ndnd stopSvs: leaving a group never joined is an error.
            RepoCmdRes::err(500, "group not joined")
        }
    }

    fn handle_blob_fetch(&self, b: crate::tlv::BlobFetch) -> RepoCmdRes {
        // Inline data: store each Data wire directly (push insertion).
        let mut stored = 0usize;
        for wire in b.data {
            if self.store_data(wire).is_ok() {
                stored += 1;
            }
        }
        // Fetch-by-name: record for the embedder to fetch from the network and
        // feed back via store_data (ndnd `processBlobFetch` → Consume).
        if let Some(name) = b.name {
            self.inner
                .pending_fetches
                .lock()
                .expect("pending poisoned")
                .push(name);
        }
        let _ = stored;
        RepoCmdRes::ok()
    }

    /// Durably store one Data packet wire under its own name, so the repo can
    /// re-serve it verbatim. Returns the stored name.
    pub fn store_data(&self, wire: Bytes) -> Result<Name, RepoError> {
        let data = Data::decode(wire.clone()).map_err(|_| RepoError::MalformedData)?;
        let name = (*data.name).clone();
        self.inner.store.insert(name.clone(), wire);
        Ok(name)
    }

    /// Serve: the stored Data wire for `name`, if held.
    pub fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.store.get(name)
    }

    /// The SVS group prefixes currently joined.
    pub fn joined_groups(&self) -> Vec<Name> {
        self.inner.groups.lock().expect("groups poisoned").iter().cloned().collect()
    }

    /// Drain the names requested via `BlobFetch`-by-name for the embedder to
    /// fetch from the network (then feed back through [`Self::store_data`]).
    pub fn take_pending_fetches(&self) -> Vec<Name> {
        std::mem::take(&mut *self.inner.pending_fetches.lock().expect("pending poisoned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::{BlobFetch, SyncJoin, SyncLeave};
    use ndn_packet::encode::DataBuilder;
    use ndn_sync::MemoryStore;

    fn repo() -> Repo {
        Repo::new(Arc::new(MemoryStore::new()))
    }

    #[test]
    fn blob_fetch_inline_store_then_serve() {
        let repo = repo();
        let name: Name = "/g/obj/v=1/seg=0".parse().unwrap();
        let wire = DataBuilder::new(name.clone(), b"payload").build();
        let cmd = RepoCmd::BlobFetch(BlobFetch { name: None, data: vec![wire.clone()] });

        let res = repo.handle_command(&cmd.encode());
        assert_eq!(res.status, 200);
        // The repo now serves it by name — even though the producer is gone.
        assert_eq!(repo.get(&name), Some(wire));
    }

    #[test]
    fn sync_join_tracks_group_and_validates() {
        let repo = repo();
        let group: Name = "/my/group".parse().unwrap();

        // Good join.
        let ok = RepoCmd::SyncJoin(SyncJoin {
            protocol: Some(sync_protocol_svs_v3()),
            group: Some(group.clone()),
            history_threshold: Some(20),
            ..Default::default()
        });
        assert_eq!(repo.handle_command(&ok.encode()).status, 200);
        assert_eq!(repo.joined_groups(), vec![group.clone()]);

        // Bad threshold rejected.
        let bad = RepoCmd::SyncJoin(SyncJoin {
            group: Some("/g2".parse().unwrap()),
            history_threshold: Some(5),
            ..Default::default()
        });
        assert_eq!(repo.handle_command(&bad.encode()).status, 400);

        // Leave an unjoined group → error (matches ndnd).
        let leave_bad = RepoCmd::SyncLeave(SyncLeave {
            group: Some("/never".parse().unwrap()),
            ..Default::default()
        });
        assert_eq!(repo.handle_command(&leave_bad.encode()).status, 500);

        // Leave the joined group → ok.
        let leave = RepoCmd::SyncLeave(SyncLeave { group: Some(group), ..Default::default() });
        assert_eq!(repo.handle_command(&leave.encode()).status, 200);
        assert!(repo.joined_groups().is_empty());
    }

    #[test]
    fn blob_fetch_by_name_is_queued() {
        let repo = repo();
        let cmd = RepoCmd::BlobFetch(BlobFetch {
            name: Some("/g/want".parse().unwrap()),
            data: vec![],
        });
        assert_eq!(repo.handle_command(&cmd.encode()).status, 200);
        assert_eq!(repo.take_pending_fetches(), vec!["/g/want".parse().unwrap()]);
        assert!(repo.take_pending_fetches().is_empty(), "drained");
    }

    #[test]
    fn malformed_command_is_400() {
        let repo = repo();
        assert_eq!(repo.handle_command(&[0xFF, 0x00]).status, 400);
    }
}

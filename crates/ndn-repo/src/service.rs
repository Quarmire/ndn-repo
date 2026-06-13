//! `RepoService` — the runnable repo: demux a forwarder connection into
//! command handling, store serving, and per-group SVS ingestion.
//!
//! Transport-agnostic by design (like the rest of ndn-rs's app layer): the
//! service drives a `send: mpsc::Sender<Bytes>` (outbound to a forwarder) and a
//! `recv: mpsc::Receiver<Bytes>` (inbound). An embedder bridges those to a real
//! face (Unix-socket IPC / in-process engine) and registers the repo command
//! prefix plus each joined group prefix so the forwarder routes them here.
//!
//! Inbound demux:
//! * **command Interest** under the repo prefix → [`Repo::handle_command`],
//!   reply a `RepoCmdRes` Data; on `SyncJoin`/`SyncLeave` start/stop the
//!   group's [`SvSync`] + ingestion.
//! * **publication Interest** under a joined group → served from the store
//!   (the repo answers for the whole group, even after the producer left).
//! * **everything else** under a group (sync Interests, fetch replies) → routed
//!   into that group's `SvSync`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_sync::{DataStore, SvSync, SvSyncConfig, SyncUpdate};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ingest::ingest_group;
use crate::repo::Repo;
use crate::tlv::RepoCmd;

/// Configuration for a [`RepoService`].
#[derive(Clone, Debug)]
pub struct RepoServiceConfig {
    /// The repo's node-name component within each joined group (its SVS member
    /// id). Default `"repo"`. Must be unique per repo on a shared group.
    pub node_id: String,
    /// FreshnessPeriod stamped on `RepoCmdRes` command replies.
    pub response_freshness: Duration,
    /// Groups to join at startup without a `SyncJoin` command (operator config).
    pub initial_groups: Vec<Name>,
    pub svs: SvSyncConfig,
}

impl Default for RepoServiceConfig {
    fn default() -> Self {
        Self {
            node_id: "repo".to_string(),
            response_freshness: Duration::from_secs(1),
            initial_groups: Vec::new(),
            svs: SvSyncConfig::default(),
        }
    }
}

struct GroupHandle {
    /// Inbound channel feeding this group's `SvSync` (sync Interests + replies).
    net_in: mpsc::Sender<Bytes>,
    /// The group's sync handle — used to fetch `BlobFetch`-by-name blobs.
    svs: Arc<SvSync>,
    cancel: CancellationToken,
}

/// The running repository service. Build with [`RepoService::new`], then drive
/// with [`RepoService::run`] (consumes the inbound stream until it closes).
pub struct RepoService {
    repo: Repo,
    repo_prefix: Name,
    send: mpsc::Sender<Bytes>,
    config: RepoServiceConfig,
    cancel: CancellationToken,
    groups: HashMap<Name, GroupHandle>,
    /// When set, prefixes the service needs the forwarder to route here (the
    /// command prefix + each joined group) are sent here for the embedder to
    /// register. Lets dynamic `SyncJoin`s become reachable.
    register_tx: Option<mpsc::Sender<Name>>,
}

impl RepoService {
    pub fn new(
        repo: Repo,
        repo_prefix: Name,
        send: mpsc::Sender<Bytes>,
        config: RepoServiceConfig,
    ) -> Self {
        Self {
            repo,
            repo_prefix,
            send,
            config,
            cancel: CancellationToken::new(),
            groups: HashMap::new(),
            register_tx: None,
        }
    }

    /// Receive the prefixes (command prefix + each joined group) the forwarder
    /// must route to this service, so the embedder can `register_prefix` them —
    /// including groups joined dynamically by `SyncJoin` at runtime.
    pub fn with_registration(mut self, register_tx: mpsc::Sender<Name>) -> Self {
        self.register_tx = Some(register_tx);
        self
    }

    /// A cancellation token that stops the service and all its group ingestion.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// The prefixes a forwarder must route to this service: the command prefix
    /// plus every joined group. (Groups are returned as they are joined; call
    /// after a join if registering dynamically.)
    pub fn registered_prefixes(&self) -> Vec<Name> {
        let mut v = vec![self.repo_prefix.clone()];
        v.extend(self.groups.keys().cloned());
        v
    }

    /// Run the demux loop until `recv` closes or the service is cancelled.
    pub async fn run(mut self, mut recv: mpsc::Receiver<Bytes>) {
        // Ask the embedder to route the command prefix here, then join any
        // operator-configured groups.
        self.emit_register(self.repo_prefix.clone()).await;
        for group in self.config.initial_groups.clone() {
            self.start_group(group).await;
        }
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                maybe = recv.recv() => {
                    let Some(raw) = maybe else { break };
                    self.dispatch(raw).await;
                }
            }
        }
        for (_, g) in self.groups.drain() {
            g.cancel.cancel();
        }
    }

    async fn dispatch(&mut self, raw: Bytes) {
        match raw.first() {
            Some(&0x05) => {
                let Ok(interest) = Interest::decode(raw.clone()) else { return };
                let name = (*interest.name).clone();
                // Command Interest under the repo prefix?
                if name.has_prefix(&self.repo_prefix)
                    && let Some(ap) = interest.app_parameters()
                    && RepoCmd::decode(ap.clone()).is_some()
                {
                    self.handle_command_interest(&interest, ap.clone()).await;
                    return;
                }
                // Publication Interest under a joined group → serve from store.
                if self.in_any_group(&name) {
                    if let Some(wire) = self.serve_from_store(&interest) {
                        let _ = self.send.send(wire).await;
                    } else {
                        self.route_to_group(&name, raw).await;
                    }
                }
            }
            Some(&0x06) => {
                // Data (e.g. a fetch reply) → route to the owning group's SvSync.
                if let Ok(data) = Data::decode(raw.clone()) {
                    let name = (*data.name).clone();
                    self.route_to_group(&name, raw).await;
                }
            }
            _ => {}
        }
    }

    async fn handle_command_interest(&mut self, interest: &Interest, ap: Bytes) {
        let parsed = RepoCmd::decode(ap.clone());
        let res = self.repo.handle_command(&ap);

        if res.status == 200 {
            match parsed {
                Some(RepoCmd::SyncJoin(j)) => {
                    if let Some(group) = j.group {
                        self.start_group(group).await;
                    }
                }
                Some(RepoCmd::SyncLeave(l)) => {
                    if let Some(group) = l.group {
                        self.stop_group(&group);
                    }
                }
                // BlobFetch-by-name queued a pending fetch in the repo; drive it.
                Some(RepoCmd::BlobFetch(_)) => self.drive_pending_fetches(),
                _ => {}
            }
        }

        // Reply the RepoCmdRes as Data named after the command Interest.
        let wire = DataBuilder::new((*interest.name).clone(), &res.encode())
            .freshness(self.config.response_freshness)
            .sign_digest_sha256();
        let _ = self.send.send(wire).await;
    }

    async fn emit_register(&self, prefix: Name) {
        if let Some(tx) = &self.register_tx {
            let _ = tx.send(prefix).await;
        }
    }

    /// Build an `SvSync` over the repo store for `group` and spawn its
    /// ingestion driver. Idempotent — re-joining a live group is a no-op.
    async fn start_group(&mut self, group: Name) {
        if self.groups.contains_key(&group) {
            return;
        }
        self.emit_register(group.clone()).await;
        let repo_node = group.clone().append(self.config.node_id.as_bytes());
        let (net_in_tx, net_in_rx) = mpsc::channel::<Bytes>(256);

        let mut svs = SvSync::join(
            group.clone(),
            repo_node,
            self.repo.store(),
            self.send.clone(),
            net_in_rx,
            self.config.svs.clone(),
        );
        let updates: mpsc::Receiver<SyncUpdate> = svs.take_updates();
        let svs = Arc::new(svs);
        let group_cancel = self.cancel.child_token();
        tokio::spawn(ingest_group(Arc::clone(&svs), updates, group_cancel.clone()));

        self.groups.insert(
            group,
            GroupHandle { net_in: net_in_tx, svs, cancel: group_cancel },
        );
    }

    /// Drain `BlobFetch`-by-name requests and fetch each from the network into
    /// the store, off the demux loop (the fetch's replies arrive *through* the
    /// loop, so awaiting here would deadlock). ndnd `processBlobFetch`.
    fn drive_pending_fetches(&self) {
        for name in self.repo.take_pending_fetches() {
            if let Some((_, g)) = self.groups.iter().find(|(grp, _)| name.has_prefix(grp)) {
                let svs = Arc::clone(&g.svs);
                tokio::spawn(async move {
                    svs.ingest_name(&name).await;
                });
            }
        }
    }

    fn stop_group(&mut self, group: &Name) {
        if let Some(g) = self.groups.remove(group) {
            g.cancel.cancel();
        }
    }

    fn in_any_group(&self, name: &Name) -> bool {
        self.groups.keys().any(|g| name.has_prefix(g))
    }

    /// Serve a publication Interest from the store (exact, or CanBePrefix via a
    /// range scan over the durable store).
    fn serve_from_store(&self, interest: &Interest) -> Option<Bytes> {
        let store: Arc<dyn DataStore> = self.repo.store();
        if interest.selectors().can_be_prefix {
            store.find_under(&interest.name)
        } else {
            store.get(&interest.name)
        }
    }

    async fn route_to_group(&self, name: &Name, raw: Bytes) {
        if let Some((_, g)) = self.groups.iter().find(|(g, _)| name.has_prefix(g)) {
            let _ = g.net_in.send(raw).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::RepoCmdRes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_sync::MemoryStore;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// Spawn a service and return (its inbound sender, its outbound receiver).
    fn spawn_service(repo: Repo, repo_prefix: Name) -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        let (out_tx, out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let svc = RepoService::new(repo, repo_prefix, out_tx, RepoServiceConfig::default());
        tokio::spawn(svc.run(in_rx));
        (in_tx, out_rx)
    }

    /// A command Interest carrying a RepoCmd is answered with a RepoCmdRes Data.
    #[tokio::test]
    async fn sync_join_command_is_answered_200() {
        let repo = Repo::new(Arc::new(MemoryStore::new()));
        let (to_svc, mut from_svc) = spawn_service(repo, n("/repo"));

        let cmd = RepoCmd::SyncJoin(crate::tlv::SyncJoin {
            protocol: Some(crate::tlv::sync_protocol_svs_v3()),
            group: Some(n("/g")),
            ..Default::default()
        });
        let interest = InterestBuilder::new(n("/repo/cmd"))
            .app_parameters(cmd.encode().to_vec())
            .build();
        to_svc.send(interest).await.unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(2), from_svc.recv())
            .await
            .expect("no reply")
            .expect("closed");
        let data = Data::decode(reply).unwrap();
        let res = RepoCmdRes::decode(data.content().unwrap().clone()).unwrap();
        assert_eq!(res.status, 200);
    }

    /// After a BlobFetch push-insert (inline) and a join, the service serves the
    /// stored publication to a consumer Interest under the group.
    #[tokio::test]
    async fn serves_stored_publication_to_consumer() {
        let repo = Repo::new(Arc::new(MemoryStore::new()));
        // Pre-store a publication under group /g and join the group so the
        // service serves under it.
        let pub_name = n("/g/alice/g/seg=0");
        let pub_wire = DataBuilder::new(pub_name.clone(), b"the-paper").build();
        repo.store_data(pub_wire.clone()).unwrap();

        let (to_svc, mut from_svc) = spawn_service(repo, n("/repo"));
        let join = RepoCmd::SyncJoin(crate::tlv::SyncJoin {
            group: Some(n("/g")),
            ..Default::default()
        });
        to_svc
            .send(InterestBuilder::new(n("/repo/cmd")).app_parameters(join.encode().to_vec()).build())
            .await
            .unwrap();
        // Drain the command reply.
        let _ = tokio::time::timeout(Duration::from_secs(2), from_svc.recv()).await;

        // A consumer asks the repo for the publication by name.
        to_svc
            .send(InterestBuilder::new(pub_name.clone()).build())
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), from_svc.recv())
            .await
            .expect("no serve reply")
            .expect("closed");
        let data = Data::decode(reply).unwrap();
        assert_eq!(*data.name, pub_name);
        assert_eq!(data.content().unwrap().as_ref(), b"the-paper");
    }
}

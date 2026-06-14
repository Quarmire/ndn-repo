//! The cluster node driver. A pure core ([`ClusterNode`] — `observe` gossiped
//! messages, `tick` to decide what to gossip/ingest) wrapped by an async
//! [`run`] that bridges it to an SVS coordination group and surfaces
//! ingest/drop decisions for the embedder to apply to its local
//! [`Repo`](ndn_repo::Repo).
//!
//! Keeping the decision logic pure makes the distributed behaviour — replication
//! convergence, capacity-aware placement, and failover — testable as a
//! deterministic multi-node simulation (see the tests), independent of any
//! transport.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::coord::{ClusterConfig, ClusterState, JobId, NodeId};
use crate::msg::ClusterMsg;

/// The actions a [`ClusterNode::tick`] decided on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TickOutcome {
    /// Messages to gossip into the coordination group (heartbeat + claims +
    /// releases).
    pub publish: Vec<ClusterMsg>,
    /// Targets this node newly claimed → the embedder should ingest them into
    /// its local repo (join the group / fetch the object).
    pub ingest: Vec<JobId>,
    /// Targets this node released → the embedder may evict them.
    pub drop: Vec<JobId>,
}

/// One repo node's coordination core: folds the cluster's gossiped state and
/// decides, each tick, what to claim/release/ingest. Deterministic and
/// transport-free.
pub struct ClusterNode {
    self_id: NodeId,
    state: ClusterState,
    capacity_used: u64,
    capacity_total: u64,
    epoch: u64,
}

impl ClusterNode {
    pub fn new(self_id: NodeId, config: ClusterConfig, capacity_total: u64) -> Self {
        Self {
            self_id,
            state: ClusterState::new(config),
            capacity_used: 0,
            capacity_total,
            epoch: 0,
        }
    }

    pub fn state(&self) -> &ClusterState {
        &self.state
    }

    pub fn self_id(&self) -> &NodeId {
        &self.self_id
    }

    /// Update this node's reported capacity usage (e.g. from the repo store).
    pub fn set_capacity_used(&mut self, used: u64) {
        self.capacity_used = used;
    }

    /// Learn of a unit of work (e.g. from a producer's store command). `repl`
    /// of 0 uses the cluster default.
    pub fn announce_job(&mut self, target: JobId, repl: usize) {
        self.state.observe_job(target, repl);
    }

    /// Fold a gossiped coordination message into the cluster view.
    pub fn observe(&mut self, msg: ClusterMsg, now_ns: u64) {
        match msg {
            ClusterMsg::Heartbeat { node, capacity_used, capacity_total, .. } => {
                self.state.observe_heartbeat(node, capacity_used, capacity_total, now_ns);
            }
            ClusterMsg::Job { target, replication_factor } => {
                self.state.observe_job(target, replication_factor as usize);
            }
            ClusterMsg::Claim { job, node, ts } => self.state.observe_claim(job, node, ts),
            ClusterMsg::Release { job, node } => self.state.observe_release(&job, &node),
        }
    }

    /// Advance one coordination round: record + emit our heartbeat, claim the
    /// jobs we are designated for, and shed over-replicated jobs if we are over
    /// capacity. Returns the messages to gossip and the ingest/drop decisions.
    pub fn tick(&mut self, now_ns: u64) -> TickOutcome {
        self.epoch += 1;
        // Our own heartbeat — recorded locally so we count ourselves live.
        self.state
            .observe_heartbeat(self.self_id.clone(), self.capacity_used, self.capacity_total, now_ns);
        let mut out = TickOutcome {
            publish: vec![ClusterMsg::Heartbeat {
                node: self.self_id.clone(),
                capacity_used: self.capacity_used,
                capacity_total: self.capacity_total,
                epoch: self.epoch,
            }],
            ..Default::default()
        };

        // Shed first (frees capacity), then claim.
        for job in self.state.jobs_to_release(&self.self_id, now_ns) {
            self.state.observe_release(&job, &self.self_id);
            out.publish.push(ClusterMsg::Release { job: job.clone(), node: self.self_id.clone() });
            out.drop.push(job);
        }
        for job in self.state.jobs_to_claim(&self.self_id, now_ns) {
            self.state.observe_claim(job.clone(), self.self_id.clone(), now_ns);
            out.publish.push(ClusterMsg::Claim {
                job: job.clone(),
                node: self.self_id.clone(),
                ts: now_ns,
            });
            out.ingest.push(job);
        }
        out
    }
}

/// Drive a [`ClusterNode`] over an SVS coordination group.
///
/// * `publish_msg(bytes)` gossips one encoded [`ClusterMsg`] (wire it to a
///   `Publisher`/`SvSync` over the coord group).
/// * `incoming` delivers peers' encoded messages (from a `Subscriber` over the
///   coord group).
/// * `ingest`/`drop_tx` surface the per-tick decisions for the embedder to
///   apply to its `Repo`.
/// * `capacity` reports current store usage each tick (e.g. repo store len).
///
/// Runs a heartbeat/placement tick every `tick_interval` until cancelled.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut node: ClusterNode,
    tick_interval: Duration,
    publish_msg: Arc<dyn Fn(Bytes) + Send + Sync>,
    mut incoming: mpsc::Receiver<Bytes>,
    ingest_tx: mpsc::Sender<JobId>,
    drop_tx: mpsc::Sender<JobId>,
    capacity: Arc<dyn Fn() -> u64 + Send + Sync>,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(tick_interval);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            msg = incoming.recv() => {
                match msg {
                    Some(raw) => {
                        if let Some(m) = ClusterMsg::decode(raw) {
                            node.observe(m, now_ns());
                        }
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                node.set_capacity_used(capacity());
                let out = node.tick(now_ns());
                for m in out.publish {
                    publish_msg(m.encode());
                }
                for job in out.ingest {
                    let _ = ingest_tx.send(job).await;
                }
                for job in out.drop {
                    let _ = drop_tx.send(job).await;
                }
            }
        }
    }
}

fn now_ns() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Name;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn cfg() -> ClusterConfig {
        ClusterConfig {
            replication_factor: 3,
            heartbeat_interval_ns: 1_000,
            missed_heartbeats: 3, // dead after 3_000 ns
            capacity_high_watermark: 0.75,
        }
    }

    /// Deterministic multi-node simulation: tick every node, broadcast each
    /// node's published messages to all others, and check the cluster
    /// converges to exactly `replication_factor` claimants per job — then that
    /// killing a claimant triggers re-replication onto a survivor.
    struct Sim {
        nodes: Vec<ClusterNode>,
        alive: Vec<bool>,
        now: u64,
    }

    impl Sim {
        fn new(ids: &[&str], capacity_total: u64) -> Self {
            Self {
                nodes: ids.iter().map(|id| ClusterNode::new(n(id), cfg(), capacity_total)).collect(),
                alive: vec![true; ids.len()],
                now: 1_000,
            }
        }

        fn announce_all(&mut self, target: &str) {
            for node in &mut self.nodes {
                node.announce_job(n(target), 0);
            }
        }

        fn kill(&mut self, idx: usize) {
            self.alive[idx] = false;
        }

        /// One synchronous round: alive nodes tick; their messages are observed
        /// by every other alive node (in-round delivery, modelling fast gossip).
        fn round(&mut self) {
            self.now += 1_000; // one heartbeat interval per round
            let mut bus: Vec<(usize, ClusterMsg)> = Vec::new();
            for (i, node) in self.nodes.iter_mut().enumerate() {
                if !self.alive[i] {
                    continue;
                }
                let out = node.tick(self.now);
                for m in out.publish {
                    bus.push((i, m));
                }
            }
            for (src, m) in bus {
                for (j, node) in self.nodes.iter_mut().enumerate() {
                    if self.alive[j] && j != src {
                        node.observe(m.clone(), self.now);
                    }
                }
            }
        }

        /// Live claimants for `target` as seen by a *surviving* node (a dead
        /// node's view freezes at its death, so it must not be the observer).
        fn live_claimants(&self, target: &str) -> usize {
            let alive = self.alive.iter().position(|&a| a).expect("a node is alive");
            self.nodes[alive].state().live_claimants(&n(target), self.now).len()
        }
    }

    #[test]
    fn cluster_converges_to_replication_factor() {
        let mut sim = Sim::new(&["/r/a", "/r/b", "/r/c", "/r/d", "/r/e"], 1000);
        sim.announce_all("/obj/data");
        // A few rounds for heartbeats to register and claims to propagate.
        for _ in 0..4 {
            sim.round();
        }
        assert_eq!(
            sim.live_claimants("/obj/data"),
            3,
            "exactly replication_factor nodes durably hold the object"
        );
    }

    #[test]
    fn cluster_re_replicates_after_a_node_dies() {
        let mut sim = Sim::new(&["/r/a", "/r/b", "/r/c", "/r/d", "/r/e"], 1000);
        sim.announce_all("/obj/data");
        for _ in 0..4 {
            sim.round();
        }
        assert_eq!(sim.live_claimants("/obj/data"), 3);

        // Find a current claimant and kill it (node 0 is alive here).
        let claimants = sim.nodes[0].state().live_claimants(&n("/obj/data"), sim.now);
        let victim = claimants[0].clone();
        let victim_idx = sim.nodes.iter().position(|node| *node.self_id() == victim).unwrap();
        sim.kill(victim_idx);

        // Let the dead node age out (>3 rounds of silence) and survivors react.
        for _ in 0..6 {
            sim.round();
        }
        assert_eq!(
            sim.live_claimants("/obj/data"),
            3,
            "a survivor re-replicated the dead node's share back to the factor"
        );
        // The victim is no longer a live claimant (as a survivor sees it).
        let observer = sim.alive.iter().position(|&a| a).unwrap();
        let now_claimants = sim.nodes[observer].state().live_claimants(&n("/obj/data"), sim.now);
        assert!(!now_claimants.contains(&victim));
    }

    #[test]
    fn tick_emits_heartbeat_then_claims() {
        let mut node = ClusterNode::new(n("/r/solo"), cfg(), 1000);
        node.announce_job(n("/obj/x"), 0);
        let out = node.tick(1_000);
        assert!(matches!(out.publish.first(), Some(ClusterMsg::Heartbeat { .. })));
        // Solo node is designated for the under-replicated job → claims + ingests.
        assert_eq!(out.ingest, vec![n("/obj/x")]);
        assert!(out.publish.iter().any(|m| matches!(m, ClusterMsg::Claim { .. })));
    }
}

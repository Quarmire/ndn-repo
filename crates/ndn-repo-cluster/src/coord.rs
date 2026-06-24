//! Decentralised coordination logic — pure, deterministic, transport-free.
//!
//! Every node feeds the cluster's shared, eventually-consistent state (peers'
//! heartbeats + job claims, gossiped over an SVS coordination group) into an
//! identical [`ClusterState`]. Because the state converges and the placement
//! decision is a deterministic function of it, every node independently
//! computes the **same** assignment without a coordinator or locks:
//!
//! * a job is *covered* when `replication_factor` **live** nodes claim it;
//! * a node is *live* while its last heartbeat is within
//!   `missed_heartbeats × heartbeat_interval` (default 3 misses → dead);
//! * when a job is under-replicated, the lowest-utilisation live nodes with
//!   spare capacity are *designated* to claim it (capacity-aware load
//!   balancing); a node claims iff it is in that designated set;
//! * a node over its capacity high-watermark sheds only *over*-replicated
//!   jobs, so relief never breaks coverage.
//!
//! A dead node's claims stop counting → the job becomes under-replicated →
//! survivors re-designate and re-claim. That is the failover.

use std::collections::HashMap;

use ndn_packet::Name;

/// A repo node's cluster identity (its NDN name).
pub type NodeId = Name;

/// A unit of durable work — replicate this target (an object or SVS group).
/// The target name *is* the job id, so every node agrees on job identity.
pub type JobId = Name;

#[derive(Clone, Debug)]
pub struct ClusterConfig {
    /// Desired number of distinct live nodes holding each job. Default 3.
    pub replication_factor: usize,
    /// Expected heartbeat period (ns).
    pub heartbeat_interval_ns: u64,
    /// Consecutive missed heartbeats before a node is declared dead. Default 3.
    pub missed_heartbeats: u32,
    /// Utilisation (0.0–1.0) at/above which a node accepts no new jobs and
    /// sheds over-replicated ones. Default 0.75.
    pub capacity_high_watermark: f64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            heartbeat_interval_ns: 5_000_000_000, // 5 s
            missed_heartbeats: 3,
            capacity_high_watermark: 0.75,
        }
    }
}

impl ClusterConfig {
    fn dead_after_ns(&self) -> u64 {
        self.heartbeat_interval_ns
            .saturating_mul(self.missed_heartbeats as u64)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NodeStatus {
    pub last_heartbeat_ns: u64,
    pub capacity_used: u64,
    pub capacity_total: u64,
}

impl NodeStatus {
    /// Fraction of capacity used (0.0 when total is 0 — treated as empty).
    pub fn utilization(&self) -> f64 {
        if self.capacity_total == 0 {
            0.0
        } else {
            self.capacity_used as f64 / self.capacity_total as f64
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Job {
    /// Per-job override; falls back to the cluster default when 0.
    pub replication_factor: usize,
    /// node → claim timestamp (ns). Liveness is judged separately.
    pub claimants: HashMap<NodeId, u64>,
    /// G6 erasure spec `(k, n)`: the object is N = k+R shards (one per holder),
    /// recoverable from any K. `None` ⇒ whole-object replication. When set, the effective
    /// replication is N (so N holders are placed), and each holder stores one shard.
    pub erasure: Option<(u16, u16)>,
}

/// What one node must store for an erasure-coded job: its shard `index` of the N, and the
/// `(k, n)` needed to name shards and reconstruct. From [`ClusterState::shard_plan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardPlan {
    pub index: u16,
    pub k: u16,
    pub n: u16,
}

/// One node's converged view of the cluster.
#[derive(Clone, Debug)]
pub struct ClusterState {
    config: ClusterConfig,
    nodes: HashMap<NodeId, NodeStatus>,
    jobs: HashMap<JobId, Job>,
}

impl ClusterState {
    pub fn new(config: ClusterConfig) -> Self {
        Self {
            config,
            nodes: HashMap::new(),
            jobs: HashMap::new(),
        }
    }

    pub fn config(&self) -> &ClusterConfig {
        &self.config
    }

    // ---- observation (fold gossiped state in) --------------------------------

    /// Record a heartbeat (newer timestamps win).
    pub fn observe_heartbeat(&mut self, node: NodeId, used: u64, total: u64, now_ns: u64) {
        let e = self.nodes.entry(node).or_insert(NodeStatus {
            last_heartbeat_ns: 0,
            capacity_used: used,
            capacity_total: total,
        });
        if now_ns >= e.last_heartbeat_ns {
            e.last_heartbeat_ns = now_ns;
            e.capacity_used = used;
            e.capacity_total = total;
        }
    }

    /// Register (or refresh) a job. `replication_factor == 0` uses the default.
    pub fn observe_job(&mut self, job: JobId, replication_factor: usize) {
        let j = self.jobs.entry(job).or_default();
        if replication_factor != 0 {
            j.replication_factor = replication_factor;
        }
    }

    /// Register (or refresh) an **erasure-coded** job (G6): N = `k + redundancy` shards,
    /// one per holder, recoverable from any K. The effective replication becomes N, so N
    /// holders are placed — each storing the shard at its [`shard_plan`](Self::shard_plan)
    /// index. `k`/`redundancy` of 0 are clamped to 1.
    pub fn observe_erasure_job(&mut self, job: JobId, k: u16, redundancy: u16) {
        let k = k.max(1);
        let n = k.saturating_add(redundancy.max(1));
        let j = self.jobs.entry(job).or_default();
        j.erasure = Some((k, n));
    }

    /// Record a node's claim on a job (creates the job if unseen).
    pub fn observe_claim(&mut self, job: JobId, node: NodeId, ts_ns: u64) {
        let j = self.jobs.entry(job).or_default();
        let e = j.claimants.entry(node).or_insert(0);
        *e = (*e).max(ts_ns);
    }

    /// Record a node releasing a job.
    pub fn observe_release(&mut self, job: &JobId, node: &NodeId) {
        if let Some(j) = self.jobs.get_mut(job) {
            j.claimants.remove(node);
        }
    }

    // ---- queries -------------------------------------------------------------

    pub fn is_live(&self, node: &NodeId, now_ns: u64) -> bool {
        self.nodes
            .get(node)
            .is_some_and(|s| now_ns.saturating_sub(s.last_heartbeat_ns) <= self.config.dead_after_ns())
    }

    fn has_capacity(&self, node: &NodeId) -> bool {
        self.nodes
            .get(node)
            .is_some_and(|s| s.utilization() < self.config.capacity_high_watermark)
    }

    /// Live nodes, sorted for deterministic placement (utilisation asc, then
    /// name) so every node computes the same ordering.
    fn ranked_live_nodes(&self, now_ns: u64) -> Vec<NodeId> {
        let mut live: Vec<(&NodeId, f64)> = self
            .nodes
            .iter()
            .filter(|(n, _)| self.is_live(n, now_ns))
            .map(|(n, s)| (n, s.utilization()))
            .collect();
        live.sort_by(|(na, ua), (nb, ub)| {
            ua.partial_cmp(ub)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| na.cmp(nb))
        });
        live.into_iter().map(|(n, _)| n.clone()).collect()
    }

    /// The `count` live nodes that should each hold one erasure shard (G6), in
    /// shard-index order — shard `i` is held by `shard_holders(..)[i]`. Deterministic
    /// (utilisation asc, ties by name), so every node agrees on the layout without a
    /// coordinator. Returns fewer than `count` only when the cluster has fewer placeable
    /// nodes than shards (the object isn't fully placeable then — raise redundancy or
    /// wait for nodes).
    ///
    /// G6.5: this is filtered by [`has_capacity`](Self::has_capacity) — the **same** pool
    /// [`designated_claimers`](Self::designated_claimers) draws from. If it weren't, a node
    /// that lacked capacity would still occupy a shard index here while never being asked to
    /// claim, so that shard would go unstored and the node that *does* claim (further down
    /// the ranking) would compute no index for itself — the placement and the claim set
    /// would diverge under capacity pressure.
    pub fn shard_holders(&self, count: usize, now_ns: u64) -> Vec<NodeId> {
        self.ranked_live_nodes(now_ns)
            .into_iter()
            .filter(|n| self.has_capacity(n))
            .take(count)
            .collect()
    }

    /// This node's shard index for an `n`-shard object, or `None` if it is not one of
    /// the `n` holders.
    pub fn shard_index_of(&self, self_id: &NodeId, n: usize, now_ns: u64) -> Option<u16> {
        self.shard_holders(n, now_ns)
            .iter()
            .position(|node| node == self_id)
            .map(|i| i as u16)
    }

    fn effective_replication(&self, job: &Job) -> usize {
        // An erasure job needs N holders (one shard each); that overrides the
        // copy-count replication factor.
        if let Some((_, n)) = job.erasure {
            return n as usize;
        }
        if job.replication_factor != 0 {
            job.replication_factor
        } else {
            self.config.replication_factor
        }
    }

    /// What `self_id` must store for `job`, if `job` is erasure-coded and `self_id` is one
    /// of its N holders: the shard index (its rank among holders) + `(k, n)`. `None` for a
    /// whole-object (replicated) job, or when `self_id` is not a holder. The embedder uses
    /// it to fetch/store `<job>/EC/<index>` instead of the whole object, and to know it
    /// needs any K shards to reconstruct on read.
    pub fn shard_plan(&self, job: &JobId, self_id: &NodeId, now_ns: u64) -> Option<ShardPlan> {
        let (k, n) = self.jobs.get(job)?.erasure?;
        let index = self.shard_index_of(self_id, n as usize, now_ns)?;
        Some(ShardPlan { index, k, n })
    }

    /// Claimants that are currently live.
    pub fn live_claimants(&self, job: &JobId, now_ns: u64) -> Vec<NodeId> {
        self.jobs
            .get(job)
            .map(|j| {
                j.claimants
                    .keys()
                    .filter(|n| self.is_live(n, now_ns))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn is_under_replicated(&self, job: &JobId, now_ns: u64) -> bool {
        match self.jobs.get(job) {
            Some(j) => self.live_claimants(job, now_ns).len() < self.effective_replication(j),
            None => false,
        }
    }

    /// Jobs with fewer than `replication_factor` live claimants.
    pub fn under_replicated_jobs(&self, now_ns: u64) -> Vec<JobId> {
        self.jobs
            .keys()
            .filter(|j| self.is_under_replicated(j, now_ns))
            .cloned()
            .collect()
    }

    /// The nodes designated to claim `job` next: the lowest-utilisation live,
    /// has-capacity, non-claiming nodes, exactly enough to reach the
    /// replication factor. Deterministic across nodes (same input → same set),
    /// so concurrent claims converge to ~no over-replication.
    pub fn designated_claimers(&self, job: &JobId, now_ns: u64) -> Vec<NodeId> {
        let Some(j) = self.jobs.get(job) else {
            return Vec::new();
        };
        let need = self
            .effective_replication(j)
            .saturating_sub(self.live_claimants(job, now_ns).len());
        if need == 0 {
            return Vec::new();
        }
        self.ranked_live_nodes(now_ns)
            .into_iter()
            .filter(|n| self.has_capacity(n) && !j.claimants.contains_key(n))
            .take(need)
            .collect()
    }

    /// Whether `self_node` should claim `job` now (it is designated for it).
    pub fn should_claim(&self, job: &JobId, self_node: &NodeId, now_ns: u64) -> bool {
        self.designated_claimers(job, now_ns)
            .iter()
            .any(|n| n == self_node)
    }

    /// All jobs `self_node` is designated to claim now.
    pub fn jobs_to_claim(&self, self_node: &NodeId, now_ns: u64) -> Vec<JobId> {
        self.under_replicated_jobs(now_ns)
            .into_iter()
            .filter(|j| self.should_claim(j, self_node, now_ns))
            .collect()
    }

    /// The live claimants that should *keep* `job`: the lowest-utilisation
    /// `replication_factor` of them (ties by name). Deterministic, so the set
    /// of "excess" claimants that must release is unambiguous across nodes —
    /// this is what trims transient over-replication back to the factor and,
    /// because keepers are the lowest-utilisation nodes, sheds load from the
    /// fullest nodes first.
    pub fn designated_keepers(&self, job: &JobId, now_ns: u64) -> Vec<NodeId> {
        let Some(j) = self.jobs.get(job) else {
            return Vec::new();
        };
        let mut live: Vec<(NodeId, f64)> = self
            .live_claimants(job, now_ns)
            .into_iter()
            .map(|n| {
                let u = self.nodes.get(&n).map(|s| s.utilization()).unwrap_or(0.0);
                (n, u)
            })
            .collect();
        live.sort_by(|(na, ua), (nb, ub)| {
            ua.partial_cmp(ub)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| na.cmp(nb))
        });
        live.into_iter()
            .take(self.effective_replication(j))
            .map(|(n, _)| n)
            .collect()
    }

    /// Jobs `self_node` should release: ones it claims but is *not* a keeper
    /// for (excess replicas). Trims over-replication to the factor and never
    /// drops below it (a keeper is retained even when full — coverage wins).
    pub fn jobs_to_release(&self, self_node: &NodeId, now_ns: u64) -> Vec<JobId> {
        self.jobs
            .iter()
            .filter(|(jid, j)| {
                j.claimants.contains_key(self_node)
                    && self.is_live(self_node, now_ns)
                    && !self.designated_keepers(jid, now_ns).contains(self_node)
            })
            .map(|(jid, _)| jid.clone())
            .collect()
    }

    // ---- introspection -------------------------------------------------------

    pub fn live_nodes(&self, now_ns: u64) -> Vec<NodeId> {
        self.nodes
            .keys()
            .filter(|n| self.is_live(n, now_ns))
            .cloned()
            .collect()
    }

    pub fn job_ids(&self) -> Vec<JobId> {
        self.jobs.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn cfg() -> ClusterConfig {
        ClusterConfig {
            replication_factor: 3,
            heartbeat_interval_ns: 1_000,
            missed_heartbeats: 3, // dead after 3_000 ns of silence
            capacity_high_watermark: 0.75,
        }
    }

    /// Heartbeat with capacity used/total at `now`.
    fn beat(st: &mut ClusterState, node: &str, used: u64, total: u64, now: u64) {
        st.observe_heartbeat(n(node), used, total, now);
    }

    #[test]
    fn liveness_window() {
        let mut st = ClusterState::new(cfg());
        beat(&mut st, "/r/a", 0, 100, 1_000);
        assert!(st.is_live(&n("/r/a"), 1_000));
        assert!(st.is_live(&n("/r/a"), 4_000)); // exactly at the 3_000 boundary
        assert!(!st.is_live(&n("/r/a"), 4_001)); // past it → dead
    }

    #[test]
    fn shard_holders_are_deterministic_lowest_utilisation_first() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        // Distinct utilisations so the ranking is unambiguous: c(10%) < a(20%) < b(30%) ...
        beat(&mut st, "/r/b", 30, 100, now);
        beat(&mut st, "/r/a", 20, 100, now);
        beat(&mut st, "/r/c", 10, 100, now);
        beat(&mut st, "/r/d", 40, 100, now);

        // Place 3 shards: the 3 lowest-utilisation live nodes, in shard-index order.
        let holders = st.shard_holders(3, now);
        assert_eq!(holders, vec![n("/r/c"), n("/r/a"), n("/r/b")]);
        // Each node knows its own shard index (or that it holds none).
        assert_eq!(st.shard_index_of(&n("/r/c"), 3, now), Some(0));
        assert_eq!(st.shard_index_of(&n("/r/b"), 3, now), Some(2));
        assert_eq!(st.shard_index_of(&n("/r/d"), 3, now), None, "4th node holds no shard of 3");

        // Asking for more shards than live nodes returns only the live ones (not placeable).
        assert_eq!(st.shard_holders(9, now).len(), 4);
    }

    /// G6.5: the shard placement and the claim pool must agree under capacity pressure —
    /// a node without capacity is excluded from BOTH (it's never asked to claim, so it must
    /// not occupy a shard index either), and the capacity-having node that does claim gets a
    /// consistent index.
    #[test]
    fn shard_holders_match_the_claim_pool_under_capacity_pressure() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        beat(&mut st, "/r/b", 10, 100, now); // 10% util → has capacity
        beat(&mut st, "/r/a", 80, 100, now); // 80% > 75% watermark → no capacity

        // shard_holders excludes the no-capacity node even though only 2 nodes are live.
        assert_eq!(
            st.shard_holders(2, now),
            vec![n("/r/b")],
            "only the capacity-having node is a holder"
        );
        assert_eq!(
            st.shard_index_of(&n("/r/a"), 2, now),
            None,
            "the no-capacity node gets no shard index (it won't be asked to claim)"
        );
        assert_eq!(st.shard_index_of(&n("/r/b"), 2, now), Some(0));

        // The 2-holder erasure job's designated claimers are exactly the holder set — no
        // node is asked to claim a shard it has no index for.
        let job = n("/obj/v=1");
        st.observe_erasure_job(job.clone(), 1, 1); // (k=1, n=2)
        let designated = st.designated_claimers(&job, now);
        assert_eq!(designated, vec![n("/r/b")], "claim pool == holder pool");
    }

    #[test]
    fn under_replicated_until_factor_reached() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        for node in ["/r/a", "/r/b", "/r/c", "/r/d"] {
            beat(&mut st, node, 10, 100, now);
        }
        let job = n("/obj/x");
        st.observe_job(job.clone(), 0);
        assert!(st.is_under_replicated(&job, now));
        // Two claims → still under (need 3).
        st.observe_claim(job.clone(), n("/r/a"), now);
        st.observe_claim(job.clone(), n("/r/b"), now);
        assert!(st.is_under_replicated(&job, now));
        // Third → covered.
        st.observe_claim(job.clone(), n("/r/c"), now);
        assert!(!st.is_under_replicated(&job, now));
        assert_eq!(st.live_claimants(&job, now).len(), 3);
    }

    #[test]
    fn designation_is_capacity_aware_and_exactly_enough() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        // Four nodes at different utilisation; one (d) is over the 0.75 mark.
        beat(&mut st, "/r/a", 50, 100, now); // 0.50
        beat(&mut st, "/r/b", 10, 100, now); // 0.10  (lowest)
        beat(&mut st, "/r/c", 30, 100, now); // 0.30
        beat(&mut st, "/r/d", 90, 100, now); // 0.90  (full → excluded)
        let job = n("/obj/y");
        st.observe_job(job.clone(), 0);

        // Need 3; the 3 lowest-utilisation nodes with capacity are b,c,a
        // (in that order); d is excluded for being over the watermark.
        let designated = st.designated_claimers(&job, now);
        assert_eq!(designated, vec![n("/r/b"), n("/r/c"), n("/r/a")]);
        assert!(st.should_claim(&job, &n("/r/b"), now));
        assert!(!st.should_claim(&job, &n("/r/d"), now), "full node not designated");
    }

    #[test]
    fn designation_excludes_existing_claimants_and_shrinks() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        for node in ["/r/a", "/r/b", "/r/c"] {
            beat(&mut st, node, 10, 100, now);
        }
        let job = n("/obj/z");
        st.observe_job(job.clone(), 0);
        st.observe_claim(job.clone(), n("/r/a"), now);
        // One claim present → only 2 more designated, and a is excluded.
        let d = st.designated_claimers(&job, now);
        assert_eq!(d.len(), 2);
        assert!(!d.contains(&n("/r/a")));
    }

    #[test]
    fn failover_redesignates_after_a_claimant_dies() {
        let mut st = ClusterState::new(cfg());
        let t0 = 1_000;
        for node in ["/r/a", "/r/b", "/r/c", "/r/d"] {
            beat(&mut st, node, 10, 100, t0);
        }
        let job = n("/obj/f");
        st.observe_job(job.clone(), 0);
        for node in ["/r/a", "/r/b", "/r/c"] {
            st.observe_claim(job.clone(), n(node), t0);
        }
        assert!(!st.is_under_replicated(&job, t0));

        // Time advances; a,b,c keep beating but the *claimant* /r/a goes silent
        // while /r/d stays alive. Refresh b,c,d at t1; a is now stale.
        let t1 = t0 + 3_500; // > dead_after for a (last beat t0)
        for node in ["/r/b", "/r/c", "/r/d"] {
            beat(&mut st, node, 10, 100, t1);
        }
        assert!(!st.is_live(&n("/r/a"), t1), "a is dead");
        // a's claim no longer counts → under-replicated → d is designated.
        assert!(st.is_under_replicated(&job, t1));
        assert_eq!(st.live_claimants(&job, t1).len(), 2);
        let d = st.designated_claimers(&job, t1);
        assert_eq!(d, vec![n("/r/d")], "the surviving spare node takes over");
        assert!(st.should_claim(&job, &n("/r/d"), t1));
    }

    #[test]
    fn over_capacity_sheds_only_over_replicated_jobs() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        beat(&mut st, "/r/a", 90, 100, now); // full (0.90)
        for node in ["/r/b", "/r/c", "/r/d"] {
            beat(&mut st, node, 10, 100, now);
        }
        // job1: a + b + c + d = 4 live claimants > repl 3 → over-replicated.
        let job1 = n("/obj/over");
        st.observe_job(job1.clone(), 0);
        for node in ["/r/a", "/r/b", "/r/c", "/r/d"] {
            st.observe_claim(job1.clone(), n(node), now);
        }
        // job2: a + b + c = exactly 3 → at target.
        let job2 = n("/obj/exact");
        st.observe_job(job2.clone(), 0);
        for node in ["/r/a", "/r/b", "/r/c"] {
            st.observe_claim(job2.clone(), n(node), now);
        }

        let shed = st.jobs_to_release(&n("/r/a"), now);
        assert_eq!(shed, vec![job1], "shed the over-replicated job, keep the at-target one");
        // A non-full node sheds nothing.
        assert!(st.jobs_to_release(&n("/r/b"), now).is_empty());
    }

    #[test]
    fn jobs_to_claim_lists_designated_under_replicated_jobs() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        for node in ["/r/a", "/r/b", "/r/c"] {
            beat(&mut st, node, 10, 100, now);
        }
        st.observe_job(n("/obj/1"), 0);
        st.observe_job(n("/obj/2"), 0);
        // With 3 live empty nodes and repl 3, all are designated for both jobs.
        let mut claim = st.jobs_to_claim(&n("/r/a"), now);
        claim.sort();
        assert_eq!(claim, vec![n("/obj/1"), n("/obj/2")]);
    }

    /// Every node computes the identical designated set from the same state —
    /// the property that lets placement be coordinator-free.
    #[test]
    fn designation_is_deterministic_across_nodes() {
        let mut st = ClusterState::new(cfg());
        let now = 1_000;
        for (node, used) in [("/r/a", 30), ("/r/b", 10), ("/r/c", 20), ("/r/d", 40)] {
            beat(&mut st, node, used, 100, now);
        }
        let job = n("/obj/d");
        st.observe_job(job.clone(), 0);
        let d1 = st.designated_claimers(&job, now);
        let d2 = st.clone().designated_claimers(&job, now);
        assert_eq!(d1, d2);
        // Lowest-utilisation three: b(0.10), c(0.20), a(0.30).
        assert_eq!(d1, vec![n("/r/b"), n("/r/c"), n("/r/a")]);
    }
}

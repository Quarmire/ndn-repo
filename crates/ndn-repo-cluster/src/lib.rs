//! `ndn-repo-cluster` — a distributed coordination layer above `ndn-repo`.
//!
//! Turns independent single-node [`Repo`](ndn_repo::Repo)s into a resilient
//! cluster: each object/group is durably held by `replication_factor` nodes,
//! placement is capacity-aware, and a node failing is detected by missed
//! heartbeats and its share re-replicated onto survivors — the feature set of
//! `a-thieme/repo`, built NDN-natively.
//!
//! The design is fully **decentralised**: nodes gossip heartbeats + job claims
//! over an SVS coordination group, fold them into an identical, converging
//! [`ClusterState`](coord::ClusterState), and each independently runs the same
//! deterministic placement function — no coordinator, no locks. This is a
//! *coordination layer*, not a wire standard; it composes above the
//! ndnd-compatible single-node repo rather than replacing its command protocol.

pub mod coord;
pub mod msg;
pub mod node;

pub use coord::{ClusterConfig, ClusterState, JobId, NodeId, NodeStatus};
pub use msg::ClusterMsg;
pub use node::{ClusterNode, TickOutcome, run};

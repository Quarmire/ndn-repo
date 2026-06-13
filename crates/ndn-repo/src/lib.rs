//! `ndn-repo` — a persistent named-data repository.
//!
//! A repo durably stores Data and serves it by name *after the producer is
//! gone* — third-party custody at the network layer, application-agnostic
//! (distinct from a service framework like NDF, which sits above it). The
//! command protocol is **byte-compatible with ndnd's `repo`**
//! ([`tlv::RepoCmd`]: `SyncJoin` / `SyncLeave` / `BlobFetch`), so an ndnd
//! client can drive an `ndn-repo` and vice versa.
//!
//! Two ingestion paths, both as in ndnd:
//! * **SVS group** — `SyncJoin` joins a sync group; the repo ingests every
//!   publication and serves it. Wire an [`ndn_sync::SvSync`] at
//!   [`Repo::store`](repo::Repo::store): its demux serves stored Data and its
//!   fetch path pulls publications into the same store.
//! * **Blob push** — `BlobFetch` carries Data wires inline (stored directly)
//!   or a name to fetch ([`Repo::take_pending_fetches`](repo::Repo::take_pending_fetches)).
//!
//! The [`Repo`](repo::Repo) engine is transport-agnostic; an embedder connects
//! its command interface to a forwarder face. Distributed operation
//! (replication, capacity-aware placement, heartbeat failover — cf.
//! `a-thieme/repo`) is a coordination layer above this single-node core.

pub mod ingest;
pub mod repo;
pub mod service;
pub mod store;
pub mod tlv;

pub use ingest::ingest_group;
pub use service::{RepoService, RepoServiceConfig};
#[cfg(feature = "fjall-store")]
pub use store::FjallStore;
pub use repo::{Repo, RepoError};
pub use tlv::{BlobFetch, RepoCmd, RepoCmdRes, SyncJoin, SyncLeave, sync_protocol_svs_v3};

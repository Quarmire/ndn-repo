//! End-to-end integration over a **real forwarding engine**: independent repo
//! nodes (separate faces, communicating only through the forwarder's PIT/FIB)
//! coordinate via `ndn-repo-cluster` and replicate a producer's object.
//!
//! These are not unit tests of the coordination logic (that is proven
//! deterministically in `node.rs`); they prove the *wiring* — that a
//! `ClusterNode`'s ingest decision flows into a `RepoService` which then
//! ingests + serves real Data through a real forwarder.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use ndn_app::connection::{Connection, InProcConnection};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_native::local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_repo::{Repo, RepoControl, RepoService, RepoServiceConfig};
use ndn_strategy::MulticastStrategy;
use ndn_sync::{MemoryStore, SvsConfig, svs_data_name};
use ndn_transport::FaceId;

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

fn fast_svs() -> SvsConfig {
    SvsConfig {
        sync_interval: Duration::from_millis(40),
        jitter_ms: 0,
        ..Default::default()
    }
}

/// Bridge an in-process engine handle to the raw `(send, recv)` channels a
/// `RepoService` drives, and spawn the service. Returns a clone of the repo so
/// the test can inspect what it has durably stored.
fn spawn_repo_node(
    handle: InProcHandle,
    repo_prefix: Name,
    initial_groups: Vec<Name>,
    control_rx: Option<mpsc::Receiver<RepoControl>>,
) -> Repo {
    let repo = Repo::new(Arc::new(MemoryStore::new()));
    let conn = Arc::new(InProcConnection::new(handle));

    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
    let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);

    let cs = Arc::clone(&conn);
    tokio::spawn(async move {
        while let Some(p) = out_rx.recv().await {
            let _ = cs.send(p).await;
        }
    });
    let cr = Arc::clone(&conn);
    tokio::spawn(async move {
        while let Some(p) = cr.recv().await {
            if in_tx.send(p).await.is_err() {
                break;
            }
        }
    });

    let cfg = RepoServiceConfig {
        initial_groups,
        svs: ndn_sync::SvSyncConfig { svs: fast_svs(), ..Default::default() },
        ..Default::default()
    };
    let mut svc = RepoService::new(repo.clone(), repo_prefix, out_tx, cfg);
    if let Some(rx) = control_rx {
        svc = svc.with_control(rx);
    }
    tokio::spawn(svc.run(in_rx));
    repo
}

/// Poll `repo` until it holds `name`, or time out.
async fn await_stored(repo: &Repo, name: &Name, within: Duration) -> Option<Bytes> {
    tokio::time::timeout(within, async {
        loop {
            if let Some(w) = repo.get(name) {
                break w;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .ok()
}

/// Foundation: a `RepoService` joining a data group ingests a producer's
/// published object **over a real forwarder** and durably holds it.
#[tokio::test]
async fn repo_service_ingests_from_producer_over_forwarder() {
    let data_group = name("/cl/data");

    let (producer_face, producer_handle) = InProcFace::new(FaceId(1), 256);
    let (repo_face, repo_handle) = InProcFace::new(FaceId(2), 256);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .strategy(MulticastStrategy::new())
        .face(producer_face)
        .face(repo_face)
        .build()
        .await
        .expect("engine");

    // The data group fans (multicast) to both participants, so SVS sync
    // Interests and publication fetches reach the producer and the repo.
    engine.fib().add_nexthop(&data_group, FaceId(1), 0);
    engine.fib().add_nexthop(&data_group, FaceId(2), 0);

    // Producer publishes one object into the group.
    let producer = ndn_app::Publisher::from_handle(
        producer_handle,
        data_group.clone(),
        name("/cl/data/producer"),
        ndn_app::PublisherConfig { svs: fast_svs(), ..Default::default() },
    )
    .expect("publisher");

    // Repo joins the group and ingests whatever is published.
    let repo = spawn_repo_node(repo_handle, name("/cl/repo"), vec![data_group.clone()], None);

    // Let SVS memberships establish, then publish.
    tokio::time::sleep(Duration::from_millis(150)).await;
    producer.put(b"the-replicated-object").await.expect("put");

    let want = svs_data_name(&name("/cl/data/producer"), &data_group, 1);
    let wire = await_stored(&repo, &want, Duration::from_secs(8))
        .await
        .expect("repo never ingested the object over the forwarder");
    let data = ndn_packet::Data::decode(wire).unwrap();
    assert_eq!(data.content().unwrap().as_ref(), b"the-replicated-object");

    drop(producer);
    drop(engine);
    shutdown.shutdown().await;
}

use ndn_repo_cluster::{ClusterConfig, ClusterNode};
use ndn_sync::{SvSync, SvSyncConfig};
use tokio_util::sync::CancellationToken;

/// Wire a full cluster node onto the engine: a data-plane `RepoService` (driven
/// by `RepoControl`), a coordination-plane `SvSync` over `/cl/coord`, and a
/// `ClusterNode` whose claims (gossiped over the coord group) decide which
/// targets the `RepoService` joins. Returns a repo clone for inspection.
#[allow(clippy::too_many_arguments)]
fn spawn_cluster_node(
    idx: usize,
    data_handle: InProcHandle,
    coord_handle: InProcHandle,
    data_group: Name,
    coord_group: Name,
    replication_factor: usize,
    cancel: CancellationToken,
) -> Repo {
    let self_id = name(&format!("/cl/coord/{idx}"));

    // --- data plane: RepoService with an out-of-band control channel ---------
    let (ctl_tx, ctl_rx) = mpsc::channel::<RepoControl>(16);
    let repo = spawn_repo_node(
        data_handle,
        name(&format!("/cl/repo/{idx}")),
        vec![],
        Some(ctl_rx),
    );

    // --- coordination plane: an SvSync over the coord group ------------------
    let coord_conn = Arc::new(InProcConnection::new(coord_handle));
    let (coord_out_tx, mut coord_out_rx) = mpsc::channel::<Bytes>(256);
    let (coord_in_tx, coord_in_rx) = mpsc::channel::<Bytes>(256);
    {
        let c = Arc::clone(&coord_conn);
        tokio::spawn(async move {
            while let Some(p) = coord_out_rx.recv().await {
                let _ = c.send(p).await;
            }
        });
        let c = Arc::clone(&coord_conn);
        tokio::spawn(async move {
            while let Some(p) = c.recv().await {
                if coord_in_tx.send(p).await.is_err() {
                    break;
                }
            }
        });
    }
    let mut coord_svs = SvSync::join(
        coord_group,
        self_id.clone(),
        Arc::new(MemoryStore::new()),
        coord_out_tx,
        coord_in_rx,
        SvSyncConfig { svs: fast_svs(), ..Default::default() },
    );
    let mut updates = coord_svs.take_updates();
    let coord_svs = Arc::new(coord_svs);

    // publish_msg → publish a ClusterMsg as a coord-group publication.
    let (pub_tx, mut pub_rx) = mpsc::channel::<Bytes>(256);
    {
        let svs = Arc::clone(&coord_svs);
        tokio::spawn(async move {
            while let Some(b) = pub_rx.recv().await {
                let _ = svs.publish_data(&b).await;
            }
        });
    }
    // incoming ← peers' coord publications (fetched over the forwarder).
    let (incoming_tx, incoming_rx) = mpsc::channel::<Bytes>(256);
    {
        let svs = Arc::clone(&coord_svs);
        tokio::spawn(async move {
            while let Some(u) = updates.recv().await {
                for seq in u.low_seq..=u.high_seq {
                    if let Some(c) = svs.fetch(&u.name, seq).await {
                        let _ = incoming_tx.send(c).await;
                    }
                }
            }
        });
    }

    // ingest decisions → RepoService Join; drops → Leave.
    let (ingest_tx, mut ingest_rx) = mpsc::channel::<Name>(64);
    let (drop_tx, mut drop_rx) = mpsc::channel::<Name>(64);
    {
        let ctl = ctl_tx.clone();
        tokio::spawn(async move {
            while let Some(job) = ingest_rx.recv().await {
                let _ = ctl.send(RepoControl::Join(job)).await;
            }
        });
        let ctl = ctl_tx;
        tokio::spawn(async move {
            while let Some(job) = drop_rx.recv().await {
                let _ = ctl.send(RepoControl::Leave(job)).await;
            }
        });
    }

    // --- the coordinator ------------------------------------------------------
    let mut node = ClusterNode::new(
        self_id,
        ClusterConfig {
            replication_factor,
            heartbeat_interval_ns: 100_000_000, // 100 ms (== tick)
            missed_heartbeats: 3,
            capacity_high_watermark: 0.75,
        },
        1_000_000,
    );
    node.announce_job(data_group, replication_factor);

    let publish_msg: Arc<dyn Fn(Bytes) + Send + Sync> =
        Arc::new(move |b: Bytes| { let _ = pub_tx.try_send(b); });
    let capacity: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| 0);
    tokio::spawn(ndn_repo_cluster::run(
        node,
        Duration::from_millis(100),
        publish_msg,
        incoming_rx,
        ingest_tx,
        drop_tx,
        capacity,
        cancel,
    ));

    repo
}

/// The headline integration: three independent repo nodes — each a separate
/// face on a real forwarder — coordinate over a coord SVS group and replicate
/// a producer's object to `replication_factor` of them, with the placement
/// decision flowing from each `ClusterNode` into its `RepoService` and out as
/// real ingestion through the forwarder.
#[tokio::test]
async fn cluster_replicates_object_to_replication_factor_over_forwarder() {
    let data_group = name("/cl/data");
    let coord_group = name("/cl/coord");
    let replication_factor = 2;

    // Faces: producer (1); per repo a data face + a coord face.
    let (producer_face, producer_handle) = InProcFace::new(FaceId(1), 256);
    let (d0, h_d0) = InProcFace::new(FaceId(2), 256);
    let (c0, h_c0) = InProcFace::new(FaceId(3), 256);
    let (d1, h_d1) = InProcFace::new(FaceId(4), 256);
    let (c1, h_c1) = InProcFace::new(FaceId(5), 256);
    let (d2, h_d2) = InProcFace::new(FaceId(6), 256);
    let (c2, h_c2) = InProcFace::new(FaceId(7), 256);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .strategy(MulticastStrategy::new())
        .face(producer_face)
        .face(d0)
        .face(c0)
        .face(d1)
        .face(c1)
        .face(d2)
        .face(c2)
        .build()
        .await
        .expect("engine");

    // Multicast routing: the data group fans to the producer + every repo data
    // face; the coord group fans to every coord face.
    for fid in [1u64, 2, 4, 6] {
        engine.fib().add_nexthop(&data_group, FaceId(fid), 0);
    }
    for fid in [3u64, 5, 7] {
        engine.fib().add_nexthop(&coord_group, FaceId(fid), 0);
    }

    let cancel = CancellationToken::new();
    let repos = [
        spawn_cluster_node(0, h_d0, h_c0, data_group.clone(), coord_group.clone(), replication_factor, cancel.clone()),
        spawn_cluster_node(1, h_d1, h_c1, data_group.clone(), coord_group.clone(), replication_factor, cancel.clone()),
        spawn_cluster_node(2, h_d2, h_c2, data_group.clone(), coord_group.clone(), replication_factor, cancel.clone()),
    ];

    // Producer publishes the object once memberships have a chance to form.
    let producer = ndn_app::Publisher::from_handle(
        producer_handle,
        data_group.clone(),
        name("/cl/data/producer"),
        ndn_app::PublisherConfig { svs: fast_svs(), ..Default::default() },
    )
    .expect("publisher");
    tokio::time::sleep(Duration::from_millis(400)).await;
    producer.put(b"replicate-me").await.expect("put");

    // The object must end up durably held by at least `replication_factor`
    // distinct repos — replication achieved end-to-end over the forwarder,
    // driven by the cluster coordinator.
    let want = svs_data_name(&name("/cl/data/producer"), &data_group, 1);
    let holders = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let n = repos.iter().filter(|r| r.get(&want).is_some()).count();
            if n >= replication_factor {
                break n;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("cluster did not reach the replication factor over the forwarder");
    assert!(holders >= replication_factor);

    cancel.cancel();
    drop(producer);
    drop(engine);
    shutdown.shutdown().await;
}

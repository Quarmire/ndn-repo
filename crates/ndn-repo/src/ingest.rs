//! SVS group ingestion driver. The repo joins a group by building an
//! [`SvSync`] over [`Repo::store`](crate::Repo::store) and
//! running [`ingest_group`]: every new publication is fetched and its raw
//! wire stored, so the same store both **ingests** (here) and **serves** (the
//! SvSync demux answers Interests from it). This is ndnd's repo model — a
//! group member that durably holds and re-serves everything published.
//!
//! The embedder owns the transport (the `net_out`/`net_in` channels bridged to
//! a forwarder face); this module is the protocol glue above it.

use std::sync::Arc;

use ndn_packet::Name;
use ndn_sync::{SvSync, SyncUpdate, svs_data_name};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Durably ingest an SVS group: for each [`SyncUpdate`], fetch every new
/// publication (`low_seq..=high_seq`) and store its raw Data wire via
/// [`SvSync::ingest_publication`]. Runs until `updates` closes or `cancel`
/// fires.
///
/// Build `svsync` with the repo's store
/// ([`SvSync::join`](ndn_sync::SvSync::join) given `repo.store()`); the same
/// store then serves what is ingested.
///
/// `two_phase` selects the commit discipline:
/// * `false` (**eager**, the default / ndnd-compatible): the group's `SvSync`
///   runs `auto_ack: true`, so merging a peer vector advances the state vector
///   immediately. Fetches that fail are retried on the next update, but the
///   vector has already moved — a permanently-rejected publication leaves a hole
///   the node advertises as held (the eager model ndnd uses).
/// * `true` (**reject-without-poison**, D-44 / NDF F5): the group's `SvSync`
///   runs `auto_ack: false`, so a merge only *detects* gaps — the vector
///   advances solely through [`ack`](ndn_sync::SyncHandle::ack). This loop acks
///   **only** publications that actually stored (fetched AND passed the
///   [`IngestValidator`](ndn_sync::IngestValidator)), and **stops at the first hole**, so a rejected/failed
///   item never advances the vector past itself: its gap stays open and
///   re-derives, and convergence is never poisoned by an item the node does not
///   truly hold. `group` is needed to form the canonical data name for the
///   stored-check; it is ignored in eager mode.
pub async fn ingest_group(
    svsync: Arc<SvSync>,
    group: Name,
    mut updates: mpsc::Receiver<SyncUpdate>,
    two_phase: bool,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            maybe = updates.recv() => {
                let Some(update) = maybe else { break };
                for seq in update.low_seq..=update.high_seq {
                    let stored = svsync.ingest_publication(&update.name, seq).await;
                    if two_phase {
                        // Advance the vector ONLY for a publication that landed
                        // (a store-presence check, since `ingest_publication`
                        // returns 0 both for a failed fetch AND an already-stored
                        // one — a re-emitted gap must still ack the parts it holds).
                        // Break at the first hole so a rejected/unfetched item is
                        // never acked over — its gap stays open (reject-without-poison).
                        let present = svsync
                            .store()
                            .find_under(&svs_data_name(&update.name, &group, seq))
                            .is_some();
                        if present {
                            let _ = svsync.sync_handle().ack(&update.publisher, seq).await;
                        } else {
                            break;
                        }
                    } else if stored == 0 {
                        tracing::debug!(
                            target: "ndn_repo.ingest",
                            publisher = %update.publisher, seq,
                            "publication fetch returned nothing (will retry on next update)"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::Name;
    use ndn_sync::{DataStore, MemoryStore, SvSync, SvSyncConfig, SvsConfig, svs_data_name};
    use std::time::Duration;

    use crate::Repo;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// End-to-end: a producer publishes into a group; the repo (a group member
    /// over its own store) ingests the publication and then **serves** it by
    /// name — even though the test never asks the producer again.
    #[tokio::test]
    async fn repo_ingests_group_and_serves() {
        let group = n("/lib/papers");
        let producer = n("/lib/papers/alice");
        let repo_node = n("/lib/papers/repo");

        let (a_out, mut a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in, a_in_rx) = mpsc::channel::<Bytes>(256);
        let (r_out, mut r_out_rx) = mpsc::channel::<Bytes>(256);
        let (r_in, r_in_rx) = mpsc::channel::<Bytes>(256);

        // Bridge producer <-> repo.
        let a_in_c = a_in.clone();
        tokio::spawn(async move {
            while let Some(p) = r_out_rx.recv().await {
                let _ = a_in_c.send(p).await;
            }
        });
        let r_in_c = r_in.clone();
        tokio::spawn(async move {
            while let Some(p) = a_out_rx.recv().await {
                let _ = r_in_c.send(p).await;
            }
        });

        let cfg = SvSyncConfig {
            svs: SvsConfig {
                sync_interval: Duration::from_millis(50),
                jitter_ms: 0,
                ..Default::default()
            },
            fetch_timeout: Duration::from_secs(2),
            ..Default::default()
        };

        // Producer.
        let producer_store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs_a = SvSync::join(
            group.clone(),
            producer.clone(),
            producer_store,
            a_out,
            a_in_rx,
            cfg.clone(),
        );

        // Repo: an SvSync over the repo's store + the ingestion driver.
        let repo = Repo::new(Arc::new(MemoryStore::new()));
        let mut svs_r = SvSync::join(group.clone(), repo_node, repo.store(), r_out, r_in_rx, cfg);
        let updates = svs_r.take_updates();
        let svs_r = Arc::new(svs_r);
        let cancel = CancellationToken::new();
        tokio::spawn(ingest_group(
            Arc::clone(&svs_r),
            group.clone(),
            updates,
            false,
            cancel.clone(),
        ));

        // Producer publishes.
        svs_a.publish_data(b"a-paper").await.expect("publish");

        // The repo eventually serves the publication from its own store.
        let want = svs_data_name(&producer, &group, 1);
        let served = tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if let Some(wire) = repo.get(&want) {
                    break wire;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("repo never served the ingested publication");

        let data = ndn_packet::Data::decode(served).unwrap();
        assert_eq!(data.content().unwrap().as_ref(), b"a-paper");
        cancel.cancel();
    }

    /// Two-phase ingest is **reject-without-poison** (D-44 / F5): a publication that fails the
    /// ingest gate is neither stored NOR acked, so the vector never advances past it — the gap
    /// stays open (re-derivable), instead of the eager model advancing over a hole the repo does
    /// not truly hold. A producer publishes seq 1 (valid) then seq 2 ("POISON", rejected); the
    /// two-phase repo ends holding+advertising exactly seq 1.
    #[tokio::test]
    async fn two_phase_ingest_is_reject_without_poison() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use ndn_sync::WireDialect;

        let group = n("/lib/papers");
        let producer = n("/lib/papers/alice");
        let repo_node = n("/lib/papers/repo");

        let (a_out, mut a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in, a_in_rx) = mpsc::channel::<Bytes>(256);
        let (r_out, mut r_out_rx) = mpsc::channel::<Bytes>(256);
        let (r_in, r_in_rx) = mpsc::channel::<Bytes>(256);

        // Bridge repo -> producer, teeing off the producer's seq the repo ADVERTISES (its vector).
        let advertised = Arc::new(AtomicU64::new(u64::MAX)); // sentinel: not yet advertised
        {
            let a_in_c = a_in.clone();
            let advertised = Arc::clone(&advertised);
            let producer = producer.clone();
            tokio::spawn(async move {
                while let Some(p) = r_out_rx.recv().await {
                    if let Ok(interest) = ndn_packet::Interest::decode(p.clone())
                        && let Some(ap) = interest.app_parameters()
                        && let Some(sv) =
                            WireDialect::V2.decode_state_vector(&Bytes::copy_from_slice(ap))
                        && let Some(entry) = sv.iter().find(|e| e.name == producer)
                    {
                        advertised.store(entry.seq, Ordering::Relaxed);
                    }
                    let _ = a_in_c.send(p).await;
                }
            });
        }
        let r_in_c = r_in.clone();
        tokio::spawn(async move {
            while let Some(p) = a_out_rx.recv().await {
                let _ = r_in_c.send(p).await;
            }
        });

        let cfg = SvSyncConfig {
            svs: SvsConfig {
                sync_interval: Duration::from_millis(50),
                jitter_ms: 0,
                ..Default::default()
            },
            fetch_timeout: Duration::from_secs(2),
            ..Default::default()
        };

        let producer_store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs_a = SvSync::join(
            group.clone(),
            producer.clone(),
            producer_store,
            a_out,
            a_in_rx,
            cfg.clone(),
        );

        // Two-phase repo: auto_ack off + a gate that rejects the poison content.
        let repo = Repo::new(Arc::new(MemoryStore::new()));
        let mut repo_cfg = cfg.clone();
        repo_cfg.svs.auto_ack = false;
        repo_cfg.serve_all_stored = true;
        let mut svs_r = SvSync::join(
            group.clone(),
            repo_node,
            repo.store(),
            r_out,
            r_in_rx,
            repo_cfg,
        );
        svs_r.set_ingest_validator(Arc::new(|wire: Bytes| {
            Box::pin(async move {
                match ndn_packet::Data::decode(wire) {
                    Ok(d) => d
                        .content()
                        .map(|c| c.as_ref() != b"POISON")
                        .unwrap_or(false),
                    Err(_) => false,
                }
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        }));
        let updates = svs_r.take_updates();
        let svs_r = Arc::new(svs_r);
        let cancel = CancellationToken::new();
        tokio::spawn(ingest_group(
            Arc::clone(&svs_r),
            group.clone(),
            updates,
            true,
            cancel.clone(),
        ));

        // Producer publishes a valid Block, then a poison one.
        svs_a.publish_data(b"good-1").await.expect("publish 1");
        svs_a.publish_data(b"POISON").await.expect("publish 2");

        // The valid Block is stored+served.
        let want1 = svs_data_name(&producer, &group, 1);
        tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if repo.get(&want1).is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("repo never stored the valid Block");

        // Let several more sync rounds pass — an eager (or broken two-phase) repo would advance
        // its vector to seq 2 here; a correct two-phase repo holds at 1.
        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(
            repo.get(&svs_data_name(&producer, &group, 2)).is_none(),
            "the rejected (poison) Block must not be stored (resource protection)"
        );
        assert_eq!(
            advertised.load(Ordering::Relaxed),
            1,
            "reject-without-poison: the vector holds at the last VALID seq (1), never advancing \
             past the rejected seq 2 — the gap stays open, convergence is not poisoned"
        );
        cancel.cancel();
    }
}

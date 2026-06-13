//! SVS group ingestion driver. The repo joins a group by building an
//! [`SvSync`](ndn_sync::SvSync) over [`Repo::store`](crate::Repo::store) and
//! running [`ingest_group`]: every new publication is fetched and its raw
//! wire stored, so the same store both **ingests** (here) and **serves** (the
//! SvSync demux answers Interests from it). This is ndnd's repo model — a
//! group member that durably holds and re-serves everything published.
//!
//! The embedder owns the transport (the `net_out`/`net_in` channels bridged to
//! a forwarder face); this module is the protocol glue above it.

use std::sync::Arc;

use ndn_sync::{SvSync, SyncUpdate};
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
pub async fn ingest_group(
    svsync: Arc<SvSync>,
    mut updates: mpsc::Receiver<SyncUpdate>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            maybe = updates.recv() => {
                let Some(update) = maybe else { break };
                for seq in update.low_seq..=update.high_seq {
                    let stored = svsync.ingest_publication(&update.name, seq).await;
                    if stored == 0 {
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
            svs: SvsConfig { sync_interval: Duration::from_millis(50), jitter_ms: 0, ..Default::default() },
            fetch_timeout: Duration::from_secs(2),
            ..Default::default()
        };

        // Producer.
        let producer_store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs_a = SvSync::join(group.clone(), producer.clone(), producer_store, a_out, a_in_rx, cfg.clone());

        // Repo: an SvSync over the repo's store + the ingestion driver.
        let repo = Repo::new(Arc::new(MemoryStore::new()));
        let mut svs_r = SvSync::join(group.clone(), repo_node, repo.store(), r_out, r_in_rx, cfg);
        let updates = svs_r.take_updates();
        let svs_r = Arc::new(svs_r);
        let cancel = CancellationToken::new();
        tokio::spawn(ingest_group(Arc::clone(&svs_r), updates, cancel.clone()));

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
}

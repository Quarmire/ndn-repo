//! `ndn-repo` — runnable persistent named-data repository daemon.
//!
//! Connects to a forwarder over its Unix-socket face, serves the repo command
//! prefix (ndnd-compatible `RepoCmd`), durably ingests joined SVS groups into
//! an on-disk store, and re-serves everything by name.
//!
//! Usage:
//!   ndn-repo [--socket <path>] [--prefix <name>] [--store <dir>] [--group <name>]...
//!
//! Defaults: socket `/run/nfd/nfd.sock`, prefix `/repo`, store `./repo-data`.
//! Each `--group` is joined at startup; further groups join via `SyncJoin`.

use std::sync::Arc;

use ndn_app::connection::{Connection, IpcConnection};
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
use ndn_repo::{FjallStore, Repo, RepoService, RepoServiceConfig};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = parse_args()?;

    // Durable store + repo engine.
    let store = Arc::new(
        FjallStore::open(&cfg.store_dir)
            .map_err(|e| anyhow::anyhow!("open store at {}: {e}", cfg.store_dir))?,
    );
    let repo = Repo::new(store);

    // Connect to the forwarder. Light up the SHM data plane if the router
    // offers one (no-op fallback to the Unix socket otherwise).
    ndn_ipc_shm::install();
    let client = ForwarderClient::connect(&cfg.socket)
        .await
        .map_err(|e| anyhow::anyhow!("connect {}: {e}", cfg.socket))?;
    let conn = Arc::new(IpcConnection::new(client));

    // Channels between the forwarder connection and the service.
    let (out_tx, mut out_rx) = mpsc::channel::<bytes::Bytes>(256);
    let (in_tx, in_rx) = mpsc::channel::<bytes::Bytes>(256);
    // Prefixes the service wants routed to it → register with the forwarder.
    let (reg_tx, mut reg_rx) = mpsc::channel::<Name>(64);

    // service.out → forwarder.
    let conn_s = Arc::clone(&conn);
    tokio::spawn(async move {
        while let Some(p) = out_rx.recv().await {
            let _ = conn_s.send(p).await;
        }
    });
    // forwarder → service.in.
    let conn_r = Arc::clone(&conn);
    tokio::spawn(async move {
        while let Some(p) = conn_r.recv().await {
            if in_tx.send(p).await.is_err() {
                break;
            }
        }
    });
    // Register prefixes the service asks for (command prefix + each group).
    let conn_reg = Arc::clone(&conn);
    tokio::spawn(async move {
        while let Some(prefix) = reg_rx.recv().await {
            match conn_reg.register_prefix(&prefix).await {
                Ok(()) => tracing::info!(%prefix, "registered prefix"),
                Err(e) => tracing::warn!(%prefix, "register failed: {e}"),
            }
        }
    });

    let svc_cfg = RepoServiceConfig {
        initial_groups: cfg.groups.clone(),
        ..Default::default()
    };
    let service =
        RepoService::new(repo, cfg.prefix.clone(), out_tx, svc_cfg).with_registration(reg_tx);

    tracing::info!(
        prefix = %cfg.prefix, store = %cfg.store_dir, groups = ?cfg.groups,
        "ndn-repo started"
    );
    service.run(in_rx).await;
    tracing::info!("ndn-repo stopped");
    Ok(())
}

struct Args {
    socket: String,
    prefix: Name,
    store_dir: String,
    groups: Vec<Name>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut socket = "/run/nfd/nfd.sock".to_string();
    let mut prefix = "/repo".to_string();
    let mut store_dir = "./repo-data".to_string();
    let mut groups = Vec::new();

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" => socket = it.next().ok_or_else(|| anyhow::anyhow!("--socket needs a value"))?,
            "--prefix" => prefix = it.next().ok_or_else(|| anyhow::anyhow!("--prefix needs a value"))?,
            "--store" => store_dir = it.next().ok_or_else(|| anyhow::anyhow!("--store needs a value"))?,
            "--group" => {
                let g = it.next().ok_or_else(|| anyhow::anyhow!("--group needs a value"))?;
                groups.push(g.parse().map_err(|_| anyhow::anyhow!("bad group name: {g}"))?);
            }
            "-h" | "--help" => {
                eprintln!(
                    "ndn-repo [--socket <path>] [--prefix <name>] [--store <dir>] [--group <name>]..."
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        socket,
        prefix: prefix.parse().map_err(|_| anyhow::anyhow!("bad prefix: {prefix}"))?,
        store_dir,
        groups,
    })
}

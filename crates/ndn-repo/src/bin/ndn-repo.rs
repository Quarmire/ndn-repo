//! `ndn-repo` — runnable persistent named-data repository daemon.
//!
//! Connects to a forwarder over its Unix-socket face, serves the repo command
//! prefix (ndnd-compatible `RepoCmd`), durably ingests joined SVS groups into
//! an on-disk store, and re-serves everything by name.
//!
//! Usage:
//!   ndn-repo [--socket <path>] [--prefix <name>] [--store <dir>] [--group <name>]...
//!
//! Defaults: socket [`ndn_app::DEFAULT_FACE_SOCKET`] (where the forwarder
//! takes app faces unless configured otherwise), prefix `/repo`, store
//! `./repo-data`.
//! Each `--group` is joined at startup; further groups join via `SyncJoin`.
//!
//! Holder mode:
//!   ndn-repo hold --device <D> --pib <dir> --socket <fwd.sock> --store <dir>
//!                 --hold-for <ns>... [--in-namespace] [--erasure <k>/<n>]
//!                 [--sync-interval-ms <N>]
//!
//! Runs device `<D>`'s data layer (`ndn_data::Device`) as a custody holder
//! for each `--hold-for` namespace (at least one is required), signing with
//! `<D>`'s key from the PIB and keeping its packets in a
//! [`HolderStore`](ndn_repo::held::HolderStore) at `<store>` (held data
//! erasure-coded `k/n`, default 2/3). Prints one line
//! `{"ready":{"device":"<D>","writer":"<key>"}}` on stdout once the layer
//! runs, logs on stderr, and stops on SIGTERM, SIGINT or end of stdin.
//!
//! A holder that must not read what it keeps is enrolled outside the
//! namespaces it holds for: a device in the namespace it holds for is a
//! device of that person — of every audience `Person(<ns>)` admits, and able
//! to sign the owner's records. Holding for the device's own namespace is
//! therefore refused unless `--in-namespace` accepts exactly that.

use std::sync::Arc;

use ndn_app::connection::{Connection, IpcConnection};
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
use ndn_repo::{FjallStore, Repo, RepoService, RepoServiceConfig};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_some_and(|a| a == "hold") {
        args.next();
        return hold::run(args).await;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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
    let mut socket = ndn_app::DEFAULT_FACE_SOCKET.to_string();
    let mut prefix = "/repo".to_string();
    let mut store_dir = "./repo-data".to_string();
    let mut groups = Vec::new();

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--socket" => {
                socket = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--socket needs a value"))?
            }
            "--prefix" => {
                prefix = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--prefix needs a value"))?
            }
            "--store" => {
                store_dir = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--store needs a value"))?
            }
            "--group" => {
                let g = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--group needs a value"))?;
                groups.push(
                    g.parse()
                        .map_err(|_| anyhow::anyhow!("bad group name: {g}"))?,
                );
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
        prefix: prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("bad prefix: {prefix}"))?,
        store_dir,
        groups,
    })
}

/// `ndn-repo hold`: an `ndn_data::Device` custody holder over a
/// [`HolderStore`]. Startup mirrors ndn-fwd's `ndn-data` tool.
mod hold {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, anyhow, bail};
    use ndn_app::{IpcConnection, Node, demux_cert_fetcher};
    use ndn_data::{Config, Device, NextStep, Transport};
    use ndn_ipc::ForwarderClient;
    use ndn_packet::Name;
    use ndn_repo::held::{Erasure, HolderStore};
    use ndn_security::{CertCache, FilePib, SecurityManager, Validator};
    use tokio::signal::unix::{SignalKind, signal};

    /// Longest certificate chain the validator walks (device → CA → root).
    const MAX_CHAIN: usize = 5;

    const USAGE: &str = "ndn-repo hold --device <D> --pib <dir> --socket <fwd.sock> --store <dir> \
                         --hold-for <ns>... [--in-namespace] [--erasure <k>/<n>] \
                         [--sync-interval-ms <N>]";

    struct Args {
        device: Name,
        pib: String,
        socket: String,
        store: PathBuf,
        hold_for: Vec<Name>,
        /// The operator accepts holding for the device's own namespace.
        in_namespace: bool,
        erasure: Erasure,
        sync_interval: Option<Duration>,
    }

    fn parse(mut it: impl Iterator<Item = String>) -> anyhow::Result<Args> {
        let (mut device, mut pib, mut store) = (None, None, None);
        let mut socket = ndn_app::DEFAULT_FACE_SOCKET.to_string();
        let mut hold_for = Vec::new();
        let mut in_namespace = false;
        let mut erasure = Erasure::default();
        let mut sync_interval = None;
        while let Some(arg) = it.next() {
            let mut value = || {
                it.next()
                    .ok_or_else(|| anyhow!("{arg} needs a value; usage: {USAGE}"))
            };
            match arg.as_str() {
                "--device" => {
                    let v = value()?;
                    device = Some(
                        v.parse::<Name>()
                            .map_err(|e| anyhow!("--device {v:?}: {e}"))?,
                    );
                }
                "--pib" => pib = Some(value()?),
                "--socket" => socket = value()?,
                "--store" => store = Some(PathBuf::from(value()?)),
                "--hold-for" => {
                    let v = value()?;
                    hold_for.push(
                        v.parse::<Name>()
                            .map_err(|e| anyhow!("--hold-for {v:?}: {e}"))?,
                    );
                }
                "--in-namespace" => in_namespace = true,
                "--erasure" => {
                    let v = value()?;
                    erasure = v.parse().map_err(|e| anyhow!("--erasure: {e}"))?;
                }
                "--sync-interval-ms" => {
                    let v = value()?;
                    let ms: u64 = v.parse().map_err(|_| {
                        anyhow!("--sync-interval-ms {v:?}: give a whole number of milliseconds")
                    })?;
                    sync_interval = Some(Duration::from_millis(ms));
                }
                "-h" | "--help" => {
                    eprintln!("{USAGE}");
                    std::process::exit(0);
                }
                other => bail!("unknown argument {other:?}; usage: {USAGE}"),
            }
        }
        let missing = |flag: &str| anyhow!("{flag} is required; usage: {USAGE}");
        if hold_for.is_empty() {
            bail!(
                "--hold-for is required: without it the holder would hold for its own \
                 namespace, of whose audience it is, and read what it keeps; name the \
                 namespaces to hold for (`--hold-for <ns>`, repeatable); usage: {USAGE}"
            );
        }
        Ok(Args {
            device: device.ok_or_else(|| missing("--device"))?,
            pib: pib.ok_or_else(|| missing("--pib"))?,
            socket,
            store: store.ok_or_else(|| missing("--store"))?,
            hold_for,
            in_namespace,
            erasure,
            sync_interval,
        })
    }

    /// Refuse to hold for `own`, the device's own namespace, unless the
    /// operator accepted it (`--in-namespace`): a holder in the namespace it
    /// holds for is a device of that person, so it reads what it keeps and
    /// can sign the owner's records.
    fn refuse_own_namespace(
        own: &Name,
        hold_for: &[Name],
        in_namespace: bool,
    ) -> anyhow::Result<()> {
        if in_namespace || own.is_empty() || !hold_for.contains(own) {
            return Ok(());
        }
        bail!(
            "--hold-for {own}: {own} is this device's own namespace, so holding for it makes \
             the device of every audience `Person({own})` admits (it reads what it keeps) and \
             able to sign {own}'s owner records; enroll the holder in a namespace of its own \
             and pass `--hold-for {own}`, or pass `--in-namespace` to accept it"
        )
    }

    pub async fn run(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();
        let cli = parse(args)?;
        let device = cli.device;

        let pib = FilePib::open(&cli.pib).map_err(|e| anyhow!("open PIB {}: {e}", cli.pib))?;
        let keys = SecurityManager::from_pib(&pib, &device).map_err(|e| {
            anyhow!(
                "PIB {}: {e}; enroll this device as {device} first (`ndn-fwd enroll`)",
                cli.pib
            )
        })?;
        ndn_cert::load_persisted_contexts(pib.root(), keys.keyring())
            .map_err(|e| anyhow!("PIB {}: {e}", cli.pib))?;
        // The device's own namespace: that of the trust context governing
        // its name (none governs it: `Device::start` refuses and says why).
        let own = keys.keyring().context_for(&device).namespace().clone();
        refuse_own_namespace(&own, &cli.hold_for, cli.in_namespace)?;
        if cli.in_namespace && cli.hold_for.contains(&own) {
            tracing::warn!(
                %device, namespace = %own,
                "holding for the device's own namespace (--in-namespace): it reads what it keeps and can sign the owner's records"
            );
        }
        let keys = Arc::new(keys);

        let store = HolderStore::open(&cli.store, device.clone(), cli.erasure)
            .map_err(|e| anyhow!("store {}: {e}", cli.store.display()))?;

        let node = Node::connect(&cli.socket)
            .await
            .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.socket))?;
        let sync = ForwarderClient::connect(&cli.socket)
            .await
            .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.socket))?;
        let sync = Arc::new(IpcConnection::new(sync));

        let cache = Arc::new(CertCache::new());
        let fetcher = demux_cert_fetcher(node.demux(), Arc::clone(&cache));
        let validator = Arc::new(Validator::with_keyring(
            Arc::clone(keys.keyring()),
            cache,
            Some(fetcher),
            MAX_CHAIN,
        ));

        let mut config = Config::new();
        config.hold_for = cli.hold_for;
        if let Some(interval) = cli.sync_interval {
            config.svs.sync_interval = interval;
        }
        let hold_for = config.hold_for.clone();
        let layer = Device::start(
            Transport { node, sync },
            device.clone(),
            keys,
            validator,
            Arc::new(store),
            config,
        )
        .await
        .map_err(|e| anyhow!("{device}: {e} (next: {})", next_step(e.next())))?;
        tracing::info!(
            %device, store = %cli.store.display(), erasure = %cli.erasure, ?hold_for,
            "ndn-repo holding"
        );
        println!(
            "{}",
            serde_json::json!({"ready": {
                "device": device.to_string(),
                "writer": layer.writer().key().to_string(),
            }})
        );

        // Until SIGTERM, SIGINT or end of stdin. Stdin is read on a plain
        // thread: a blocking read there cannot hold up the runtime's shutdown.
        let mut term = signal(SignalKind::terminate()).context("install the SIGTERM handler")?;
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            let mut sink = std::io::sink();
            let _ = std::io::copy(&mut std::io::stdin().lock(), &mut sink);
            let _ = eof_tx.send(());
        });
        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM"),
            _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT"),
            _ = eof_rx => tracing::info!("end of stdin"),
        }
        layer.shutdown();
        tracing::info!(%device, "ndn-repo hold stopped");
        Ok(())
    }

    fn next_step(n: NextStep) -> &'static str {
        match n {
            NextStep::None => "nothing: the answer is final",
            NextStep::RetryLater => "ask again later, unchanged: no path or holder answered",
            NextStep::AskOwner => {
                "ask the collection's owner for membership, a reading key or re-admission"
            }
            NextStep::UseOwnerDevice => "do it on a device that holds the owner's key",
            NextStep::EditInstead => "remove it with an edit to the collection: it is not yours",
            NextStep::FixLocal => "fix this device: its storage or its keys",
            NextStep::FixName => "ask again with a well-formed name: the message says how",
            NextStep::HoldFirst => "ask holders to keep it first (hold), and audit them",
            NextStep::FixRequest => {
                "ask again as the error says: the request, as given, asks for something no \
                 device does (a prune past the log, too few holders)"
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(list: &[&str]) -> impl Iterator<Item = String> {
            list.iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .into_iter()
        }

        #[test]
        fn a_holder_names_the_namespaces_it_holds_for() {
            let base = ["--device", "/ph/member/repo", "--pib", "p", "--store", "s"];
            assert!(
                parse(args(&base)).is_err(),
                "without --hold-for a holder would hold for its own namespace, of whose \
                 audience it is: it would read the sealed data it keeps"
            );
            let mut named = base.to_vec();
            named.extend(["--hold-for", "/ph"]);
            let ph: Name = "/ph".parse().unwrap();
            assert_eq!(parse(args(&named)).unwrap().hold_for, vec![ph]);
        }

        #[test]
        fn holding_for_the_own_namespace_needs_consent() {
            let (ph, other): (Name, Name) = ("/ph".parse().unwrap(), "/kin".parse().unwrap());
            let refused = refuse_own_namespace(&ph, &[other.clone(), ph.clone()], false)
                .expect_err("a holder in /ph holding for /ph is of /ph's audience");
            assert!(refused.to_string().contains("--in-namespace"), "{refused}");
            assert!(refuse_own_namespace(&ph, std::slice::from_ref(&ph), true).is_ok());
            assert!(refuse_own_namespace(&ph, &[other], false).is_ok());
        }
    }
}

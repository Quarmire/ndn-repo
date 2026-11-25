//! `ndn-repo follow`: a carrier of heap spaces.
//!
//! ```text
//! ndn-repo follow --device <D> --pib <dir> --socket <fwd.sock> --store <dir>
//!                 --space <name>... [--sync-interval-ms <N>]
//! ```
//!
//! Runs device `<D>`'s heap layer ([`ndn_heap::Node`]) and carries each
//! `--space` (`<namespace>/32=data/<name>`, at least one is required): it
//! joins the space's sync group, **verifies** what the space's members wrote,
//! stores it in a plain fjall store at `<store>` and serves it by name, so a
//! device that was offline when the writer was reachable still gets it.
//!
//! A follower verifies what it stores. The operator must therefore hold
//! (adopt) the trust context of each space's owner in `<D>`'s PIB
//! (`ndn-fwd adopt`); with none, the owner's entries wait for it
//! (`Pending(adoption)`), nothing is stored, and the periodic report says so
//! with the step to take (`NextStep::AskOwner`). A follower publishes no
//! vector entry and holds no read key unless its person is a reader, so what
//! it carries of a sealed space stays closed to it.
//!
//! The relays the forwarder uses are told which spaces the follower follows:
//! for each carried space of an owner other than `<D>`'s namespace the follower
//! marks the space's sync group (`<owner>/32=sync/<space>`) on the forwarder
//! (`security/transit`, over one management connection kept open for the run),
//! and the forwarder's links tell the relays to route exactly that group here
//! (`ndn-link.md` §5.10), not the owner's other spaces. The forwarder refuses
//! a follower that is no operator and in none of its `[security]
//! transit_groups`; the log then says so and the space is carried all the same.
//!
//! Prints one line `{"ready":{"device":"<D>","writer":"<key>"}}` on stdout once
//! the layer runs and carries every space, logs on stderr (one line per space
//! with the entries held, every [`REPORT_EVERY`]), and stops on SIGTERM, SIGINT
//! or end of stdin, closing the node cleanly. A restart on the same `--store`
//! carries the same spaces again, `--space` or not.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use ndn_app::{IpcConnection, demux_cert_fetcher};
use ndn_heap::wire::{parse_space_name, sync_group_of};
use ndn_heap::{Config, Follower, NextStep, Node, Transport};
use ndn_ipc::{ForwarderClient, MgmtClient};
use ndn_packet::Name;
use ndn_security::{CertCache, FilePib, SecurityManager, Validator};
use ndn_sync::DataStore;
use ndn_sync::store::BackendStore;
use tokio::signal::unix::{SignalKind, signal};

/// Longest certificate chain the validator walks (device → CA → root).
const MAX_CHAIN: usize = 5;

/// How often the entries held per space are logged.
const REPORT_EVERY: Duration = Duration::from_secs(10);

const USAGE: &str = "ndn-repo follow --device <D> --pib <dir> --socket <fwd.sock> --store <dir> \
                     --space <name>... [--sync-interval-ms <N>]";

#[derive(Debug)]
pub struct Args {
    pub device: Name,
    pub pib: String,
    pub socket: String,
    pub store: PathBuf,
    pub spaces: Vec<Name>,
    pub sync_interval: Option<Duration>,
}

pub fn parse(mut it: impl Iterator<Item = String>) -> anyhow::Result<Args> {
    let (mut device, mut pib, mut store) = (None, None, None);
    let mut socket = ndn_app::DEFAULT_FACE_SOCKET.to_string();
    let mut spaces: Vec<Name> = Vec::new();
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
            "--space" => {
                let v = value()?;
                let space = v
                    .parse::<Name>()
                    .map_err(|e| anyhow!("--space {v:?}: {e}"))?;
                if parse_space_name(&space).is_none() {
                    bail!(
                        "--space {v}: a space is named <namespace>/32=data/<name> (one to four \
                         plain components after the keyword 32=data, e.g. /alice/32=data/notes)"
                    );
                }
                if !spaces.contains(&space) {
                    spaces.push(space);
                }
            }
            "--sync-interval-ms" => {
                let v = value()?;
                let ms: u64 = v.parse().map_err(|_| {
                    anyhow!("--sync-interval-ms {v:?}: give a whole number of milliseconds")
                })?;
                sync_interval = Some(Duration::from_millis(ms));
            }
            "-h" | "--help" => {
                eprintln!("{USAGE}\n\n{HELP}");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other:?}; usage: {USAGE}"),
        }
    }
    let missing = |flag: &str| anyhow!("{flag} is required; usage: {USAGE}");
    if spaces.is_empty() {
        bail!(
            "--space is required: a follower carries the spaces it is told to (`--space \
             <namespace>/32=data/<name>`, repeatable); usage: {USAGE}"
        );
    }
    Ok(Args {
        device: device.ok_or_else(|| missing("--device"))?,
        pib: pib.ok_or_else(|| missing("--pib"))?,
        socket,
        store: store.ok_or_else(|| missing("--store"))?,
        spaces,
        sync_interval,
    })
}

const HELP: &str = "A follower verifies what it stores: hold (adopt) the trust context of each \
space's owner in --pib (`ndn-fwd adopt`). With none, the owner's entries stay Pending(adoption) \
and nothing is stored; the report says so. A follower publishes no vector entry and holds no \
read key unless its person is a reader. A reader finds this follower only when its host lists it \
as a holder (this device's name <D>, e.g. `--holder <D>` for the `ndn-heap` tool; \
`ndn_heap::Config.holders`), because a follower publishes no vector entry.";

/// What to do about an error of the heap layer, in words.
pub fn next_step(n: NextStep) -> &'static str {
    match n {
        NextStep::None => "nothing: the answer is final",
        NextStep::RetryLater => "ask again later, unchanged: no path or holder answered",
        NextStep::AskOwner => {
            "ask the space's owner for membership, a reading key or re-admission, and hold the \
             owner's trust context on this device (`ndn-fwd adopt`)"
        }
        NextStep::UseOwnerDevice => "do it on a device that holds the owner's key",
        NextStep::FixLocal => "fix this device: its storage or its keys",
        NextStep::FixName => {
            "name the space <namespace>/32=data/<name>: the message says how a name is formed"
        }
        NextStep::FixRequest => {
            "ask again as the error says: the request, as given, asks for something no device \
             does"
        }
    }
}

/// What to tell about a space of which nothing is held: the likeliest cause
/// and the step to take. `None` once something is held.
fn hint(space: &Name, held: u64) -> Option<String> {
    if held > 0 {
        return None;
    }
    let owner = parse_space_name(space).map(|s| s.owner)?;
    Some(format!(
        "{space}: nothing stored. A follower stores only what it verifies, so it needs the \
         trust context of the space's owner {owner}; without it the owner's entries wait for \
         its adoption and none is stored (next: {}). Nothing is wrong if {owner} has written \
         nothing to the space yet",
        next_step(NextStep::AskOwner)
    ))
}

/// The sync groups of the spaces a follower carries that are another
/// owner's than `own`, this device's namespace: `<owner>/32=sync/<space>`
/// (`ndn_heap::wire::sync_group_of`), the group of each space and not the
/// owner's whole group, which every space of the owner lies under. A space of
/// the device's own namespace is no following: a relay routes the
/// namespace's group for the devices it serves.
fn followed_groups(own: &Name, spaces: &[Name]) -> Vec<Name> {
    spaces
        .iter()
        .filter_map(|space| {
            let parsed = parse_space_name(space)?;
            (parsed.owner != *own)
                .then(|| sync_group_of(space))
                .flatten()
        })
        .collect()
}

/// Tell the daemon the groups this follower follows, as marks
/// (`security/transit`) owned by a management connection that is returned and
/// must be kept open for the whole run: the daemon's links tell the relays
/// they use to route exactly these groups here (ndn-link.md §5.10), so a
/// space carried reaches this device through them; the daemon releases the
/// marks when the connection closes. A daemon that refuses (this host is no
/// operator or member of its `[security] transit_groups`; it runs no links)
/// is told in the log, with what to do: the space is carried all the same.
async fn tell_daemon(socket: &str, groups: &[Name]) -> Option<MgmtClient> {
    if groups.is_empty() {
        return None;
    }
    let client = match MgmtClient::connect(socket).await {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(
                "cannot tell the forwarder at {socket} which spaces this follower follows: {e}; \
                 the relays it uses route no space group here until it is started again"
            );
            return None;
        }
    };
    for group in groups {
        if let Err(e) = client.security_transit(group, true).await {
            let why =
                ndn_ipc::trust_refusal_in(&e).map_or_else(|| e.to_string(), |r| r.to_string());
            tracing::warn!(
                %group,
                "the forwarder did not take the group of a followed space: {why}; run this \
                 follower as a member of a group in the forwarder's `[security] transit_groups` \
                 (or as an operator) so the relays it uses route the space's group here"
            );
        }
    }
    Some(client)
}

/// The certificate cache of the follower's validator: the manager's own, which
/// `SecurityManager::from_pib` filled from the follower's PIB (every certificate stored for
/// its key, those of the PIB's other signing identities, and its trust anchors). A grant ask
/// carries the asker's chain, read from this cache alone (`Judge::chain_of`); a cache that
/// starts empty sends asks without one, and a granter that fetches nothing refuses them.
fn follower_cert_cache(keys: &SecurityManager) -> Arc<CertCache> {
    keys.cert_cache_arc()
}

/// The node of a follower and the spaces it carries.
pub struct Carrying {
    node: Node,
    followers: Vec<(Name, Follower)>,
}

/// Start the heap layer of `device` and follow each of `spaces`.
pub async fn carry(
    transport: Transport,
    device: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
    store: Arc<dyn DataStore>,
    config: Config,
    spaces: &[Name],
) -> anyhow::Result<Carrying> {
    let node = Node::start(transport, device.clone(), keys, validator, store, config)
        .await
        .map_err(|e| anyhow!("{device}: {e} (next: {})", next_step(e.next())))?;
    let mut followers = Vec::with_capacity(spaces.len());
    for space in spaces {
        let follower = node
            .follow(space)
            .await
            .map_err(|e| anyhow!("{space}: {e} (next: {})", next_step(e.next())))?;
        followers.push((space.clone(), follower));
    }
    Ok(Carrying { node, followers })
}

impl Carrying {
    /// The entries held of each carried space.
    pub fn held(&self) -> Vec<(Name, u64)> {
        self.followers
            .iter()
            .map(|(space, follower)| (space.clone(), follower.held()))
            .collect()
    }

    /// The key the node signs with.
    pub fn writer(&self) -> &Name {
        self.node.writer()
    }

    /// Log what is held of each space, and what to do where nothing is.
    fn report(&self) {
        for (space, held) in self.held() {
            match hint(&space, held) {
                Some(hint) => tracing::warn!("{hint}"),
                None => tracing::info!(%space, held, "carrying"),
            }
        }
    }

    /// Stop cleanly: flush the store and record the close.
    pub async fn stop(self) {
        self.node.close().await;
    }
}

pub async fn run(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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
    let keys = Arc::new(keys);
    let own = keys.keyring().context_for(&device).namespace().clone();

    let store: Arc<dyn DataStore> = Arc::new(
        BackendStore::open_fjall(&cli.store)
            .map_err(|e| anyhow!("store {}: {e}", cli.store.display()))?,
    );

    let node = ndn_app::Node::connect(&cli.socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.socket))?;
    let sync = ForwarderClient::connect(&cli.socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.socket))?;
    let sync = Arc::new(IpcConnection::new(sync));

    let cache = follower_cert_cache(&keys);
    let fetcher = demux_cert_fetcher(node.demux(), Arc::clone(&cache));
    let validator = Arc::new(Validator::with_keyring(
        Arc::clone(keys.keyring()),
        cache,
        Some(fetcher),
        MAX_CHAIN,
    ));

    let mut config = Config::new();
    if let Some(interval) = cli.sync_interval {
        config.svs.sync_interval = interval;
    }
    let carrying = carry(
        Transport { node, sync },
        device.clone(),
        keys,
        validator,
        store,
        config,
        &cli.spaces,
    )
    .await?;
    // Held to the end of the run: the daemon releases the marks with it.
    let _marks = tell_daemon(&cli.socket, &followed_groups(&own, &cli.spaces)).await;
    tracing::info!(
        %device, store = %cli.store.display(), spaces = ?cli.spaces,
        "ndn-repo following"
    );
    println!(
        "{}",
        serde_json::json!({"ready": {
            "device": device.to_string(),
            "writer": carrying.writer().to_string(),
        }})
    );

    // Until SIGTERM, SIGINT or end of stdin. Stdin is read on a plain thread: a
    // blocking read there cannot hold up the runtime's shutdown.
    let mut term = signal(SignalKind::terminate()).context("install the SIGTERM handler")?;
    let (eof_tx, mut eof_rx) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let mut sink = std::io::sink();
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut sink);
        let _ = eof_tx.send(());
    });
    let mut tick = tokio::time::interval(REPORT_EVERY);
    loop {
        tokio::select! {
            _ = term.recv() => { tracing::info!("SIGTERM"); break }
            _ = tokio::signal::ctrl_c() => { tracing::info!("SIGINT"); break }
            _ = &mut eof_rx => { tracing::info!("end of stdin"); break }
            _ = tick.tick() => carrying.report(),
        }
    }
    carrying.stop().await;
    tracing::info!(%device, "ndn-repo follow stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use ndn_app::EngineAppExt;
    use ndn_engine::EngineBuilder;
    use ndn_heap::{Config, NextStep, Node, PutOptions, Readers, Share, Transport};
    use ndn_packet::Name;
    use ndn_security::{Certificate, SecurityManager, SignedTrustContext, TrustSchema, Validator};
    use ndn_sync::{DataStore, MemoryStore};
    use tokio_util::sync::CancellationToken;

    use super::*;

    fn n(uri: &str) -> Name {
        uri.parse().expect("a valid name")
    }

    /// The follower's own certificate and its issuer's (a trust anchor of its
    /// PIB) are held by the validator's cache from the start: a follower whose
    /// person is a reader asks for epoch keys, the ask carries the asker's
    /// chain (`Judge::chain_of`, which reads only that cache), and a granter
    /// that fetches nothing refuses an ask without one.
    #[tokio::test]
    async fn the_validators_cache_holds_the_followers_certificate_chain_from_the_pib() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let pib = FilePib::new(dir.path()).expect("a PIB");
        let (root_key, device_key) = (n("/carol/KEY/root"), n("/carol/repo/KEY/d1"));
        let root_signer = pib.generate_ed25519(&root_key).expect("root key");
        let device_signer = pib.generate_ed25519(&device_key).expect("device key");

        let issuer = SecurityManager::new();
        issuer.register_signer(root_key.clone(), pib.get_signer(&root_key).expect("root"));
        let day_ms = 24 * 3600 * 1000;
        let anchor = issuer
            .issue_self_signed(
                &root_key,
                Bytes::copy_from_slice(&root_signer.public_key_bytes()),
                day_ms,
            )
            .expect("anchor");
        pib.add_trust_anchor(&root_key, &anchor)
            .expect("anchor stored");
        let cert = issuer
            .certify(
                &device_key,
                Bytes::copy_from_slice(&device_signer.public_key_bytes()),
                &root_key,
                day_ms,
            )
            .await
            .expect("device certificate");
        pib.store_issued_cert(
            &device_key,
            &cert.data_wire().expect("a signed certificate"),
        )
        .expect("device certificate stored");

        let keys = SecurityManager::from_pib(&pib, &n("/carol/repo")).expect("keys");
        let cache = follower_cert_cache(&keys);
        assert!(
            cache.get(&Arc::new(cert.name.as_ref().clone())).is_some(),
            "the cache holds no certificate of the follower's own key {device_key}: its grant \
             asks carry no chain"
        );
        assert!(
            cache.get(&Arc::new(root_key.clone())).is_some(),
            "the cache holds no certificate of the issuer {root_key} the PIB trusts: the chain \
             stops at the follower's"
        );
    }

    fn args(list: &[&str]) -> impl Iterator<Item = String> {
        list.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn a_follower_names_the_spaces_it_carries() {
        let base = ["--device", "/carol/repo", "--pib", "p", "--store", "s"];
        let refused = parse(args(&base)).expect_err("a follower with no space carries nothing");
        assert!(refused.to_string().contains("--space"), "{refused}");

        let mut named = base.to_vec();
        named.extend([
            "--space",
            "/alice/32=data/notes",
            "--space",
            "/bob/32=data/a/b",
        ]);
        let parsed = parse(args(&named)).unwrap();
        assert_eq!(
            parsed.spaces,
            vec![n("/alice/32=data/notes"), n("/bob/32=data/a/b")]
        );
        assert_eq!(parsed.device, n("/carol/repo"));
        assert_eq!(parsed.sync_interval, None);

        let mut tuned = named.clone();
        tuned.extend(["--sync-interval-ms", "250"]);
        assert_eq!(
            parse(args(&tuned)).unwrap().sync_interval,
            Some(Duration::from_millis(250))
        );
    }

    #[test]
    fn a_space_is_a_space_name_not_any_name() {
        let mut bad = ["--device", "/carol/repo", "--pib", "p", "--store", "s"].to_vec();
        bad.extend(["--space", "/alice/notes"]);
        let refused = parse(args(&bad)).expect_err("/alice/notes has no 32=data component");
        assert!(refused.to_string().contains("32=data"), "{refused}");
    }

    /// What a follower tells the daemon is the group of each space it carries
    /// of another owner (`<owner>/32=sync/<space>`): never the owner's whole
    /// group `<owner>/32=sync`, which the relays would route for every space
    /// of the owner, and none for a space of the device's own namespace.
    #[test]
    fn a_follower_follows_the_groups_of_the_spaces_of_other_owners_only() {
        let spaces = [
            n("/alice/32=data/notes"),
            n("/bob/32=data/a/b"),
            n("/carol/32=data/mine"),
        ];
        assert_eq!(
            followed_groups(&n("/carol"), &spaces),
            [n("/alice/32=sync/notes"), n("/bob/32=sync/a/b")]
        );
        assert!(followed_groups(&n("/carol"), &[]).is_empty());
    }

    #[test]
    fn every_next_step_says_something_different() {
        let all = [
            NextStep::None,
            NextStep::RetryLater,
            NextStep::AskOwner,
            NextStep::UseOwnerDevice,
            NextStep::FixLocal,
            NextStep::FixName,
            NextStep::FixRequest,
        ];
        let said: std::collections::BTreeSet<&str> = all.iter().map(|&n| next_step(n)).collect();
        assert_eq!(said.len(), all.len(), "{said:?}");
        assert!(said.iter().all(|s| !s.is_empty()));
        assert!(
            next_step(NextStep::AskOwner).contains("owner"),
            "{}",
            next_step(NextStep::AskOwner)
        );
    }

    #[test]
    fn a_space_that_holds_nothing_says_whose_trust_context_to_adopt() {
        let space = n("/alice/32=data/notes");
        let hint = hint(&space, 0).expect("nothing held is said");
        assert!(hint.contains("/alice"), "{hint}");
        assert!(hint.contains("trust context"), "{hint}");
        assert!(hint.contains(next_step(NextStep::AskOwner)), "{hint}");
        assert_eq!(super::hint(&space, 3), None);
    }

    /// A namespace's root: it certifies its devices' keys.
    struct Namespace {
        name: Name,
        root: SecurityManager,
        key: Name,
        anchor: Certificate,
    }

    impl Namespace {
        fn new(name: &str) -> Namespace {
            let name = n(name);
            let root = SecurityManager::new();
            let key = name.clone().append("KEY").append("root");
            root.generate_ed25519(key.clone()).unwrap();
            let public = root.get_signer_sync(&key).unwrap().public_key().unwrap();
            let anchor = root.issue_self_signed(&key, public, u64::MAX).unwrap();
            Namespace {
                name,
                root,
                key,
                anchor,
            }
        }

        /// A device of the namespace: its keys and the certificate of its key.
        async fn enroll(&self, device: &str) -> (Name, Arc<SecurityManager>, Certificate) {
            let device = n(device);
            let keys = Arc::new(SecurityManager::new());
            let key = keys
                .generate_ed25519(device.clone().append("KEY").append("1"))
                .unwrap();
            let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
            let cert = self
                .root
                .certify(&key, public, &self.key, 365 * 24 * 3600 * 1000)
                .await
                .unwrap();
            (device, keys, cert)
        }
    }

    /// A validator that holds the trust contexts of `held` and every certificate
    /// in `certs`: what a PIB with those contexts gives a device.
    fn validator(held: &[&Namespace], certs: &[Certificate]) -> Arc<Validator> {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for ns in held {
            let ctx = SignedTrustContext::hierarchical(ns.name.clone());
            assert!(ctx.add_anchor(ns.anchor.clone()));
            validator.adopt_context(Arc::new(ctx)).unwrap();
        }
        for cert in certs {
            validator.cert_cache().insert(cert.clone());
        }
        validator
    }

    fn fast() -> Config {
        let mut c = Config::new();
        c.settle = Duration::from_millis(50);
        c.svs.jitter_ms = 20;
        c.svs.suppression_period = Duration::from_millis(30);
        c.svs.sync_interval = Duration::from_secs(1);
        c
    }

    async fn eventually<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
        for _ in 0..300 {
            if f().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("not within 15 s: {what}");
    }

    /// Two carriers of Alice's space on one forwarder, both holding every
    /// certificate and Carol's trust context: one also holds Alice's trust
    /// context, one does not. Alice writes. The first stores what she wrote, the
    /// second stores nothing: it cannot verify it, and a follower stores only
    /// what it verifies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn follow_refuses_to_store_what_it_cannot_verify() {
        let (alice, carol) = (Namespace::new("/alice"), Namespace::new("/carol"));
        let (writer, writer_keys, writer_cert) = alice.enroll("/alice/laptop").await;
        let (adopted, adopted_keys, adopted_cert) = carol.enroll("/carol/adopted").await;
        let (blind, blind_keys, blind_cert) = carol.enroll("/carol/blind").await;
        let certs = [writer_cert, adopted_cert, blind_cert];

        let (engine, shutdown) = EngineBuilder::new(Default::default())
            .build()
            .await
            .expect("an engine");
        shutdown.detach();
        for ns in [&alice, &carol] {
            ndn_namespace::sync_group::carry(&engine, &ns.name);
        }
        let cancel = CancellationToken::new();
        let faces = || Transport {
            node: engine.app_node(cancel.child_token()),
            sync: engine.app_face(cancel.child_token()),
        };
        let memory = || -> Arc<dyn DataStore> { Arc::new(MemoryStore::new()) };

        let owner = Node::start(
            faces(),
            writer,
            writer_keys,
            validator(&[&alice], &certs),
            memory(),
            fast(),
        )
        .await
        .expect("the owner's node starts");

        let space = n("/alice/32=data/notes");
        let mut carrying = Vec::new();
        for (device, keys, held) in [
            (adopted, adopted_keys, vec![&alice, &carol]),
            (blind, blind_keys, vec![&carol]),
        ] {
            carrying.push(
                carry(
                    faces(),
                    device,
                    keys,
                    validator(&held, &certs),
                    memory(),
                    fast(),
                    std::slice::from_ref(&space),
                )
                .await
                .expect("the carrier starts"),
            );
        }
        let (adopted, blind) = (&carrying[0], &carrying[1]);

        let heap = owner
            .create(
                &space,
                Share {
                    readers: Readers::Anyone,
                    writers: vec![],
                },
            )
            .await
            .unwrap();
        heap.put(
            &n("/a"),
            Bytes::from_static(b"one"),
            PutOptions {
                durable: Some(true),
            },
        )
        .await
        .unwrap();

        eventually(
            "the carrier that holds Alice's context stores her entries",
            || async { adopted.held().iter().all(|(_, held)| *held >= 2) },
        )
        .await;
        // The other had the same chance: the same group, the same Interests, the
        // same certificates. Give it more time than the first needed.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            blind.held(),
            vec![(space.clone(), 0)],
            "a follower that holds no trust context of {} stored what it cannot verify",
            alice.name
        );
        assert!(
            hint(&space, 0).is_some(),
            "and the report says what to do about it"
        );
    }
}

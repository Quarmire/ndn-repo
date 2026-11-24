# ndn-repo

Persistent named-data repository daemon for the
[ndn-rs](https://github.com/Quarmire/ndn-rs) ecosystem — durable ingest + serve,
with a command protocol byte-compatible with **ndnd**'s `repo`.

Part of the [ndn-rs](https://github.com/Quarmire/ndn-rs) ecosystem. See [`ATTRIBUTION.md`](ATTRIBUTION.md).

## Running

Build with `--features bin`.

```
ndn-repo [--socket <path>] [--prefix <name>] [--store <dir>] [--group <name>]...
```

The ndnd-compatible repo: serves the `RepoCmd` prefix (default `/repo`),
ingests joined SVS groups into a FjallStore at `--store`, re-serves by name.

## Follower

```
ndn-repo follow --device <D> --pib <dir> --socket <fwd.sock> --store <dir>
                --space <name>... [--sync-interval-ms <N>]
```

Runs the heap layer (`ndn_heap::Node`) of the enrolled device `<D>` as a
**follower**, a carrier of each `--space` (`<namespace>/32=data/<name>`, at
least one): it joins the space's sync group, verifies and stores what the
space's members write in a plain fjall store at `--store`, and serves it by
name, so a reader that comes when the writers are away still gets it. It
signs with `<D>`'s key from the PIB at `--pib` (enroll it first,
`ndn-fwd enroll`). `--socket` is the forwarder's face socket;
`--sync-interval-ms` is State Vector Sync's periodic interval (performance
only).

**What the operator must hold.** A follower verifies what it stores, so the
operator must hold (adopt) the trust context of each space's **owner** in the
PIB (`ndn-fwd adopt <anchor-link> --pib <dir>`). With none, the owner's
entries stay `Pending(adoption)` and nothing is stored; the periodic report
says so, with the step to take (ask the owner; `NextStep::AskOwner`). A
follower publishes no vector entry, and holds no read key unless its person
is a reader of the space, so what it carries of a sealed space stays closed to
it. It is not a member: it cannot write to the space.

**How readers find it.** A follower publishes no vector entry, so no member
vouches for it: a reader finds this follower only when its host lists it as a
holder, by the repo's device name `<D>` (`--holder <D>` for the `ndn-heap`
tool, `ndn_heap::Config.holders`). It is then asked for held copies after the
members that vouch, and what it gives is verified as the writer's own.

On start it prints one line on stdout,
`{"ready":{"device":"<D>","writer":"<key name>"}}`; logs go to stderr, and
every 10 seconds one line per space with the entries held (a warning where it
is none). It runs until SIGTERM, SIGINT or end of stdin (keep stdin open when
it should keep running) and then closes cleanly. A restart on the same
`--store` carries the same spaces again.

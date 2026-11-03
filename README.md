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

## Holder mode

```
ndn-repo hold --device <D> --pib <dir> --socket <fwd.sock> --store <dir>
              [--hold-for <ns>]... [--erasure <k>/<n>] [--sync-interval-ms <N>]
```

Runs the data layer (`ndn_data::Device`) of the enrolled device `<D>` as a
**custody holder**: it answers hold asks and audits from the owners of each
`--hold-for` namespace (default: the device's own namespace), keeps what it
promised in its leases, and serves it to readers. It signs with `<D>`'s key
from the PIB at `--pib` (enroll it first, `ndn-fwd enroll`) and trusts what
that PIB's trust contexts say. `--socket` is the forwarder's face socket;
`--sync-interval-ms` is State Vector Sync's periodic interval (performance
only).

On start it prints one line on stdout,
`{"ready":{"device":"<D>","writer":"<key name>"}}`; logs go to stderr. It
runs until SIGTERM, SIGINT or end of stdin (keep stdin open when it should
keep running). A restart on the same `--store` picks up where it left off.

### Store layout

```
<store>/erasure      the k/n the held packets are coded with ("2/3")
<store>/own/         the device's own names (<D>/..., /localhost/...): a plain FjallStore
<store>/held/<i>/    stripe i of n (i in 0..n): one FjallStore per stripe
```

Everything the device keeps for others is **erasure-coded per packet**: each
packet's wire becomes `k` source shards and `n - k` parity shards (the
workspace's systematic Reed-Solomon codec, `ndn-coding`), shard `i` stored
under the packet's name in stripe `i` with the wire's length and digest and
its own digest. Any `k` stripes rebuild a packet; a read that finds a stripe
lacking a good shard rewrites it (repair), and so does the restart's restore
scan. `--erasure` defaults to `2/3`; a store is refused when opened with
parameters other than the ones in `<store>/erasure`, saying which to use.

### Losing a stripe

A stripe is one directory `<store>/held/<i>`; mount a disk there per stripe
to make "a stripe" mean "a disk".

* **Losing up to `n - k` stripes** (the directory deleted or emptied, the
  disk replaced by a blank one) loses nothing: the daemon rebuilds each
  packet from the remaining stripes and writes the missing shards back.
* **Losing more** makes the packets those stripes held missing: the store
  answers nothing for them, so an owner's audit finds them missing and the
  owner repairs custody elsewhere.
* `<store>/own` is not coded: losing it loses the device's own log.

To simulate, stop the daemon, then delete `<store>/held/1` (one disk lost:
still kept) or every `<store>/held/*` (the held data lost), and start it
again on the same `--store`.

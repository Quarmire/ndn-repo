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

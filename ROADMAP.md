# Cairn Roadmap

Cairn is focused on being a **reliable, encrypted, deduplicated backup filesystem** — boring and trustworthy on the
data path, with two things that set it apart from restic/borg/kopia:

1. **Asymmetric (public/private-key) envelope encryption** — back up with only a *public* key from any machine; that
   machine can never read what it backed up. Restore only from a machine holding the *private* key.
2. **Live FUSE mount** — mount an encrypted, deduplicated backup as a normal read/write filesystem, not just extract it.

---

## Near-term (backup core hardening)
- **Restore/read performance.** Asymmetric unwrap (age X25519) runs per chunk on read. Keep the session key-cache warm,
  parallelize chunk fetch+decrypt on `extract`, and benchmark a large restore end-to-end.
- ~~**Verify/repair.** Extend `scrub` into a real `verify` (per-chunk integrity + report) and a `repair` that re-fetches
  corrupt chunks from another storage backend.~~ (Completed)
- ~~**Symmetric mode (optional).** Offer a password-only (symmetric) mode for users who don't want key management, while
  keeping asymmetric as the recommended default. Store the mode with the archive.~~ (Completed)

## Storage: pseudo-RAID expansion
Today `--raid-mode` (raid0/raid1/raid5/raid6/raid10) spreads/mirrors/erasure-codes chunks across multiple S3/GCS operators. Expand this into a
proper multi-backend story:
- ~~**raid5/raid6-style erasure coding** (Reed-Solomon) across N backends so the archive survives losing a whole provider,
  at a fraction of full mirroring's cost.~~ (Completed)
- **Heterogeneous backends per tier** (e.g. local SSD cache + B2 cold + S3 warm) with a placement policy.
- **Health & rebalance**: detect a degraded/unreachable backend and re-replicate its chunks onto the survivors.
- ~~**Read repair on RAID**: on a chunk mismatch, transparently fetch from a healthy replica and automatically heal (re-upload) the bad chunk on the remote backend.~~ (Completed via `--auto-heal` flag)

## Observability: metrics
- **Prometheus `/metrics` endpoint** (opt-in): bytes written/read, dedup hit-ratio, compression ratio, chunk counts,
  per-backend upload/fetch latency & error rate, cache hit-ratio, write-buffer/flush pipeline depth, RSS.
- **Structured operation logs** (backup/restore/gc/scrub) with durations and outcomes.
- ~~**`cairn stats`** CLI: archive size, unique vs logical bytes, snapshot list, storage-backend health.~~ (Completed)

## GUI (`cairn-gui`) — Separate project / CLI Wrapper
A desktop/web front-end that acts as an orchestrator/wrapper around the `cairn` CLI (Unix-way). It is a standalone binary and practically a separate project that does **not** link to `cairn-core` directly.
- **Architecture**: The GUI executes the `cairn` CLI under the hood using the `--json` flags (e.g. `cairn status --json`, `cairn list-snapshots --json`) and renders the structured output. This keeps the daemon extremely lightweight, crash-isolated from the UI, and allows the GUI to be written in any stack.
- **Features**: Visual "Time Machine" (snapshot browser), one-click restore/extract, health/metrics dashboard with deduplication charts, and a setup wizard for S3 buckets / RAID / Crypto keys.
- **Tech options**: Tauri (Rust + React/Vite/Tailwind). Distributed as a separate binary (e.g. `cairn-desktop`).

## Engine architecture refinements
- ~~**fuse-independent core**: give `cairn-core` a small neutral API (plain `Result`/errors + data) instead of fuse3 types,
  so `cairn-fuse` and `cairn-gui` both sit on the same surface. This is the concrete reason the GUI is worth building.~~ (Completed)
- ~~**`ChunkStore` trait**: fold the chunk *upload* path (currently in `cairn-cdc`) and the *fetch* path (in `cairn-store`)
  behind one trait, so a new backend is one impl.~~ (Completed)

## Cross-platform Mounting (Windows / macOS)
- **Adapter approach**: Support filesystem mounting on non-Linux systems using the `fuser` crate (which binds to WinFSP on Windows and macFUSE on macOS).
- **Architecture**: Create `cairn-fuser-cross`, a synchronous adapter that wraps `cairn-core` calls in `block_on`. Windows users will select a mountpoint (e.g. `Z:\` or `X:\` via CLI argument) and rely on WinFSP. Linux users will continue to use the high-performance async `fuse3` adapter.

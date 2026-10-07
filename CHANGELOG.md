# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

CLI exit codes are now consistent: 0 success, 1 integrity check failed,
2 usage or I/O error. The library API and all proof formats are unchanged.

### Added

- Optional system metadata at `init`: `--system-name`, `--purpose`,
  `--provider`, `--retention` (library: `Logsiegel.init(..., metadata={...})`,
  read back via `Logsiegel.metadata`). Stored as free text in `metadata.json`
  and shown in a `## System` section of the dossier, marked as declared by
  the operator and not covered by the log's signatures. The retention period
  is not enforced. Logs without metadata and their dossiers are unchanged.

### Changed

- **Behaviour change:** `logsiegel export` exits with 1 when the integrity
  verification in the dossier is FAIL (was 0). The dossier is still written.
- **Behaviour change:** `logsiegel shred` exits with 1 when the log fails
  verification after shredding (was 0). The payload is still shredded.

### Fixed

- Expected operator errors print one line `error: …` on stderr and exit with 2
  instead of a Python traceback: `init` on an existing log, a missing log
  directory, `receipt` for an unknown entry or without a covering checkpoint,
  `shred` or `payload` on an already shredded entry, a missing or malformed
  receipt file, and a malformed `--pubkey` PEM file.
- `log` (and every other command except `init`) no longer creates a bare
  `log.jsonl` without keys and origin in a directory that holds no log; it
  exits with 2 and `error: no log at DIR (run 'logsiegel init' first)`.

## 0.1.2 — 2026-09-13

Packaging metadata (project URLs, classifiers), SECURITY.md, no code changes.

- `[project.urls]`: homepage, documentation, repository, browser verifier,
  changelog and issue tracker — the PyPI sidebar was empty before.
- Trove classifiers (development status, intended audience, supported Python
  versions, cryptography/logging topics) and `keywords`.
- `SECURITY.md`: how to report a vulnerability, and what to expect.
- README: maintainers.

## 0.1.1 — 2026-09-10

- Optional `saklam` extra: in-process PII masking of stored payloads via the
  Saklam engine — no HTTP hop, licence key required. Tests skip when the
  package or the licence is missing.

## 0.1.0 — 2026-09-06

First release on PyPI.

- Append-only log on the local filesystem, SHA-256 hash chaining, exclusive
  file lock and fsync before an append is acknowledged.
- Ed25519-signed Merkle checkpoints, RFC 6962 inclusion and consistency proofs.
- Single-entry receipts, verifiable offline against the log's public key alone.
- Crypto-shredding: deleting a per-entry key removes content and hash
  linkability while the log stays byte-identical and verifiable.
- Minimal AI-lifecycle event taxonomy, OpenTelemetry GenAI attribute naming,
  PII masking, auditor-readable dossier export, LiteLLM adapter.
- Independent browser verifier (plain JS + WebCrypto, single HTML file, runs
  offline) that agrees with the Python reference on every test vector.

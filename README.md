# Logsiegel

**Prove your AI didn't lie.**

[![ci](https://github.com/logsiegel/logsiegel/actions/workflows/ci.yml/badge.svg)](https://github.com/logsiegel/logsiegel/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/logsiegel.svg)](https://pypi.org/project/logsiegel/)
[![Python](https://img.shields.io/pypi/pyversions/logsiegel.svg)](https://pypi.org/project/logsiegel/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Website](https://logsiegel.com) ·
[Try the browser verifier](https://logsiegel.com/verifier/) (offline, drag & drop a receipt) ·
[PyPI](https://pypi.org/project/logsiegel/)

Tamper-evident, privacy-preserving event logs for AI systems.

When an AI system or agent acts — answers, decides, books, escalates — the
record of what happened usually lives in an ordinary database at the
operator: silently editable, verifiable by no one. Logsiegel records AI
lifecycle events (inference, model changes, human overrides, …) into an
append-only log with hash chaining and Ed25519-signed Merkle checkpoints —
the same battle-tested construction as Certificate Transparency (RFC 6962).
Observability tools show what happened; Logsiegel makes it *provable*:
offline, by any third party holding a checkpoint or a single-entry receipt,
without access to the operator's infrastructure. Deliberately **no
blockchain**: no consensus, no tokens, no GDPR conflict.

Where this matters: accountability for autonomous agents (what did the agent
do, when, on whose behalf?) and record-keeping duties such as the EU AI
Act's automatic logging and retention rules (Art. 12/19) — built for teams
that don't have a compliance-engineering department.

## Why

- **Logs in ordinary databases are silently editable.** When an AI decision
  is challenged, "our logs say X" proves nothing. Logsiegel makes any
  after-the-fact modification, reordering or truncation cryptographically
  detectable.
- **Single-entry receipts.** An affected person or auditor gets one entry
  plus an RFC 6962 inclusion proof and a signed checkpoint — verifiable
  offline with the log's public key alone, no access to the full log.
- **Privacy by design.** Only event metadata and salted payload hashes enter
  the log. Raw prompts/outputs are stored separately, encrypted per entry;
  a pluggable PII detector masks identifiers in stored payloads. Deleting
  the per-entry key (**crypto-shredding**) removes the content *and* the
  hash linkability, while the log stays byte-identical and verifiable —
  deletion rights and tamper-evidence stop being a contradiction.
- **Speaks the ecosystem's language.** Event attributes follow the
  OpenTelemetry GenAI semantic conventions; adapters hook into existing
  stacks (LiteLLM today, OTel collector and agent-framework adapters
  planned) instead of asking you to re-instrument.

## Quick start

```bash
pip install logsiegel            # from source: pip install -e ".[dev]"
pip install "logsiegel[saklam]"  # optional: in-process PII masking of stored payloads (Saklam licence key required)

logsiegel init ./mylog --origin "acme.example/support-bot"
logsiegel log ./mylog --event inference \
  --attr gen_ai.request.model=gpt-5 --attr gen_ai.usage.input_tokens=412 \
  --input "customer question …" --output "answer …" --store-payload
logsiegel checkpoint ./mylog
logsiegel verify ./mylog                    # PASS: chain + Merkle roots + signatures
logsiegel receipt ./mylog --seq 1 --out receipt.json
logsiegel verify-receipt receipt.json \
  --pubkey mylog/keys/signing_key.pub       # single entry, offline, no log access
logsiegel export ./mylog                    # auditor-readable dossier (markdown)
logsiegel shred ./mylog --seq 1             # GDPR erasure; verify still passes
```

Full walkthrough incl. receipts and tamper detection: `python examples/demo.py`
(PII masking: `python examples/pii_demo.py`)

## LiteLLM integration

```python
import litellm
from logsiegel.integrations.litellm_logger import LogsiegelLogger

litellm.callbacks = [LogsiegelLogger("/var/lib/logsiegel/prod", store_payload=True)]
```

Every completion becomes a signed-committable `inference` event; failures are
recorded as `anomaly`.

## Where Logsiegel runs

- **Withdraw witness at anycast.dev (network measurement).** Since
  September 2026 an anycast measurement lab uses Logsiegel as its evidence
  layer. When an anycast node withdraws its route, an appender writes every
  event (RIS Live BGP messages, RIPE Atlas measurements, host digs, the
  drain playbook) into a Logsiegel trail; checkpoints are additionally
  timestamped via RFC 3161 at DigiCert. The runs are published in full
  (log, checkpoints, tokens; the public key was published beforehand), so
  third parties can verify them without access to the operator. There is no
  AI in this use case: it shows that the trail format is not tied to AI
  semantics. Pinned to `logsiegel==0.1.2`.
  Trails: [anycast.dev/witness](https://anycast.dev/witness/) ·
  verification guide: [logsiegel-verify.txt](https://anycast.dev/.well-known/logsiegel-verify.txt) ·
  public key: [logsiegel-pubkey.txt](https://anycast.dev/.well-known/logsiegel-pubkey.txt)
- **PII masking of stored payloads (production PII engine).** The optional
  `logsiegel[saklam]` extra (since 0.1.1) masks personal data in stored
  payloads in-process via the [Saklam](https://saklam.com) engine, a
  commercial PII engine running in production. It requires a licence key;
  the engine is not open source. Without the extra, Logsiegel uses its
  built-in regex detector or any other pluggable detector.

## How verification works

1. Each entry embeds the SHA-256 of its predecessor (hash chain); appends
   are serialized under an exclusive file lock and fsynced before they are
   acknowledged.
2. `checkpoint` commits to an RFC-6962 Merkle root over the first *N*
   entries and signs `{origin, size, root, ts}` with Ed25519.
3. `verify` recomputes everything from the raw files: broken chains, edited
   entries, shrunken logs and forged checkpoints all fail loudly.
4. `receipt` / `verify-receipt` prove a single entry against a signed
   checkpoint via an inclusion proof; consistency proofs (append-only
   growth between two checkpoints, the check a witness performs) ship in
   `logsiegel.merkle`.

## Threat model, honestly

Logsiegel is tamper-*evident*, not tamper-*proof*. Precisely:

- **Against third parties and after-the-fact edits:** any modification,
  reordering or truncation of committed entries breaks verification against
  every previously distributed checkpoint or receipt.
- **Against the operator:** the operator holds the signing key and could
  rewrite and re-sign the entire log. That is detectable exactly when
  someone else holds an earlier checkpoint or receipt — so distribute them
  (to auditors, counterparties, or an independent witness co-signing
  checkpoints; witness support is on the roadmap). Verify against an
  out-of-band copy of the public key (`logsiegel verify --pubkey …`), not
  the copy stored next to the log.
- **Completeness is not a cryptographic property.** The log proves that
  recorded events are unaltered — never that everything was recorded.
  Closing that gap is an integration property: log at a choke point that
  actions must pass through.
- **Timestamps are the operator's claims** until checkpoints are
  co-signed by an external witness.

## Status

v0.1.2 on PyPI (packaging metadata only — see [CHANGELOG.md](CHANGELOG.md)).
v0.1.1 added the optional `saklam` extra: in-process PII masking
of stored payloads via the Saklam engine, no HTTP hop, licence key required.
v0.1.0: local filesystem, minimal AI-lifecycle event taxonomy
(pluggable per writer), RFC 6962 inclusion + consistency proofs,
single-entry receipts, crypto-shredding, PII masking, dossier export,
LiteLLM adapter, and an independent **browser verifier** (plain JS +
WebCrypto, single HTML file, runs offline; source in [`verifier/`](verifier/),
live at [logsiegel.com/verifier](https://logsiegel.com/verifier/)) that
agrees with the Python reference on every test vector. 57 tests.

Roadmap: agent-action taxonomy (tool calls, delegation, value flows, human
intervention) with OTel GenAI span semantics, mandate binding to verifiable
credentials / eID ecosystems, independent witness co-signing (C2SP-style
checkpoints), browser verification of whole trails and dossiers with
timeline and mandate status (today the browser verifier checks single
receipts), retention policy engine, TypeScript SDK, mapping to emerging
logging standards (EU AI Act Art. 12, prEN 18229-1, ISO/IEC 24970).

## Maintainers

Stefan Böck (architecture, cryptography, core) and Emmanuelle
St-Pierre-Wittwer (development, regulatory mapping).
Project site: [logsiegel.com](https://logsiegel.com) · contact:
logsiegel@stefan.boeck.name · security reports: [SECURITY.md](SECURITY.md)

## License

Apache-2.0

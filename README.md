# Logbuch

**Tamper-evident, privacy-preserving event logs for AI systems.**

Observability tools show what happened — Logbuch makes it *provable*. It records
AI lifecycle events (inference, model changes, human overrides, …) into an
append-only log with hash chaining and Ed25519-signed Merkle checkpoints — the
same battle-tested construction as Certificate Transparency (RFC 6962).
Deliberately **no blockchain**: no consensus, no tokens, no GDPR conflict.

Built with the record-keeping duties of the EU AI Act (Art. 12 automatic logging,
Art. 19 retention) in mind, for teams that don't have a compliance-engineering
department.

## Why

- **Logs in ordinary databases are silently editable.** When an AI decision is
  challenged, "our logs say X" proves nothing. Logbuch makes any after-the-fact
  modification, reordering or truncation cryptographically detectable — offline,
  by anyone holding a checkpoint.
- **Privacy by design.** Only event metadata and salted payload hashes enter the
  log. Raw prompts/outputs are stored separately, encrypted per entry. Deleting
  the per-entry key (**crypto-shredding**) removes the content *and* the hash
  linkability, while the log stays byte-identical and verifiable — deletion
  rights and tamper-evidence stop being a contradiction.
- **Speaks the ecosystem's language.** Event attributes follow the OpenTelemetry
  GenAI semantic conventions; adapters hook into existing stacks (LiteLLM today,
  OTel collector and LangChain planned) instead of asking you to re-instrument.

## Quick start

```bash
pip install -e .

logbuch init ./mylog --origin "acme.example/support-bot"
logbuch log ./mylog --event inference \
  --attr gen_ai.request.model=gpt-5 --attr gen_ai.usage.input_tokens=412 \
  --input "customer question …" --output "answer …" --store-payload
logbuch checkpoint ./mylog
logbuch verify ./mylog          # PASS: hash chain + Merkle roots + signatures
logbuch export ./mylog          # auditor-readable dossier (markdown)
logbuch shred ./mylog --seq 1   # GDPR erasure; verify still passes
```

Full walkthrough incl. tamper detection: `python examples/demo.py`

## LiteLLM integration

```python
import litellm
from logbuch.integrations.litellm_logger import LogbuchLogger

litellm.callbacks = [LogbuchLogger("/var/lib/logbuch/prod", store_payload=True)]
```

Every completion becomes a signed-committable `inference` event; failures are
recorded as `anomaly`.

## How verification works

1. Each entry embeds the SHA-256 of its predecessor (hash chain).
2. `checkpoint` commits to an RFC-6962 Merkle root over the first *N* entries
   and signs `{origin, size, root, ts}` with Ed25519.
3. `verify` recomputes everything from the raw files: broken chains, edited
   entries, shrunken logs and forged checkpoints all fail loudly. No server,
   no trusted third party required.

## Status

Proof of concept (v0.1): single writer, local filesystem, minimal Art.-12
event taxonomy. Roadmap: full event schema mapped to OTel GenAI + emerging
logging standards (prEN 18229-1, ISO/IEC 24970), retention policy engine,
Annex-IV-oriented dossier export, TypeScript SDK, more adapters, witness
co-signing.

## License

Apache-2.0

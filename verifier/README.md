# Browser verifier

A second, independent implementation of the Logsiegel receipt format —
plain JavaScript + WebCrypto, no WASM, no dependencies. The goal is a single
static HTML file that verifies a receipt offline (`file://`): drag in
`receipt.json` and the log's public key, get a green/red verdict. If the
Python reference and this implementation agree on every test vector, the
receipt format is specified by the format, not by one codebase.

Verification stages (each runs only if the previous one passed):

1. **structure** — shape, types, hex fields, origin/seq consistency
2. **signature** — Ed25519 over the canonical checkpoint body
3. **inclusion** — RFC 6962 audit path against the committed root

Status: M1 (canonical JSON + structure stage + leaf hashing) — done.
M2 inclusion, M3 signature + UI, M4 full fixture matrix.

## Test vectors

`fixtures/` is generated from the Python reference:

```bash
python scripts/export_fixtures.py   # from the repo root
```

Every case carries the Python verdict (`python_report`) and the stage the JS
implementation must fail at (`expect_stage`) — deliberately stricter at the
structure stage where Python folds malformed input into later verdicts.

## Run tests

```bash
node --test verifier/test/*.test.mjs
```

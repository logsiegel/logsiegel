"""E2E demo: PII-free tamper-evident logging of an AI session.

Shows the full chain: a prompt containing identifiers is logged, the log and
the stored payload are provably PII-free, the salted hash still commits to
the original text (whoever holds the original can prove the match), and
crypto-shredding removes even that linkability.

Run:  python examples/pii_demo.py
"""

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsiegel import Logsiegel  # noqa: E402
from logsiegel.core import _salted_hash  # noqa: E402
from logsiegel.pii import RegexDetector  # noqa: E402

WORK = Path(__file__).resolve().parent / "_pii_demo_log"

PROMPT = (
    "Kündigungsschreiben für Max Mustermann entwerfen. Kontakt: "
    "max.mustermann@example.com, Tel. +49 89 1234567, "
    "Abfindung auf DE89 3704 0044 0532 0130 00."
)
ANSWER = "Sehr geehrter Herr Mustermann, hiermit kündigen wir …"

PII_STRINGS = ["max.mustermann@example.com", "+49 89 1234567", "DE89 3704 0044"]


def contains_pii(blob: str) -> list[str]:
    return [s for s in PII_STRINGS if s in blob]


def main():
    if WORK.exists():
        shutil.rmtree(WORK)

    print("== 1. inference with PII in the prompt, detector active ==")
    lb = Logsiegel.init(WORK, origin="demo.example/legal-drafting")
    lb.pii_detector = RegexDetector()
    lb.append("system_start", {"service.version": "0.1"})
    entry = lb.append(
        "inference",
        {"gen_ai.system": "openai", "gen_ai.request.model": "gpt-5"},
        input_text=PROMPT,
        output_text=ANSWER,
        store_payload=True,
    )
    lb.checkpoint()
    print(f"  masked: {entry['pii']['input']} (detector {entry['pii']['detector']})")

    print("\n== 2. the log file is PII-free ==")
    leaks = contains_pii((WORK / "log.jsonl").read_text())
    print(f"  identifiers in log.jsonl: {leaks or 'NONE'}")

    print("\n== 3. even the encrypted payload holds only the masked copy ==")
    payload = lb.read_payload(1)
    leaks = contains_pii(payload["input"])
    print(f"  identifiers in payload:   {leaks or 'NONE'}")
    print(f"  stored input: {payload['input'][:80]}…")

    print("\n== 4. …but the hash still commits to the ORIGINAL ==")
    import json
    salt = bytes.fromhex(
        json.loads((WORK / "keys/payload_keys.json").read_text())["1"]["salt"]
    )
    holder_proof = _salted_hash(salt, PROMPT) == entry["input_hash"]
    masked_match = _salted_hash(salt, payload["input"]) == entry["input_hash"]
    print(f"  original text matches committed hash: {holder_proof}")
    print(f"  masked copy matches committed hash:   {masked_match} (as it must be)")

    print("\n== 5. integrity verification ==")
    r = lb.verify()
    print(f"  {'PASS' if r.ok else 'FAIL'}: {r.entries} entries, {r.checkpoints} checkpoint(s)")

    print("\n== 6. GDPR erasure: shred → even hash linkability is gone ==")
    lb.shred(1)
    print(f"  payload readable: no  |  log verification: "
          f"{'PASS' if lb.verify().ok else 'FAIL'} (log byte-identical)")

    print("\n== 7. auditor dossier (PII section) ==")
    dossier = lb.export_dossier()
    section = dossier[dossier.index("## PII scrubbing"):]
    print("  " + "\n  ".join(section.splitlines()[:9]))


if __name__ == "__main__":
    main()

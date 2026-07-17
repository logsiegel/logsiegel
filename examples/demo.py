"""End-to-end demo: a public-administration assistant prepares a decision,
every step lands in a tamper-evident trail; a citizen (or ombuds office)
verifies a single receipt offline; then tampering, GDPR crypto-shredding
and the auditor dossier.

Run:  python examples/demo.py
"""

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsiegel import Logsiegel, verify_receipt  # noqa: E402

WORK = Path(__file__).resolve().parent / "_demo_log"


def main():
    if WORK.exists():
        shutil.rmtree(WORK)

    print("== 1. init + record an assistant session (public-sector case) ==")
    lb = Logsiegel.init(WORK, origin="stadt.example/buergerservice-assistent")
    lb.append("system_start", {"service.version": "2.3.1"})
    lb.append(
        "inference",
        {"gen_ai.system": "openai", "gen_ai.request.model": "gpt-5",
         "gen_ai.usage.input_tokens": 412, "gen_ai.usage.output_tokens": 88},
        input_text="Anfrage von Anna Muster: Zweitausfertigung der Wohnsitzbestätigung …",
        output_text="Entwurf: Bestätigung wird ausgestellt; Gebühr CHF 20 gemäss Tarif 4.2.",
        store_payload=True,
    )
    lb.append("human_override",
              {"actor": "sachbearbeiterin-12", "reason": "Entwurf geprüft und freigegeben"})
    cp = lb.checkpoint()
    print(f"  {len(lb.entries())} events, checkpoint root {cp['root'][:16]}…")

    print("\n== 2. verify (intact) ==")
    r = lb.verify()
    print(f"  {'PASS' if r.ok else 'FAIL'}")

    print("\n== 3. receipt: the citizen verifies ONE entry offline ==")
    rec = lb.receipt(2)  # the human approval
    ok = verify_receipt(rec, lb.public_key()).ok
    print(f"  receipt for entry 2 (human approval): {'PASS' if ok else 'FAIL'} "
          "— no access to the full log needed")

    print("\n== 4. tamper: forge the approving actor after the fact ==")
    log = WORK / "log.jsonl"
    lines = log.read_bytes().splitlines(keepends=True)
    e = json.loads(lines[2])
    e["attrs"]["actor"] = "someone-else"
    lines[2] = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    backup = log.read_bytes()
    log.write_bytes(b"".join(lines))
    r = lb.verify()
    print(f"  {'PASS' if r.ok else 'FAIL'} — {r.problems[0] if r.problems else ''}")
    log.write_bytes(backup)

    print("\n== 5. GDPR: crypto-shred the citizen's payload, log stays valid ==")
    print(f"  payload before: {lb.read_payload(1)['input'][:45]}…")
    lb.shred(1)
    try:
        lb.read_payload(1)
    except KeyError as exc:
        print(f"  payload after:  {exc}")
    print(f"  verify: {'PASS' if lb.verify().ok else 'FAIL'} (log unchanged, content gone)")

    print("\n== 6. auditor dossier ==")
    print("  " + "\n  ".join(lb.export_dossier().splitlines()[:12]))


if __name__ == "__main__":
    main()

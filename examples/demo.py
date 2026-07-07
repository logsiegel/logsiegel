"""End-to-end demo: log an AI session, checkpoint, tamper, detect, shred, export.

Run:  python examples/demo.py
"""

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logbuch import Logbuch  # noqa: E402

WORK = Path(__file__).resolve().parent / "_demo_log"


def main():
    if WORK.exists():
        shutil.rmtree(WORK)

    print("== 1. init + record an AI session ==")
    lb = Logbuch.init(WORK, origin="demo.example/hr-screening")
    lb.append("system_start", {"service.version": "2.3.1"})
    lb.append(
        "inference",
        {"gen_ai.system": "openai", "gen_ai.request.model": "gpt-5",
         "gen_ai.usage.input_tokens": 412, "gen_ai.usage.output_tokens": 88},
        input_text="Bewerber Max Mustermann, geb. 12.03.1990, bitte bewerten …",
        output_text="Empfehlung: zur zweiten Runde einladen.",
        store_payload=True,
    )
    lb.append("human_override",
              {"actor": "recruiter-7", "reason": "manual re-ranking"})
    lb.append("model_change",
              {"gen_ai.request.model": "gpt-5-mini", "reason": "cost policy"})
    cp = lb.checkpoint()
    print(f"  {len(lb.entries())} events, checkpoint root {cp['root'][:16]}…")

    print("\n== 2. verify (intact) ==")
    r = lb.verify()
    print(f"  {'PASS' if r.ok else 'FAIL'}")

    print("\n== 3. tamper: forge the human_override actor after the fact ==")
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

    print("\n== 4. GDPR: crypto-shred the applicant's payload, log stays valid ==")
    print(f"  payload before: {lb.read_payload(1)['input'][:45]}…")
    lb.shred(1)
    try:
        lb.read_payload(1)
    except KeyError as exc:
        print(f"  payload after:  {exc}")
    print(f"  verify: {'PASS' if lb.verify().ok else 'FAIL'} (log unchanged, content gone)")

    print("\n== 5. auditor dossier ==")
    print("  " + "\n  ".join(lb.export_dossier().splitlines()[:12]))


if __name__ == "__main__":
    main()

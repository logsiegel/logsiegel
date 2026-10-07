"""Demo: an AI pre-screening step in a hiring process, recorded in a
tamper-evident trail. The AI only scores the application; a recruiter
reviews it and makes the decision, here a rejection. The applicant gets a
receipt for the AI step that she can verify offline, the auditor gets a dossier,
and her stored data is crypto-shredded at the end while all proofs stay valid.

All names and data are fictitious.

Run:  python examples/hiring_demo.py
"""

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from logsiegel import Logsiegel, verify_receipt  # noqa: E402

WORK = ROOT / "examples" / "_hiring_demo_log"

APPLICATION = (
    "Application of Jane Example for 'Junior Data Analyst' (ref. JDA-2026-04): "
    "BSc Statistics, 1 year of SQL and Python, available from 1 January."
)
ASSESSMENT = (
    "Pre-screening score 0.41: required skills present, 3 years of experience not shown. "
    "Recommendation for the recruiter: do not shortlist, review manually."
)


def main():
    if WORK.exists():
        shutil.rmtree(WORK)

    print("== 1. create the log ==")
    lb = Logsiegel.init(WORK, origin="hr.example/pre-screening")
    print(f"  origin {lb.origin}, signing key {lb.public_key_fingerprint()}")

    print("\n== 2. the application comes in ==")
    received = lb.append(
        "data_input",
        {"application.id": "JDA-2026-04-0017", "channel": "careers-portal"},
        input_text=APPLICATION,
        store_payload=True,
    )
    print(f"  entry {received['seq']}: only a salted hash enters the log, "
          "the text is stored encrypted")

    print("\n== 3. the AI system pre-screens it (score only, no decision) ==")
    scoring = lb.append(
        "inference",
        {"gen_ai.system": "example-ranker", "gen_ai.request.model": "cv-screen-1.4",
         "application.id": "JDA-2026-04-0017", "result": "score 0.41, recommendation only"},
        input_text=APPLICATION,
        output_text=ASSESSMENT,
        store_payload=True,
    )
    print(f"  entry {scoring['seq']}: {scoring['attrs']['result']}")

    print("\n== 4. a recruiter reviews the score and decides ==")
    decision = lb.append(
        "human_override",
        {"actor": "recruiter-07", "application.id": "JDA-2026-04-0017",
         "decision": "rejected",
         "reason": "CV checked manually, required experience not met; AI score not adopted unseen"},
    )
    print(f"  entry {decision['seq']}: {decision['attrs']['actor']} -> "
          f"{decision['attrs']['decision']}")

    print("\n== 5. sign a checkpoint ==")
    cp = lb.checkpoint()
    print(f"  {cp['size']} entries, root {cp['root'][:16]}…")

    print("\n== 6. receipt for the AI step, handed to the rejected applicant ==")
    receipt_file = WORK / "receipt_ai_prescreening.json"
    pubkey_file = WORK / "public_key.pem"
    receipt_file.write_text(json.dumps(lb.receipt(scoring["seq"]), ensure_ascii=False, indent=1))
    shutil.copy(WORK / "keys" / "signing_key.pub", pubkey_file)
    receipt = json.loads(receipt_file.read_text())
    ok = verify_receipt(receipt, lb.public_key()).ok
    print(f"  receipt for entry {scoring['seq']}: {'PASS' if ok else 'FAIL'}")
    print("  she can check it herself:")
    print(f"    logsiegel verify-receipt {receipt_file.relative_to(ROOT)} "
          f"--pubkey {pubkey_file.relative_to(ROOT)}")
    print("  or drop both files into the browser verifier (verifier/).")

    print("\n== 7. auditor dossier ==")
    dossier_file = WORK / "dossier.md"
    dossier_file.write_text(lb.export_dossier())
    print(f"  written to {dossier_file.relative_to(ROOT)}")
    print("  " + "\n  ".join(dossier_file.read_text().splitlines()[2:7]))

    print("\n== 8. GDPR erasure: shred the applicant's stored data ==")
    for entry in (received, scoring):  # application text and AI assessment
        lb.shred(entry["seq"])
    try:
        lb.read_payload(scoring["seq"])
    except KeyError as exc:
        print(f"  payload after shredding: {exc}")
    log_ok = lb.verify().ok
    receipt_ok = verify_receipt(receipt, lb.public_key()).ok
    print(f"  log verification:     {'PASS' if log_ok else 'FAIL'}")
    print(f"  receipt verification: {'PASS' if receipt_ok else 'FAIL'} "
          "(proof kept, content gone)")


if __name__ == "__main__":
    main()

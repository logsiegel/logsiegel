"""Export test vectors for the browser verifier (independent JS reimplementation).

Generates verifier/fixtures/{canonical_vectors,receipts}.json from the Python
reference implementation. The JS verifier must reach the same verdict as
``verify_receipt`` on every case — that cross-check is what makes the browser
verifier a second, independent implementation of the receipt format rather
than a port.

Run from the repo root:  python scripts/export_fixtures.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization

from logsiegel.core import Logsiegel, canonical, verify_receipt
from logsiegel.merkle import leaf_hash

OUT_DIR = Path(__file__).resolve().parents[1] / "verifier" / "fixtures"


def _pub_bundle(lb: Logsiegel) -> dict:
    pub = lb.public_key()
    return {
        "pem": (lb.dir / "keys/signing_key.pub").read_text(),
        "spki_der_b64": base64.b64encode(
            pub.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode(),
        "raw_hex": pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex(),
    }


def build_log(directory: Path, origin: str) -> Logsiegel:
    lb = Logsiegel.init(directory, origin=origin)
    lb.append("system_start", {"model": "demo-1", "note": "boot"})
    lb.checkpoint()  # size 1 — single-leaf tree, empty inclusion proof
    lb.append("inference", {"gen_ai.request.model": "demo-1"},
              input_text="Antrag von Frau Müller, IBAN DE02 1203 0000 0000 2020 51",
              output_text="Entwurf erstellt", store_payload=True)
    lb.append("config_change", {"temperature": 0.2})
    lb.append("human_override", {"reason": 'Sachbearbeiterin korrigiert "§ 12"-Verweis'})
    lb.append("inference", {"note": "Umlaute äöü, Emoji 🔏, Backslash \\ und\nZeilenumbruch"})
    lb.checkpoint()  # size 5
    for i in range(7):
        lb.append("inference", {"i": i})
    lb.append("system_stop", {})
    lb.checkpoint()  # size 13
    return lb


def case(name: str, receipt: dict, pub, expect_stage: str, note: str = "") -> dict:
    """expect_stage: first stage the JS verifier must fail — or 'ok'."""
    report = verify_receipt(receipt, pub)
    entry_leaf = None
    if isinstance(receipt.get("entry"), dict):
        entry_leaf = leaf_hash(canonical(receipt["entry"])).hex()
    return {
        "name": name,
        "note": note,
        "receipt": receipt,
        "entry_leaf_hash_hex": entry_leaf,
        "python_report": {"ok": report.ok, "problems": report.problems},
        "expect_stage": expect_stage,
    }


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="logsiegel-fixtures-"))
    try:
        lb = build_log(tmp / "log_a", "stadt.example/buergerservice-assistent")
        other = Logsiegel.init(tmp / "log_b", origin="other.example/writer")
        other.append("system_start", {})
        other.checkpoint()

        lb.shred(1)  # crypto-shredding must not affect verifiability
        pub, pub_b = lb.public_key(), other.public_key()

        cases = [
            case("valid_seq0_size1", lb_receipt(lb, 0, cp_index=0), pub, "ok",
                 "single-leaf tree: empty inclusion proof"),
            case("valid_seq0_size13", lb.receipt(0), pub, "ok"),
            case("valid_seq7_size13", lb.receipt(7), pub, "ok"),
            case("valid_seq12_size13", lb.receipt(12), pub, "ok", "last entry"),
            case("valid_after_shred", lb.receipt(1), pub, "ok",
                 "payload crypto-shredded; receipt must still verify"),
            case("valid_unicode", lb.receipt(4), pub, "ok",
                 "umlauts, emoji, backslash, newline in attrs — canonical-JSON parity"),
        ]

        r = lb.receipt(7)

        t = copy.deepcopy(r)
        t["entry"]["attrs"]["i"] = 99
        cases.append(case("tampered_entry", t, pub, "inclusion",
                          "attrs changed after issuance — leaf hash no longer in tree"))

        t = copy.deepcopy(r)
        t["seq"] = 8
        cases.append(case("seq_mismatch", t, pub, "structure"))

        t = copy.deepcopy(r)
        t["origin"] = "evil.example/impostor"
        cases.append(case("origin_mismatch", t, pub, "structure"))

        t = copy.deepcopy(r)
        t["checkpoint"]["root"] = flip_hex(t["checkpoint"]["root"])
        cases.append(case("wrong_root", t, pub, "signature",
                          "root is part of the signed body — signature check catches it"))

        t = copy.deepcopy(r)
        t["checkpoint"]["sig"] = flip_hex(t["checkpoint"]["sig"])
        cases.append(case("bad_signature", t, pub, "signature"))

        t = copy.deepcopy(r)
        t["inclusion_proof"][0], t["inclusion_proof"][1] = (
            t["inclusion_proof"][1], t["inclusion_proof"][0])
        cases.append(case("proof_reordered", t, pub, "inclusion"))

        t = copy.deepcopy(r)
        t["inclusion_proof"] = t["inclusion_proof"][:-1]
        cases.append(case("proof_truncated", t, pub, "inclusion"))

        t = copy.deepcopy(r)
        t["inclusion_proof"][0] = "zz" + t["inclusion_proof"][0][2:]
        cases.append(case("proof_not_hex", t, pub, "structure",
                          "python folds this into the inclusion verdict; JS rejects at parse"))

        t = copy.deepcopy(lb.receipt(12))
        t["seq"] = t["entry"]["seq"] = 13
        cases.append(case("index_beyond_size", t, pub, "inclusion"))

        t = copy.deepcopy(r)
        del t["checkpoint"]["root"]
        cases.append(case("checkpoint_missing_root", t, pub, "structure",
                          "python folds this into the signature verdict; JS rejects at parse"))

        t = copy.deepcopy(r)
        t["entry"] = "not-an-object"
        cases.append(case("entry_not_object", t, pub, "structure"))

        wk = case("wrong_public_key", copy.deepcopy(r), pub_b, "signature",
                  "valid receipt of log A checked against key of log B")
        wk["public_key_override"] = _pub_bundle(other)
        cases.append(wk)

        OUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUT_DIR / "receipts.json").write_text(json.dumps({
            "format": "logsiegel-receipt-fixtures/1",
            "origin": lb.origin,
            "public_key": _pub_bundle(lb),
            "cases": cases,
        }, indent=1, ensure_ascii=False) + "\n")

        vectors = canonical_vectors()
        (OUT_DIR / "canonical_vectors.json").write_text(
            json.dumps({"format": "logsiegel-canonical-vectors/1", "vectors": vectors},
                       indent=1, ensure_ascii=False) + "\n")

        ok = sum(1 for c in cases if c["expect_stage"] == "ok")
        print(f"receipts.json: {len(cases)} cases ({ok} valid, {len(cases)-ok} negative)")
        print(f"canonical_vectors.json: {len(vectors)} vectors")
        print(f"→ {OUT_DIR}")
    finally:
        shutil.rmtree(tmp)


def lb_receipt(lb: Logsiegel, seq: int, cp_index: int) -> dict:
    """Receipt against a specific (older) checkpoint instead of the latest."""
    from logsiegel.core import LOG_FILE
    from logsiegel.merkle import inclusion_proof

    lines = lb._read_lines(LOG_FILE)
    cp = lb.checkpoints()[cp_index]
    leaves = [leaf_hash(ln) for ln in lines[: cp["size"]]]
    return {
        "v": 0,
        "origin": lb.origin,
        "seq": seq,
        "entry": json.loads(lines[seq]),
        "inclusion_proof": [p.hex() for p in inclusion_proof(leaves, seq)],
        "checkpoint": cp,
    }


def flip_hex(h: str) -> str:
    repl = "1" if h[0] != "1" else "2"
    return repl + h[1:]


def canonical_vectors() -> list[dict]:
    samples = [
        ("empty_object", {}),
        ("key_sorting", {"z": 1, "a": 2, "m": {"y": 0, "b": [3, 2, 1]}}),
        ("unicode_raw", {"s": "äöü ß € 🔏 中文"}),
        ("escapes", {"s": "quote \" backslash \\ newline \n tab \t ctrl "}),
        ("numbers", {"i": 0, "j": -7, "k": 1234567890}),
        ("null_bool", {"a": None, "b": True, "c": False}),
        ("nested_arrays", {"a": [{"b": 1}, [], {}, "x"]}),
        ("realistic_entry", {
            "v": 0, "seq": 3, "ts": "2026-07-30T12:00:00.000001+00:00",
            "event": "human_override",
            "attrs": {"reason": 'korrigiert "§ 12"', "Grüße": "übermittelt"},
            "prev": "sha256:" + "ab" * 32,
        }),
    ]
    out = []
    for name, value in samples:
        c = canonical(value)
        out.append({
            "name": name,
            "value": value,
            "canonical_utf8_hex": c.hex(),
            "sha256_hex": hashlib.sha256(c).hexdigest(),
            "leaf_hash_hex": leaf_hash(c).hex(),
        })
    return out


if __name__ == "__main__":
    main()

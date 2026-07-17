import json

import pytest

from logsiegel import Logsiegel


@pytest.fixture
def lb(tmp_path):
    lb = Logsiegel.init(tmp_path / "log", origin="test")
    lb.append("system_start", {"version": "0.1"})
    for i in range(5):
        lb.append(
            "inference",
            {"gen_ai.request.model": "gpt-5", "gen_ai.usage.input_tokens": 10 + i},
            input_text=f"prompt {i} with PII: max@example.com",
            output_text=f"answer {i}",
            store_payload=True,
        )
    lb.checkpoint()
    lb.append("model_change", {"gen_ai.request.model": "claude-fable-5"})
    lb.checkpoint()
    return lb


def test_verify_passes_on_intact_log(lb):
    r = lb.verify()
    assert r.ok, r.problems
    assert r.entries == 7
    assert r.checkpoints == 2


def test_entry_modification_detected(lb):
    p = lb.dir / "log.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    e = json.loads(lines[2])
    e["attrs"]["gen_ai.usage.input_tokens"] = 999  # forge usage after the fact
    lines[2] = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    p.write_bytes(b"".join(lines))

    r = lb.verify()
    assert not r.ok
    assert any("hash chain broken" in x or "Merkle root mismatch" in x for x in r.problems)


def test_truncation_detected(lb):
    p = lb.dir / "log.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:-1]))  # drop the last committed entry

    r = lb.verify()
    assert not r.ok
    assert any("truncation" in x for x in r.problems)


def test_checkpoint_signature_tamper_detected(lb):
    p = lb.dir / "checkpoints.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    cp = json.loads(lines[0])
    cp["size"] = 1  # rewrite history in the checkpoint itself
    lines[0] = json.dumps(cp, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    p.write_bytes(b"".join(lines))

    r = lb.verify()
    assert not r.ok
    assert any("signature invalid" in x for x in r.problems)


def test_crypto_shredding_keeps_log_verifiable(lb):
    assert lb.read_payload(1)["input"].startswith("prompt 0")
    before = (lb.dir / "log.jsonl").read_bytes()

    lb.shred(1)

    with pytest.raises(KeyError):
        lb.read_payload(1)
    assert (lb.dir / "log.jsonl").read_bytes() == before  # log byte-identical
    assert lb.verify().ok


def test_dossier_reports_state(lb):
    lb.shred(2)
    text = lb.export_dossier()
    assert "PASS" in text
    assert "| inference | 5 |" in text  # noqa: taxonomy table
    assert "Shredded entries: 1" in text


def test_unknown_event_rejected(lb):
    with pytest.raises(ValueError):
        lb.append("compliance_theatre")


def test_receipt_verifies_standalone(lb):
    from logsiegel import verify_receipt

    rec = lb.receipt(3)
    r = verify_receipt(rec, lb.public_key())
    assert r.ok, r.problems


def test_receipt_forgery_detected(lb):
    from logsiegel import verify_receipt

    rec = lb.receipt(3)
    rec["entry"]["attrs"]["gen_ai.usage.input_tokens"] = 999
    assert not verify_receipt(rec, lb.public_key()).ok


def test_receipt_wrong_key_detected(lb, tmp_path):
    from logsiegel import Logsiegel, verify_receipt

    other = Logsiegel.init(tmp_path / "other", origin="test")
    assert not verify_receipt(lb.receipt(0), other.public_key()).ok


def test_receipt_requires_covering_checkpoint(lb):
    lb.append("system_stop")  # not yet checkpointed
    with pytest.raises(ValueError):
        lb.receipt(7)


def test_second_writer_instance_stays_consistent(lb):
    from logsiegel import Logsiegel

    lb2 = Logsiegel(lb.dir)
    lb2.append("system_stop")
    lb.append("system_start")  # first instance must pick up the new tail
    r = lb.verify()
    assert r.ok, r.problems
    assert r.entries == 9


def test_verify_with_external_pubkey(lb, tmp_path):
    from logsiegel import Logsiegel

    assert lb.verify(public_key=lb.public_key()).ok
    other = Logsiegel.init(tmp_path / "other", origin="test")
    r = lb.verify(public_key=other.public_key())
    assert not r.ok  # wrong trust anchor → signatures must not check out

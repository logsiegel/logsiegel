import json

import pytest

from logsiegel.cli import main


@pytest.fixture
def log_dir(tmp_path):
    """A log with three entries (one with a stored payload) and one checkpoint."""
    d = tmp_path / "log"
    assert main(["init", str(d), "--origin", "cli-test"]) == 0
    assert main(["log", str(d), "--event", "system_start"]) == 0
    assert main([
        "log", str(d), "--event", "inference",
        "--attr", "gen_ai.request.model=gpt-5",
        "--input", "hello", "--output", "world",
        "--store-payload",
    ]) == 0
    assert main(["log", str(d), "--event", "system_stop"]) == 0
    assert main(["checkpoint", str(d)]) == 0
    return d


@pytest.fixture
def other_pubkey(tmp_path):
    """Public key of a second, unrelated log (the wrong trust anchor)."""
    other = tmp_path / "other"
    main(["init", str(other)])
    return other / "keys" / "signing_key.pub"


def tamper_entry(log_dir, line_no):
    """Rewrite one attribute of a committed entry, keeping canonical JSON."""
    p = log_dir / "log.jsonl"
    lines = p.read_bytes().splitlines(keepends=True)
    e = json.loads(lines[line_no])
    e["attrs"]["forged"] = "yes"
    lines[line_no] = json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    p.write_bytes(b"".join(lines))


# -- init ----------------------------------------------------------------


def test_init_creates_log_files(tmp_path, capsys):
    d = tmp_path / "new"
    assert main(["init", str(d), "--origin", "my-system"]) == 0

    out = capsys.readouterr().out
    assert "origin=my-system" in out
    assert "key=ed25519:" in out
    assert (d / "log.jsonl").read_text() == ""
    assert (d / "keys" / "signing_key.pub").exists()
    assert (d / "origin").read_text() == "my-system"


# -- log -----------------------------------------------------------------


def test_log_prints_new_entry_as_json(log_dir, capsys):
    capsys.readouterr()  # drop output of the fixture
    assert main(["log", str(log_dir), "--event", "model_change", "--attr", "model=v2"]) == 0

    entry = json.loads(capsys.readouterr().out)
    assert entry["seq"] == 3
    assert entry["event"] == "model_change"
    assert entry["attrs"] == {"model": "v2"}
    assert len((log_dir / "log.jsonl").read_text().splitlines()) == 4


def test_log_stores_only_hashes_of_input_and_output(log_dir):
    text = (log_dir / "log.jsonl").read_text()
    assert "hello" not in text
    assert "world" not in text
    assert '"input_hash":"sha256:' in text
    assert (log_dir / "payloads" / "00000001.enc").exists()


def test_log_rejects_unknown_event(log_dir, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["log", str(log_dir), "--event", "not_an_event"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert len((log_dir / "log.jsonl").read_text().splitlines()) == 3


def test_log_rejects_attr_without_equals_sign(log_dir):
    with pytest.raises(SystemExit) as exc:
        main(["log", str(log_dir), "--event", "inference", "--attr", "model"])
    assert "key=value" in str(exc.value.code)
    assert len((log_dir / "log.jsonl").read_text().splitlines()) == 3


# -- checkpoint ----------------------------------------------------------


def test_checkpoint_reports_size_and_is_appended(log_dir, capsys):
    capsys.readouterr()
    main(["log", str(log_dir), "--event", "anomaly"])
    assert main(["checkpoint", str(log_dir)]) == 0

    assert "checkpoint #2: size=4" in capsys.readouterr().out
    assert len((log_dir / "checkpoints.jsonl").read_text().splitlines()) == 2


# -- verify --------------------------------------------------------------


def test_verify_passes_on_intact_log(log_dir, capsys):
    capsys.readouterr()
    assert main(["verify", str(log_dir)]) == 0
    assert "PASS: 3 entries, 1 checkpoints" in capsys.readouterr().out

    pub = log_dir / "keys" / "signing_key.pub"  # same result with an explicit trust anchor
    assert main(["verify", str(log_dir), "--pubkey", str(pub)]) == 0
    assert "PASS" in capsys.readouterr().out


def test_verify_fails_on_tampered_log(log_dir, capsys):
    capsys.readouterr()
    tamper_entry(log_dir, 1)

    assert main(["verify", str(log_dir)]) == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL")
    assert "Merkle root mismatch" in out


def test_verify_fails_with_wrong_pubkey(log_dir, other_pubkey, capsys):
    capsys.readouterr()
    assert main(["verify", str(log_dir), "--pubkey", str(other_pubkey)]) == 1
    assert "signature invalid" in capsys.readouterr().out


# -- receipt and verify-receipt -------------------------------------------


def test_receipt_written_to_file(log_dir, tmp_path, capsys):
    out_file = tmp_path / "receipt.json"
    assert main(["receipt", str(log_dir), "--seq", "1", "--out", str(out_file)]) == 0

    assert "written to" in capsys.readouterr().out
    rec = json.loads(out_file.read_text())
    assert rec["seq"] == 1
    assert rec["origin"] == "cli-test"
    assert rec["entry"]["event"] == "inference"


def test_receipt_rejects_non_numeric_seq(log_dir, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["receipt", str(log_dir), "--seq", "first"])
    assert exc.value.code == 2
    assert "invalid int value" in capsys.readouterr().err


@pytest.fixture
def receipt_file(log_dir, tmp_path):
    path = tmp_path / "receipt.json"
    main(["receipt", str(log_dir), "--seq", "1", "--out", str(path)])
    return path


def test_verify_receipt_passes_with_log_key(log_dir, receipt_file, capsys):
    capsys.readouterr()
    pub = log_dir / "keys" / "signing_key.pub"
    assert main(["verify-receipt", str(receipt_file), "--pubkey", str(pub)]) == 0
    assert "PASS: entry 1 of origin 'cli-test'" in capsys.readouterr().out


def test_verify_receipt_fails_on_tampered_receipt(log_dir, receipt_file, capsys):
    capsys.readouterr()
    rec = json.loads(receipt_file.read_text())
    rec["entry"]["attrs"]["gen_ai.request.model"] = "cheaper-model"
    receipt_file.write_text(json.dumps(rec))

    pub = log_dir / "keys" / "signing_key.pub"
    assert main(["verify-receipt", str(receipt_file), "--pubkey", str(pub)]) == 1
    assert "inclusion proof invalid" in capsys.readouterr().out


def test_verify_receipt_fails_with_wrong_pubkey(receipt_file, other_pubkey, capsys):
    capsys.readouterr()
    assert main(["verify-receipt", str(receipt_file), "--pubkey", str(other_pubkey)]) == 1
    assert "checkpoint signature invalid" in capsys.readouterr().out


# -- export --------------------------------------------------------------


def test_export_writes_dossier(log_dir, tmp_path):
    out_file = tmp_path / "dossier.md"
    assert main(["export", str(log_dir), "--out", str(out_file)]) == 0

    text = out_file.read_text()
    assert "Origin: `cli-test`" in text
    assert "Integrity verification: PASS" in text
    assert "| inference | 1 |" in text
    assert "gpt-5" in text


def test_export_reports_tampered_log(log_dir, capsys):
    tamper_entry(log_dir, 1)
    capsys.readouterr()
    assert main(["export", str(log_dir)]) == 1  # dossier still written, exit code flags the failure

    out = capsys.readouterr().out
    assert "Integrity verification: FAIL" in out
    assert "problem: checkpoint 0: Merkle root mismatch" in out


# -- payload and shred ---------------------------------------------------


def test_payload_prints_decrypted_content(log_dir, capsys):
    capsys.readouterr()
    assert main(["payload", str(log_dir), "--seq", "1"]) == 0
    assert json.loads(capsys.readouterr().out) == {"input": "hello", "output": "world"}


def test_shred_removes_payload_and_keeps_log_valid(log_dir, capsys):
    before = (log_dir / "log.jsonl").read_bytes()
    capsys.readouterr()
    assert main(["shred", str(log_dir), "--seq", "1"]) == 0

    assert "log verification: PASS" in capsys.readouterr().out
    assert not (log_dir / "payloads" / "00000001.enc").exists()
    assert (log_dir / "log.jsonl").read_bytes() == before
    assert main(["verify", str(log_dir)]) == 0


def test_shred_reports_failed_verification_of_tampered_log(log_dir, capsys):
    tamper_entry(log_dir, 0)
    capsys.readouterr()
    assert main(["shred", str(log_dir), "--seq", "1"]) == 1
    assert "log verification: FAIL" in capsys.readouterr().out
    assert not (log_dir / "payloads" / "00000001.enc").exists()  # shredded regardless
    assert main(["payload", str(log_dir), "--seq", "1"]) == 2


# Each command needs its arguments; argparse stops with exit code 2.
@pytest.mark.parametrize("argv", [
    ["init"],
    ["checkpoint"],
    ["receipt", "LOG"],
    ["shred", "LOG"],
    ["payload", "LOG"],
    ["verify-receipt", "receipt.json"],
])
def test_missing_required_argument_is_rejected(argv, log_dir, capsys):
    argv = [str(log_dir) if a == "LOG" else a for a in argv]
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    assert "required" in capsys.readouterr().err


# -- operator errors: one line on stderr, exit code 2, no traceback --------


def assert_error(capsys, *fragments):
    err = capsys.readouterr().err
    assert err.startswith("error: ")
    assert "Traceback" not in err
    for f in fragments:
        assert f in err


def test_init_refuses_existing_log(log_dir, capsys):
    capsys.readouterr()
    assert main(["init", str(log_dir)]) == 2
    assert_error(capsys, "already contains a log")


@pytest.mark.parametrize("argv", [
    ["log", "DIR", "--event", "inference"],
    ["checkpoint", "DIR"],
    ["verify", "DIR"],
    ["export", "DIR"],
    ["receipt", "DIR", "--seq", "0"],
    ["shred", "DIR", "--seq", "0"],
    ["payload", "DIR", "--seq", "0"],
])
def test_commands_reject_missing_directory(argv, tmp_path, capsys):
    d = tmp_path / "nope"
    assert main([str(d) if a == "DIR" else a for a in argv]) == 2
    assert_error(capsys, f"no log at {d}", "logsiegel init")
    assert not d.exists()


def test_log_into_empty_directory_creates_nothing(tmp_path, capsys):
    d = tmp_path / "empty"
    d.mkdir()
    assert main(["log", str(d), "--event", "inference", "--input", "x", "--store-payload"]) == 2
    assert_error(capsys, f"no log at {d}")
    assert list(d.iterdir()) == []


def test_verify_copy_without_private_key(log_dir, tmp_path, capsys):
    """An auditor gets log, checkpoints and the public key, never the signing key."""
    copy = tmp_path / "copy"
    copy.mkdir()
    for name in ("log.jsonl", "checkpoints.jsonl", "origin"):
        (copy / name).write_bytes((log_dir / name).read_bytes())
    capsys.readouterr()
    pub = log_dir / "keys" / "signing_key.pub"
    assert main(["verify", str(copy), "--pubkey", str(pub)]) == 0
    assert "PASS: 3 entries, 1 checkpoints" in capsys.readouterr().out


def test_receipt_rejects_unknown_entry(log_dir, capsys):
    capsys.readouterr()
    assert main(["receipt", str(log_dir), "--seq", "5"]) == 2
    assert_error(capsys, "no entry 5 (log has 3)")


def test_receipt_requires_checkpoint(log_dir, capsys):
    main(["log", str(log_dir), "--event", "anomaly"])
    capsys.readouterr()
    assert main(["receipt", str(log_dir), "--seq", "3"]) == 2
    assert_error(capsys, "no checkpoint covers entry 3")


def test_shred_twice_is_rejected(log_dir, capsys):
    assert main(["shred", str(log_dir), "--seq", "1"]) == 0
    capsys.readouterr()
    assert main(["shred", str(log_dir), "--seq", "1"]) == 2
    err = capsys.readouterr().err
    assert err == "error: no payload key for entry 1\n"  # no Python quotes around the message


def test_payload_after_shred_is_rejected(log_dir, capsys):
    main(["shred", str(log_dir), "--seq", "1"])
    capsys.readouterr()
    assert main(["payload", str(log_dir), "--seq", "1"]) == 2
    assert_error(capsys, "payload key for entry 1 not available")


def test_verify_receipt_rejects_missing_file(log_dir, tmp_path, capsys):
    capsys.readouterr()
    pub = log_dir / "keys" / "signing_key.pub"
    assert main(["verify-receipt", str(tmp_path / "missing.json"), "--pubkey", str(pub)]) == 2
    assert_error(capsys, "missing.json", "No such file or directory")


@pytest.mark.parametrize("content", ["{broken", "[1, 2]"])
def test_verify_receipt_rejects_broken_receipt(content, log_dir, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    capsys.readouterr()
    pub = log_dir / "keys" / "signing_key.pub"
    assert main(["verify-receipt", str(bad), "--pubkey", str(pub)]) == 2
    assert_error(capsys, "bad.json: not")


def test_verify_receipt_rejects_broken_pubkey(receipt_file, tmp_path, capsys):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a pem")
    capsys.readouterr()
    assert main(["verify-receipt", str(receipt_file), "--pubkey", str(bad)]) == 2
    assert_error(capsys, "bad.pem: not a PEM public key")


def test_verify_rejects_broken_pubkey(log_dir, tmp_path, capsys):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a pem")
    capsys.readouterr()
    assert main(["verify", str(log_dir), "--pubkey", str(bad)]) == 2
    assert_error(capsys, "bad.pem: not a PEM public key")

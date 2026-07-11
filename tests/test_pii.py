import io
import json

import pytest

from logsiegel import Logsiegel
from logsiegel.core import _salted_hash
from logsiegel.pii import Detection, HttpDetector, RegexDetector, scrub

PROMPT = (
    "Bewerber Max Mustermann, erreichbar unter max.mustermann@example.com "
    "oder +49 89 1234567, Gehaltskonto DE89 3704 0044 0532 0130 00, bitte bewerten."
)


def test_regex_detector_finds_email_phone_iban():
    kinds = {d.kind for d in RegexDetector().detect(PROMPT)}
    assert {"email", "phone", "iban"} <= kinds


def test_scrub_masks_values_and_counts():
    det = RegexDetector()
    masked, counts = scrub(PROMPT, det.detect(PROMPT))
    assert "max.mustermann@example.com" not in masked
    assert "DE89" not in masked
    assert "[EMAIL]" in masked and "[IBAN]" in masked and "[PHONE]" in masked
    assert counts["email"] == 1 and counts["iban"] == 1
    assert "bitte bewerten" in masked  # non-PII text untouched


def test_scrub_resolves_overlaps_longest_first():
    text = "id 0123456789"
    dets = [Detection("phone", 3, 13), Detection("short", 3, 7)]
    masked, counts = scrub(text, dets)
    assert masked == "id [PHONE]"
    assert counts == {"phone": 1}


@pytest.fixture
def lb(tmp_path):
    return Logsiegel.init(tmp_path / "log", origin="test-pii")


def test_stored_payload_is_masked_log_is_pii_free(lb):
    lb.pii_detector = RegexDetector()
    lb.append("inference", {"gen_ai.request.model": "gpt-5"},
              input_text=PROMPT, output_text="Empfehlung: einladen.",
              store_payload=True)
    lb.checkpoint()

    payload = lb.read_payload(0)
    assert "max.mustermann@example.com" not in payload["input"]
    assert "[EMAIL]" in payload["input"]
    assert payload["output"] == "Empfehlung: einladen."

    raw = (lb.dir / "log.jsonl").read_text()
    assert "max.mustermann" not in raw and "DE89" not in raw

    entry = lb.entries()[0]
    assert entry["pii"]["detector"] == "regex-v0"
    assert entry["pii"]["input"]["email"] == 1
    assert lb.verify().ok


def test_hash_commits_to_original_not_masked(lb):
    lb.pii_detector = RegexDetector()
    entry = lb.append("inference", {}, input_text=PROMPT, store_payload=True)
    salt = bytes.fromhex(
        json.loads((lb.dir / "keys/payload_keys.json").read_text())["0"]["salt"]
    )
    # whoever holds the original can prove the match; the masked copy cannot
    assert entry["input_hash"] == _salted_hash(salt, PROMPT)
    assert entry["input_hash"] != _salted_hash(salt, lb.read_payload(0)["input"])


def test_without_detector_behavior_unchanged(lb):
    lb.append("inference", {}, input_text=PROMPT, store_payload=True)
    assert "pii" not in lb.entries()[0]
    assert lb.read_payload(0)["input"] == PROMPT


def test_http_detector_parses_ner_response(monkeypatch):
    captured = {}

    class FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        captured["body"] = json.loads(req.data)
        captured["timeout"] = timeout
        return FakeResp(json.dumps(
            {"entities": [{"label": "PERSON", "start": 9, "end": 23}]}
        ).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    det = HttpDetector("http://localhost:8080/detect", detector_id="saklam-pii")
    found = det.detect(PROMPT)
    assert captured["body"] == {"text": PROMPT}
    assert found == [Detection("person", 9, 23)]
    assert det.id == "saklam-pii"


def test_dossier_reports_pii_section(lb):
    lb.pii_detector = RegexDetector()
    lb.append("inference", {}, input_text=PROMPT, store_payload=True)
    lb.checkpoint()
    text = lb.export_dossier()
    assert "## PII scrubbing" in text
    assert "regex-v0" in text
    assert "| email | 1 |" in text

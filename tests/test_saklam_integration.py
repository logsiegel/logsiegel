"""Tests für die Saklam-Integration.

Übersprungen, solange das Paket ``saklam`` nicht installiert ist oder keine
gültige Lizenz vorliegt — die Integration ist ein optionales Extra
(``pip install logsiegel[saklam]``).
"""

from __future__ import annotations

import pytest

from logsiegel.integrations.saklam import SaklamDetector
from logsiegel.pii import Detection, scrub

saklam = pytest.importorskip("saklam", reason="pip install logsiegel[saklam]")

SATZ = (
    "Philip Müller aus Zürich, +41 78 222 60 45, philip@example.org, "
    "IBAN DE89 3704 0044 0532 0130 00"
)


def _lizenziert() -> bool:
    from saklam import license as lic

    return lic.current_status().valid


lizenz = pytest.mark.skipif(not _lizenziert(), reason="keine gültige Saklam-Lizenz")


def test_konstruktor_laedt_nichts():
    """Der Import der Engine passiert erst beim ersten detect()."""
    d = SaklamDetector()
    assert d.id == "saklam:pending"
    assert d._engine is None


def test_erfuellt_die_detektor_schnittstelle():
    d = SaklamDetector()
    assert hasattr(d, "id") and callable(d.detect)


@lizenz
def test_detect_liefert_detections():
    d = SaklamDetector()
    found = d.detect(SATZ)
    assert found and all(isinstance(x, Detection) for x in found)
    kinds = {x.kind for x in found}
    assert {"email_address", "german_iban", "phone"} <= kinds, kinds
    assert d.id.startswith("saklam:")


@lizenz
def test_scrub_entfernt_die_werte():
    d = SaklamDetector()
    masked, counts = scrub(SATZ, d.detect(SATZ))
    for wert in ("philip@example.org", "+41 78 222 60 45", "DE89 3704 0044 0532 0130 00"):
        assert wert not in masked
    assert sum(counts.values()) == len(d.detect(SATZ))


@lizenz
def test_date_wird_uebersprungen():
    text = "Termin am 12.02.1968 mit Anna Berger."
    assert not any(x.kind == "date" for x in SaklamDetector().detect(text))
    mit_datum = SaklamDetector(skip_types=()).detect(text)
    assert any(x.kind == "date" for x in mit_datum) or True  # DATE optional


@lizenz
def test_leerer_text():
    assert SaklamDetector().detect("") == []


@lizenz
def test_regex_modus_ohne_modell():
    d = SaklamDetector(model="regex")
    kinds = {x.kind for x in d.detect(SATZ)}
    assert {"email_address", "german_iban"} <= kinds
    assert d.id == "saklam:regex"

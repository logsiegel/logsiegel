"""Saklam-Integration: PII-Erkennung in-process statt über HTTP.

Der Detektor erfüllt dieselbe Schnittstelle wie ``logsiegel.pii.RegexDetector``
und ``HttpDetector`` (``.id`` und ``.detect(text) -> list[Detection]``), nutzt
aber die Saklam-Engine direkt im Prozess — kein Container, kein Netz-Hop.

    from logsiegel.core import Logsiegel
    from logsiegel.integrations.saklam import SaklamDetector

    ls = Logsiegel("/var/lib/logsiegel/prod", pii_detector=SaklamDetector())

Installation::

    pip install logsiegel[saklam]

Das Paket ``saklam`` braucht einen gültigen Saklam-Lizenzschlüssel
(``license_key=`` oder ``SAKLAM_LICENSE_KEY``); siehe https://saklam.com.

Datumsangaben werden per Default NICHT maskiert: im Provenance-Log sind sie
Kontext, kein Identifikator. Über ``skip_types`` anpassbar.
"""

from __future__ import annotations

from ..pii import Detection

_INSTALL_HINT = (
    "saklam ist nicht installiert — 'pip install saklam' (oder "
    "'pip install logsiegel[saklam]'). Ohne das Paket bleibt der HTTP- bzw. "
    "Regex-Detektor die Alternative."
)


class SaklamDetector:
    """Saklam-PII-Engine als logsiegel-Detektor (in-process).

    Args:
        skip_types: Entity-Typen, die NICHT als PII gelten sollen.
            Default ``("DATE",)`` — gleiche Regel wie der HTTP-Pfad im
            Provenance-Hook.
        license_key: Saklam-Lizenzschlüssel; ohne Angabe ``SAKLAM_LICENSE_KEY``.
        model: Registry-Eintrag von ``saklam`` (``auto``/``small``/``default``/
            ``regex``). Default ``auto``: mitgeliefertes Modell, sonst Cache,
            sonst Regex-Modus.
        max_chars: Obergrenze je Aufruf; längere Texte werden abgeschnitten
            (die gesalzenen Hashes binden weiter an den Originaltext).
        **kwargs: an ``saklam.Saklam`` durchgereicht (``language``, ``device``,
            ``custom_dir``, ``domain_layer`` …).

    Der Import von ``saklam`` passiert erst beim ersten ``detect()`` — so lässt
    sich der Detektor auch dort konstruieren, wo das Paket fehlen darf.
    """

    def __init__(
        self,
        skip_types: tuple[str, ...] = ("DATE",),
        license_key: str | None = None,
        model: str = "auto",
        max_chars: int = 100_000,
        **kwargs,
    ):
        self.skip_types = {t.upper() for t in skip_types}
        self.max_chars = max_chars
        self._license_key = license_key
        self._model = model
        self._kwargs = kwargs
        self._engine = None
        self.id = "saklam:pending"

    def _ensure(self):
        if self._engine is not None:
            return self._engine
        try:
            from saklam import Saklam
        except ImportError as exc:  # pragma: no cover - hängt von der Umgebung ab
            raise ImportError(_INSTALL_HINT) from exc

        self._engine = Saklam(
            license_key=self._license_key, model=self._model, **self._kwargs
        )
        # Die id landet im Log ("womit wurde maskiert") — sie muss die
        # tatsächlich laufende Engine nennen, nicht die gewünschte.
        self.id = f"saklam:{self._engine.engine_id}"
        return self._engine

    def detect(self, text: str) -> list[Detection]:
        if not text:
            return []
        engine = self._ensure()
        entities = engine.detect(text[: self.max_chars])
        return [
            Detection(str(e["type"]).lower(), int(e["start"]), int(e["end"]))
            for e in entities
            if str(e["type"]).upper() not in self.skip_types
        ]

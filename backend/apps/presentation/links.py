"""Enlaces dentro de la narrativa: cada mención a un riesgo, activo, vulnerabilidad o conteo lleva
al apartado que la sustenta. El texto va escapado; solo se insertan ``<a>`` con URLs del sistema.

El ``Linker`` se construye una vez por petición (consulta nombres de activos, títulos de riesgos
abiertos y claves de vulnerabilidades) y se aplica a cada campo con el filtro ``linkify``.
"""

from __future__ import annotations

import re

from django.urls import reverse
from django.utils.html import escape
from django.utils.safestring import mark_safe

# Patrones fijos (regex, URL por nombre, parámetros). El orden importa: lo más específico primero.
_GENERIC = (
    (
        r"\b\d+\s+riesgos?\s+cr[ií]ticos?\b|\briesgos?\s+cr[ií]ticos?\b",
        "detection:risks",
        "level=CRITICAL",
    ),
    (
        r"\b\d+\s+riesgos?\s+muy\s+altos?\b|\briesgos?\s+muy\s+altos?\b",
        "detection:risks",
        "level=VERY_HIGH",
    ),
    (r"\b\d+\s+riesgos?\s+altos?\b|\briesgos?\s+altos?\b", "detection:risks", "level=HIGH"),
    (r"\b\d+\s+riesgos?\s+moderados?\b", "detection:risks", "level=MODERATE"),
    (
        r"\b\d+\s+riesgos?\s+abiertos?\b|\briesgos?\s+abiertos?\b|\briesgos?\s+(?:sin\s+tratamiento|valorados?)\b",
        "detection:risks",
        "",
    ),
    (
        r"\bplazos?\s+(?:de\s+)?(?:remediaci[oó]n\s+(?:de\s+)?)?(?:de\s+)?CISA(?:\s+vencidos?)?\b",
        "detection:panel",
        "in_kev=1",
    ),
    (
        r"\bexplotaci[oó]n\s+activa(?:\s+conocida)?(?:\s*\(KEV\))?(?!\w)|\bKEV\b",
        "detection:panel",
        "in_kev=1",
    ),
    (
        r"\b\d+\s+vulnerabilidad(?:es)?\s+sostenidas?\b|\bvulnerabilidad(?:es)?\s+sostenidas?\b",
        "detection:panel",
        "",
    ),
    (
        r"\b\d+\s+vulnerabilidad(?:es)?\s+(?:confirmadas?|por\s+verificar|consolidadas?|acumuladas?|nuevas?)\b",
        "detection:panel",
        "",
    ),
    (r"\b\d+\s+(?:descripciones|textos)\b", "detection:panel", ""),
    (
        r"\b\d+\s+acci[oó]n(?:es)?(?:\s+del\s+planificador)?\s+(?:esperan|por|pendientes\s+de)\s+aprobaci[oó]n\b|\bcola\s+de\s+aprobaci[oó]n\b|\bacciones?\s+(?:por|pendientes\s+de)\s+aprobar\b",
        "detection:queue",
        "",
    ),
    (
        r"\b\d+\s+decisiones(?:\s+del\s+planificador|\s+de\s+planificaci[oó]n)?\b|\b\d+\s+escaneos?\b",
        "detection:activity",
        "",
    ),
    (
        r"\b\d+\s+sincronizaciones?\s+de\s+inteligencia\b|\binteligencia\s+de\s+amenazas\b|\bNVD\b|\bEPSS\b",
        "detection:sources",
        "",
    ),
    (
        r"\b\d+\s+(?:de\s+\d+\s+)?activos?\b(?:\s+con\s+criticidad(?:\s+calculada)?)?",
        "assets:list",
        "",
    ),
    # Menciones cortas que quedan tras las anteriores («1 crítico», «3 muy altos», «825 vulnerabilidades»).
    (r"\b\d+\s+cr[ií]ticos?\b", "detection:risks", "level=CRITICAL"),
    (r"\b\d+\s+muy\s+altos?\b", "detection:risks", "level=VERY_HIGH"),
    (r"\b\d+\s+altos?\b", "detection:risks", "level=HIGH"),
    (r"\b\d+\s+moderados?\b", "detection:risks", "level=MODERATE"),
    (r"\b\d+\s+vulnerabilidad(?:es)?\b", "detection:panel", ""),
    (r"\b\d+\s+riesgos?\b", "detection:risks", ""),
)


class Linker:
    def __init__(self, *, assets=(), risks=(), vulns=()):
        """``assets``: (nombre, pk); ``risks``: (título, pk); ``vulns``: (clave, pk)."""
        self.rules: list[tuple[re.Pattern, str]] = []
        for title, pk in sorted(risks, key=lambda t: -len(t[0])):
            if len(title) >= 12:
                self.rules.append(
                    (re.compile(re.escape(title)), reverse("detection:risk", args=[pk]))
                )
        for key, pk in vulns:
            self.rules.append(
                (re.compile(re.escape(key) + r"\b"), reverse("detection:vulnerability", args=[pk]))
            )
        for name, pk in sorted(assets, key=lambda t: -len(t[0])):
            if len(name) >= 3:
                self.rules.append(
                    (
                        re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])"),
                        reverse("assets:detail", args=[pk]),
                    )
                )
        for pattern, url_name, query in _GENERIC:
            url = reverse(url_name) + (f"?{query}" if query else "")
            self.rules.append((re.compile(pattern, re.IGNORECASE), url))
        self.rules.append((re.compile(r"\bCVE-\d{4}-\d{4,}\b"), reverse("detection:sources")))

    @classmethod
    def from_db(cls):
        from apps.assets.models import Asset
        from apps.detection.descriptions import SUSTAINED
        from apps.detection.models import Risk, Vulnerability

        from . import indicators

        return cls(
            assets=Asset.objects.filter(merged_into__isnull=True).values_list("name", "pk"),
            risks=Risk.objects.filter(status__in=indicators.RISK_OPEN).values_list("title", "pk"),
            vulns=Vulnerability.objects.filter(status__in=SUSTAINED, key__startswith="CVE-")
            .order_by("-contextual_score")
            .values_list("key", "pk")[:400],
        )

    def spans(self, text: str):
        """Tramos (inicio, fin, url) sin solaparse; gana el que aparece antes en ``rules``."""
        taken = []
        for pattern, url in self.rules:
            for m in pattern.finditer(text):
                if m.end() == m.start():
                    continue
                if any(not (m.end() <= s or m.start() >= e) for s, e, _ in taken):
                    continue
                taken.append((m.start(), m.end(), url))
        return sorted(taken)

    def render(self, text: str) -> str:
        text = text or ""
        out, pos = [], 0
        for start, end, url in self.spans(text):
            out.append(escape(text[pos:start]))
            out.append(f'<a href="{escape(url)}" class="nar-link">{escape(text[start:end])}</a>')
            pos = end
        out.append(escape(text[pos:]))
        return mark_safe("".join(out))

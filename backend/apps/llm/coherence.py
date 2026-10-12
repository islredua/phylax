"""Coherencia entre la clase elegida por el LLM y su explicación.

Los modelos pequeños a veces copian líneas de la rúbrica o nombran en
``rationale`` una clase distinta de la que devuelven en ``criticality``. Solo se
buscan los códigos en mayúsculas (``ALTO``, ``INFORMATIVO``...): las palabras
comunes en minúsculas ("impacto medio", "riesgo bajo") no cuentan.
"""

import re

CLASSES = ("CRITICO", "ALTO", "MEDIO", "BAJO", "INFORMATIVO")
_CLASS_RE = re.compile(r"\b(CR[IÍ]TICO|ALTO|MEDIO|BAJO|INFORMATIVO)\b")


def other_classes_mentioned(criticality, rationale):
    """Clases (códigos) que la explicación nombra y no son la elegida, sin repetir."""
    found = []
    for match in _CLASS_RE.findall(rationale or ""):
        code = match.replace("Í", "I")
        if code != criticality and code not in found:
            found.append(code)
    return found

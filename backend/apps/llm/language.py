"""Detección ligera de idioma para la salida de los modelos locales.

Un modelo de 7B instruido en español responde en inglés con cierta frecuencia, sobre todo cuando
la entrada (descripciones NVD, nombres de plantillas) está en inglés. Antes de publicar un texto
al usuario se comprueba que **parezca español**; si no, se descarta y se redacta de nuevo. La
heurística cuenta palabras funcionales de cada idioma: los términos técnicos («server», «buffer»)
no deciden, las preposiciones y artículos sí.
"""

from __future__ import annotations

import re

_WORD = re.compile(r"[a-záéíóúüñ]+", re.IGNORECASE)
_ACCENTS = re.compile(r"[áéíóúñ¿¡]", re.IGNORECASE)

SPANISH = frozenset(
    """de la el que en y los las un una para con por se del es al como más pero sus le ya o este
    sí porque esta entre cuando muy sin sobre también hasta hay donde desde todo durante todos
    uno les ni contra otros ese eso ante ellos esto antes algunos qué unos otro otras otra él
    tanto esa estos mucho quienes nada muchos cual poco ella estar estas algunas algo puede podría
    permite permitiría atacante versión versiones afectado afectada afectadas actualizar
    vulnerabilidad vulnerabilidades servidor servicio datos ejecución código remoto remota través
    mediante debe deben riesgo impacto organización activo expuesto expuesta acceso información
    ataque exposición cabeceras credenciales interrupción fuga pérdida compromiso toma""".split()
)
ENGLISH = frozenset(
    """the of and to in is that for it as with be this are by on an or from which can could may
    allows allow attacker attackers via version versions vulnerable prior before affected through
    using when remote user users input system file code execution has have been was were
    not if into than their its these those such also would should there where while due any all
    some more other vulnerabilities vulnerability multiple security issues flaw found update fix
    fixed exposure disclosure missing headers configuration injection overflow leading lead
    attack access data exposed information sensitive unauthenticated authenticated arbitrary""".split()
)


def looks_spanish(text: str | None, *, min_words: int = 3) -> bool:
    """``True`` si el texto parece español (o es demasiado corto para juzgarlo).

    Textos de menos de ``min_words`` palabras (una clave, un nombre de producto) se aceptan.
    """
    words = [w.lower() for w in _WORD.findall(text or "")]
    if len(words) < min_words:
        return True
    es = sum(1 for w in words if w in SPANISH) + 2 * len(_ACCENTS.findall(text or ""))
    en = sum(1 for w in words if w in ENGLISH)
    if en == 0:
        return True
    return es > en


def non_spanish(*texts: str | None) -> list[str]:
    """Los textos de la lista que no parecen español (para registrar qué se descartó)."""
    return [t for t in texts if t and not looks_spanish(t)]

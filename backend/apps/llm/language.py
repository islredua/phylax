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


# --- Concordancia básica ------------------------------------------------------------------
# El modelo de 7B tropieza con el género y el número de los sustantivos técnicos («un
# denegación de servicio», «estos vulnerabilidades», «injectar»). Son errores de forma, no de
# fondo, así que se corrigen de manera determinista antes de guardar el texto; lo que no está en
# estas listas se deja tal cual.

_FEMININE = (
    "denegación|inyección|ejecución|elevación|escalada|exposición|divulgación|fuga|falsificación|"
    "omisión|lectura|escritura|sobrescritura|manipulación|revelación|condición|desreferencia|"
    "validación|configuración|vulnerabilidad|pérdida|interrupción|toma|suplantación|evasión|"
    "autenticación|autorización|corrupción|filtración|desbordamiento de pila|carga|descarga|"
    "contraseña|cabecera|clave|sesión|cookie|consulta|petición|solicitud|respuesta|versión"
)
_FEMININE_PLURAL = (
    "vulnerabilidades|fallas|debilidades|versiones|configuraciones|credenciales|cabeceras|"
    "contraseñas|claves|sesiones|cookies|consultas|peticiones|solicitudes|respuestas|"
    "inyecciones|ejecuciones|exposiciones|fugas|actualizaciones|correcciones|medidas"
)
_SINGULAR_DETS = {
    "un": "una",
    "este": "esta",
    "el": "la",
    "mismo": "misma",
    "otro": "otra",
    "dicho": "dicha",
    "ese": "esa",
    "aquel": "aquella",
    "ningún": "ninguna",
    "algún": "alguna",
    "cualquier": "cualquier",
}
_PLURAL_DETS = {
    "estos": "estas",
    "los": "las",
    "unos": "unas",
    "muchos": "muchas",
    "algunos": "algunas",
    "otros": "otras",
    "varios": "varias",
    "dichos": "dichas",
    "esos": "esas",
    "todos": "todas",
    "aquellos": "aquellas",
    "ningunos": "ningunas",
}
_SING_RE = re.compile(rf"\b({'|'.join(_SINGULAR_DETS)}) ({_FEMININE})\b", re.IGNORECASE)
_PLUR_RE = re.compile(rf"\b({'|'.join(_PLURAL_DETS)}) ({_FEMININE_PLURAL})\b", re.IGNORECASE)
_SPELLING = (
    (re.compile(r"\binjec(t|c)", re.IGNORECASE), lambda m: m.group(0)[0] + "nyec" + m.group(1)),
    (re.compile(r"\bvulnerabilidade\b", re.IGNORECASE), lambda m: m.group(0)[:-1]),
    (re.compile(r"\bactualizacion\b"), lambda m: "actualización"),
    (re.compile(r"\bversion\b"), lambda m: "versión"),
    (re.compile(r"\bejecucion\b"), lambda m: "ejecución"),
    (re.compile(r"\bcodigo\b"), lambda m: "código"),
    (re.compile(r"\bautenticacion\b"), lambda m: "autenticación"),
    (re.compile(r"\binformacion\b"), lambda m: "información"),
)


def _agree(table):
    def repl(match):
        det, noun = match.group(1), match.group(2)
        fixed = table.get(det.lower(), det)
        if det[0].isupper():
            fixed = fixed[0].upper() + fixed[1:]
        return f"{fixed} {noun}"

    return repl


def fix_spanish(text: str | None) -> str:
    """Corrige concordancia y faltas frecuentes del modelo sin tocar el sentido del texto."""
    if not text:
        return text or ""
    out = _SING_RE.sub(_agree(_SINGULAR_DETS), str(text))
    out = _PLUR_RE.sub(_agree(_PLURAL_DETS), out)
    for pattern, repl in _SPELLING:
        out = pattern.sub(repl, out)
    return out

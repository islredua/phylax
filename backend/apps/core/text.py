"""Números y plurales de los textos que se le muestran a una persona.

Los textos que arma el código decían «9 hallazgo(s) distintos de 33753 resultado(s)». Aquí vive la
única regla para escribirlos bien:

- ``cuantos(n, "hallazgo")`` → «1 hallazgo», «33,753 hallazgos»: el número con separador de miles
  y la forma que toca. Para adjetivos que concuerdan, ``cuantos(n, "hallazgo nuevo",
  "hallazgos nuevos")``.
- ``legible(texto)`` arregla **al mostrar** los textos que quedaron guardados con «(s)» antes de
  esta regla (bitácora de automatización, eventos): no cambia nada en la base.
"""

from __future__ import annotations

import re


def miles(n) -> str:
    """``1,049``: separador de miles como se escribe en México."""
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def forma(n, singular, plural=None) -> str:
    """La palabra sin el número: «hallazgo» para 1, «hallazgos» para lo demás."""
    try:
        one = int(n) == 1
    except (TypeError, ValueError):
        one = False
    return singular if one else (plural or singular + "s")


def cuantos(n, singular, plural=None) -> str:
    """«1 hallazgo» / «33,753 hallazgos»."""
    return f"{miles(n)} {forma(n, singular, plural)}"


# «9 hallazgo(s) distintos», «1 vulnerabilidad(es)», «3 hallazgo(s) nuevo(s)».
_MARKED = re.compile(
    r"(?P<n>\d[\d,]*)(?P<rest>(?:\s+[^\W\d_]+(?:\((?:s|es)\))?){0,4}?\s+[^\W\d_]+\((?:s|es)\)"
    r"(?:\s+[^\W\d_]+\((?:s|es)\))*)(?P<adj>\s+[^\W\d_]+)?"
)
_MARK = re.compile(r"(?P<word>[^\W\d_]+)\((?P<end>s|es)\)")
_UNACCENT = str.maketrans("áéíóú", "aeiou")
# Adjetivos que seguían a la palabra marcada y ya venían en plural: con «1» van en singular.
_SINGULAR_ADJECTIVE = {
    "distintos": "distinto",
    "crudos": "crudo",
    "nuevos": "nuevo",
    "vistos": "visto",
    "actualizados": "actualizado",
    "abiertas": "abierta",
    "abiertos": "abierto",
    "marcados": "marcado",
}


def _plural(word, ending) -> str:
    """«hallazgo» + s; «decisión» + es → «decisiones» (la tilde de la última sílaba se pierde)."""
    if ending == "es" and len(word) > 1 and word[-2] in "áéíóú":
        word = word[:-2] + word[-2].translate(_UNACCENT) + word[-1]
    return word + ending


def legible(text) -> str:
    """«9 hallazgo(s) distintos de 33753 resultado(s)» → «9 hallazgos distintos de 33,753
    resultados». Solo toca los números que gobiernan una palabra marcada con «(s)» o «(es)»."""
    if not text or "(s)" not in str(text) and "(es)" not in str(text):
        return text

    def fix(match):
        try:
            n = int(match["n"].replace(",", ""))
        except ValueError:
            return match[0]
        rest = _MARK.sub(
            lambda m: m["word"] if n == 1 else _plural(m["word"], m["end"]), match["rest"]
        )
        adj = match["adj"] or ""
        if n == 1 and adj.strip().lower() in _SINGULAR_ADJECTIVE:
            adj = adj.replace(adj.strip(), _SINGULAR_ADJECTIVE[adj.strip().lower()])
        return f"{n:,}{rest}{adj}"

    return _MARKED.sub(fix, str(text))

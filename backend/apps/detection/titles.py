"""Coherencia del título de una vulnerabilidad con el software que de verdad se observó.

El título lo escribe el modelo y tres cosas salían mal con los datos del laboratorio:

- **Claves de catálogo en lugar de nombres.** «…en http_server 2.4.49», «…en horizon_daas»: la
  clave de producto de NVD (o de la plantilla de nuclei) copiada tal cual.
- **La versión de un software pegada a otro producto.** «Ejecución remota de código en PHPMailer
  4.7»: 4.7 es la versión de WordPress que se observó, no la de PHPMailer.
- **Versiones que nadie observó.** «…en VMware ESXi y Horizon DaaS (OpenSLP) 6.5.x, 6.7.x» en un
  activo donde no se identificó software y con un texto técnico que no menciona versiones: el
  modelo las puso de memoria.

Aquí no se le pide nada al modelo: se revisa lo que escribió contra el componente observado y se
arregla por código lo que se puede (la clave del propio software se cambia por su nombre; la
versión se devuelve a su software; una versión sin sustento se quita). Lo que no se puede arreglar
(una clave de otro producto, un título que se queda sin contenido) se rechaza y el título lo pone
la regla de siempre (``consolidation.rule_title``).
"""

from __future__ import annotations

import re

# Sube cuando cambian las reglas: el repaso de los títulos ya guardados corre una vez por versión.
RULES_VERSION = 2

# «http_server», «horizon_daas», «mod_proxy_ajp»: minúsculas unidas con guion bajo.
_RAW_KEY = re.compile(r"(?<![\w.\-/])[a-z][a-z0-9]*(?:_[a-z0-9]+)+(?![\w\-])")
_REPEATED = re.compile(r"\b(\w{3,}) \1\b", re.IGNORECASE)
# «2.4.49», «6.5.x», «8.38»: números con punto. Un entero suelto («Samba 4») no cuenta.
_VERSION = re.compile(r"(?<![\w.])\d+(?:\.(?:\d+|[xX]))+(?![\w])")
# Lo que queda colgando al quitar una versión del final: «…Samba smbd 4.0.0 a», «… y versiones».
_CONNECTOR = (
    r"y|e|o|a|al|de|del|en|la|las|los|el|hasta|desde|entre|versión|versiones|anterior|anteriores|"
    r"posterior|posteriores|inferiores|superiores|antes|previas|previa|v"
)
_TRAILING = re.compile(rf"(?:[\s,;:·\-–/(<>=≤≥]+|\b(?:{_CONNECTOR})\b)+$", re.IGNORECASE)
_ONLY_CONNECTORS = re.compile(rf"\b(?:{_CONNECTOR})\b|[\s,;:·\-–/().<>=≤≥]", re.IGNORECASE)
MIN_WORDS = 3  # un título más corto que esto tras el recorte ya no dice nada: manda la regla
# Palabras del nombre de un software que no lo identifican.
_GENERIC = frozenset(
    "server servidor http https core api web client cliente service servicio lib library "
    "detectado por the for and".split()
)


class UnfixableTitleError(ValueError):
    """El título no corresponde a lo observado y no se puede arreglar por código."""


def software_name(component) -> str:
    """Nombre del software observado sin la nota de cómo se detectó: «wordpress (detectado por
    wordpress-detect)» → «wordpress»."""
    return (component.name or "").split(" (")[0].strip() if component else ""


def readable_product(value) -> str:
    """Un producto de la plantilla sirve para un título solo si es un nombre, no una clave
    («horizon_daas», «vmware:esxi»)."""
    text = str(value or "").strip()
    return "" if "_" in text or ":" in text else text


def _tokens(component) -> set:
    """Palabras que identifican al componente en un título."""
    words = re.split(r"[^\w]+", f"{software_name(component)} {component.product_key or ''}")
    words += (component.product_key or "").split("_")
    return {w.lower() for w in words if len(w) >= 3 and w.lower() not in _GENERIC}


def mentions(title, component) -> bool:
    """``True`` si el título nombra al componente (o no hay con qué comprobarlo)."""
    tokens = _tokens(component)
    if not tokens:
        return True
    return any(
        re.search(rf"(?<![\w]){re.escape(token)}(?![\w])", title, re.IGNORECASE) for token in tokens
    )


def catalog_keys(cve_id) -> set:
    """Claves de producto con guion bajo que NVD asocia al CVE («http_server», «horizon_daas»)."""
    if not cve_id:
        return set()
    from apps.cti.models import CveProduct

    return {
        key
        for key in CveProduct.objects.filter(cve_id=cve_id).values_list("product", flat=True)
        if key and "_" in key
    }


def _grounded(token, grounding) -> bool:
    """¿Aparece la versión en lo que se observó o en el texto técnico? «6.5.x» vale por «6.5»."""
    base = re.sub(r"(?:\.[xX])+$", "", token)
    return bool(re.search(rf"(?<![\w.]){re.escape(base)}(?!\d)", grounding))


def strip_ungrounded(title, grounding):
    """Quita del título las versiones que no salen de ``grounding``. Devuelve ``(título, quitadas)``.

    Las versiones se miran por tramos («4.0.0 - 4.2.13», «6.5.x, 6.7.x», «4.0.x < 4.1.23»: varias
    unidas solo por conectores). Si una del tramo no tiene sustento se quita el tramo entero:
    dejar un extremo del rango haría leer «Samba 4.0.0» como si esa fuera la versión observada.
    """
    runs = []  # [inicio, fin, [versiones], alguna_sin_sustento]
    for match in _VERSION.finditer(title):
        loose = not _grounded(match.group(0), grounding)
        if runs and not _ONLY_CONNECTORS.sub("", title[runs[-1][1] : match.start()]):
            runs[-1][1] = match.end()
            runs[-1][2].append(match.group(0))
            runs[-1][3] = runs[-1][3] or loose
        else:
            runs.append([match.start(), match.end(), [match.group(0)], loose])
    bad = [run for run in runs if run[3]]
    if not bad:
        return title, []
    out = title
    for start, end, _versions, _loose in reversed(bad):
        out = out[:start] + out[end:]
    out = re.sub(r"\(\s*\)", "", out)
    out = re.sub(r"\s{2,}", " ", out)
    out = re.sub(r"\s+([,;:.])", r"\1", out)
    out = _TRAILING.sub("", out).strip()
    return out, [version for run in bad for version in run[2]]


def suspicious(title, component, grounding=None) -> bool:
    """Filtro barato (sin consultas): ¿merece este título pasar por ``coherent``?

    ``grounding`` aquí es lo que ya se tiene a mano (el texto técnico guardado): una versión que
    no aparezca en él ni sea la del componente merece la revisión completa.
    """
    title = str(title or "")
    if _RAW_KEY.search(title):
        return True
    version = (component.version or "").strip() if component else ""
    if grounding is not None:
        own = f"{grounding} {version}"
        if any(not _grounded(m.group(0), own) for m in _VERSION.finditer(title)):
            return True
    if not version:
        return False
    found = re.search(rf"(?<![\w.]){re.escape(version)}(?![\w.])", title)
    return bool(found) and not mentions(title, component)


def coherent(title, component, *, cve_id=None, extra_keys=(), grounding=None):
    """Ajusta el título al software observado. Devuelve ``(título, notas)``.

    ``grounding`` es todo lo que sustenta una versión: texto técnico, evidencia y versiones del
    software del activo; sin él no se revisan las versiones. Lanza ``UnfixableTitleError`` si el
    título nombra una clave de producto que no es la del componente, o si tras quitar las versiones
    sin sustento ya no dice nada: no se arregla por código.
    """
    notes = []
    title = str(title or "").strip()
    own_key = (component.product_key or "").split(":")[-1] if component else ""
    name = software_name(component)
    foreign = None  # se consulta solo si el título trae alguna clave

    def swap(match):
        nonlocal foreign
        token = match.group(0)
        if own_key and token == own_key:
            notes.append(f"«{token}» es la clave del software: se escribe su nombre, {name}")
            return name
        if foreign is None:
            foreign = catalog_keys(cve_id) | {k for k in extra_keys if k and "_" in k}
        if token in foreign:
            raise UnfixableTitleError(token)
        return token  # «mod_lua», «mod_proxy_ajp»: nombres propios, se conservan

    title = _RAW_KEY.sub(swap, title)
    title = _REPEATED.sub(r"\1", title)  # «Apache Apache httpd» → «Apache httpd»

    version = (component.version or "").strip() if component else ""
    if name and version:
        where = re.compile(rf"(?<![\w.]){re.escape(version)}(?![\w.])")
        if where.search(title) and not mentions(title, component):
            bare = re.sub(r"\s{2,}", " ", where.sub("", title, count=1)).strip(" ·,;-")
            title = f"{bare} (en {name} {version})"
            notes.append(f"la versión {version} es de {name}, no del producto que nombraba")

    if grounding is not None:
        title, removed = strip_ungrounded(title, f"{grounding} {version}")
        if removed:
            if len(title.split()) < MIN_WORDS:
                raise UnfixableTitleError(", ".join(removed))
            what = (
                f"se quitaron las versiones {', '.join(removed)}: no salen"
                if len(removed) > 1
                else f"se quitó la versión {removed[0]}: no sale"
            )
            notes.append(f"{what} de lo observado ni del texto técnico")
    return title, notes


def reviewed(title, component, *, cve_id=None, extra_keys=(), grounding=None):
    """Como ``coherent`` pero sin excepción: ``(título | None, notas)``; ``None`` = usar la regla."""
    try:
        return coherent(title, component, cve_id=cve_id, extra_keys=extra_keys, grounding=grounding)
    except UnfixableTitleError as error:
        return None, [f"«{error}» no corresponde a lo observado y no se arregla por código"]


def grounding_text(asset_id, findings, *extra) -> str:
    """Todo lo que sustenta una versión en un título: los textos técnicos y la evidencia de las
    observaciones, y las versiones del software que el activo tiene registrado."""
    from .models import SoftwareComponent

    parts = [str(text) for text in extra if text]
    for finding in findings:
        parts += [finding.title or "", finding.description or ""]
        if finding.cve_id and finding.cve:
            parts.append(finding.cve.description or "")
        for evidence in finding.evidence.all():
            data = evidence.data or {}
            parts.append(evidence.summary or "")
            parts += [str(data.get(key) or "") for key in ("fix", "affected_range", "version")]
    for name, version in SoftwareComponent.objects.filter(asset_id=asset_id).values_list(
        "name", "version"
    ):
        parts.append(f"{name} {version}")
    return " \n".join(parts)

"""Consolidación: N observaciones (herramientas, CTI, manual) → vulnerabilidades reales del activo.

Fase 4 del plan de consolidación. Reglas deterministas agrupan y pre-juzgan; el LLM local
explica, estima factores y elige el estado; ``apps.scoring`` calcula los dos puntajes. Si el
LLM no responde, las vulnerabilidades existen igual por regla, marcadas «sin evaluar por IA».

Garantías:
- Ninguna vulnerabilidad sin observación existente: las referencias inválidas se descartan y
  el grupo se crea por regla con «requiere verificación».
- Idempotente por ``(activo, clave)``; repetir actualiza, no duplica. Un grupo que pierde todas
  sus observaciones abiertas pasa a «mitigada» con evento (salvo decisión humana previa).
- El estado humano se conserva: la IA actualiza explicación y puntajes, no el estado.
- Lotes: ``DETECTION_CONSOLIDATE_CHUNK`` observaciones por llamada al LLM.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from apps.assets import catalogs
from apps.assets import services as assets_services
from apps.cti.products import product_key
from apps.cti.versions import is_distro_package, precision
from apps.llm.client import register_mock, run_structured
from apps.llm.language import fix_spanish, looks_spanish, non_spanish
from apps.llm.prompts import load_prompt
from apps.llm.schemas import VULN_ASSESSMENT_SCHEMA, VulnAssessmentOutput
from apps.llm.status import active_model
from apps.scoring import services as scoring

from . import components as components_index
from .models import (
    AI_STATUSES,
    OPEN_STATUSES,
    VULN_OPEN_STATUSES,
    Finding,
    FindingSeverity,
    FindingSource,
    StatusSource,
    Vulnerability,
    VulnerabilityEvent,
    VulnerabilityEventKind,
    VulnerabilityStatus,
)

log = logging.getLogger(__name__)

PROMPT_VERSION = "v4"
TASK = "VULN_ASSESSMENT"
TEXT_MAX = 300
LOW_PLAUSIBILITY = 0.3
MISMATCH_PLAUSIBILITY = 0.5  # plantilla cuyo producto no aparece en el software del activo
EXACT_PLAUSIBILITY = 0.8  # versión exacta en rango, SBOM/Grype o varias fuentes, sin LLM
KEV_FLOOR_PLAUSIBILITY = 0.7  # versión exacta en rango + KEV: el modelo no puede bajar de aquí
EXACT_FLOOR_PLAUSIBILITY = 0.6  # versión exacta en rango sin KEV: piso al subirla a «probable»
# Etiquetas de plantilla que nombran una tecnología concreta (si no está en el software
# observado, la observación es poco plausible).
TECH_TAGS = {
    "nextjs": "next.js",
    "wordpress": "wordpress",
    "woocommerce": "woocommerce",
    "drupal": "drupal",
    "joomla": "joomla",
    "laravel": "laravel",
    "django": "django",
    "rails": "rails",
    "spring": "spring",
    "struts": "struts",
    "tomcat": "tomcat",
    "jboss": "jboss",
    "weblogic": "weblogic",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "confluence": "confluence",
    "jira": "jira",
    "exchange": "exchange",
    "sharepoint": "sharepoint",
    "citrix": "citrix",
    "fortinet": "fortinet",
    "f5": "big-ip",
    "vmware": "vmware",
    "magento": "magento",
    "prestashop": "prestashop",
    "grafana": "grafana",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
    "redis": "redis",
    "mongodb": "mongodb",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "samba": "samba",
    "exim": "exim",
    "openssh": "openssh",
    "nginx": "nginx",
    "apache": "apache",
    "iis": "iis",
}
# Debilidades genéricas sin CVE que se agrupan bajo una misma clave.
WEAKNESS_FAMILIES = (
    (
        ("eol", "end-of-life", "outdated", "sin soporte", "end of life", "version"),
        "SOFTWARE_SIN_SOPORTE",
    ),
    (("tls", "ssl", "cipher", "certificate", "certificado"), "TLS_DEBIL"),
    (("header", "cabecera", "hsts", "csp", "x-frame"), "CABECERAS_HTTP"),
    (("default", "credencial", "password", "contraseña", "login"), "CREDENCIALES_POR_DEFECTO"),
    (
        ("exposure", "exposed", "expuesto", "disclosure", "listing", "panel", "phpinfo", "unauth"),
        "EXPOSICION_DE_INFORMACION",
    ),
)


# Nombre en español de cada familia de debilidad, para el título determinista.
WEAKNESS_LABELS = {
    "SOFTWARE_SIN_SOPORTE": "Software sin soporte",
    "TLS_DEBIL": "Configuración TLS débil",
    "CABECERAS_HTTP": "Cabeceras de seguridad HTTP ausentes",
    "CREDENCIALES_POR_DEFECTO": "Credenciales por defecto",
    "EXPOSICION_DE_INFORMACION": "Exposición de información",
}


def rule_title(key, lead):
    """Título determinista en español cuando la IA no dio uno válido.

    «CVE-… en producto versión» si se conoce el software; si no, el CVE con el nombre de la
    plantilla u observación (nombre propio, se conserva). Para las debilidades sin CVE, la familia.
    """
    product = (
        lead.component.label if lead.component else (_template_meta(lead).get("product") or "")
    )
    if key.startswith("CVE-"):
        if product:
            return f"{key} en {product}"[:160]
        title = clean(lead.title, 120) if lead.title else ""
        if not title:
            return key
        # La observación de Grype ya se titula «CVE-… en producto»: no repetir la clave.
        return title[:160] if title.upper().startswith(key.upper()) else f"{key} · {title}"[:160]
    parts = key.split(":")
    label = WEAKNESS_LABELS.get(parts[1] if len(parts) > 1 else "")
    if label:
        return f"{label} en {product}"[:160] if product else label
    return clean(lead.title, 160) or key


def technical_description(findings):
    """Texto técnico original (NVD, luego la herramienta), sin redactar."""
    for f in findings:
        if f.cve_id and f.cve and f.cve.description:
            return clean(f.cve.description, 2000)
    for f in findings:
        if f.description:
            return clean(f.description, 2000)
    return ""


def _slug(text, limit=60):
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return text[:limit] or "debilidad"


def clean(value, limit=TEXT_MAX):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


# --------------------------------------------------------------------------
# Entrada: observaciones abiertas, software, contexto
# --------------------------------------------------------------------------


@dataclass
class Group:
    key: str
    findings: list = field(default_factory=list)
    rule_flags: list = field(default_factory=list)
    plausibility_cap: float = 1.0
    # Estado máximo que las reglas permiten afirmar ("" = sin tope).
    status_cap: str = ""
    # Estado mínimo cuando la evidencia es exacta (SBOM/Grype, versión exacta, varias fuentes).
    status_floor: str = ""
    exact_evidence: bool = False

    @property
    def lead(self):
        # CTI o CVE primero; luego la observación de mayor severidad.
        order = {FindingSource.CTI_MATCH: 0, FindingSource.GRYPE: 1, FindingSource.NUCLEI: 2}
        return sorted(
            self.findings,
            key=lambda f: (min(order.get(s, 3) for s in (f.sources or ["x"])), f.severity),
        )[0]

    @property
    def cve(self):
        return next((f.cve for f in self.findings if f.cve_id), None)

    @property
    def in_kev(self):
        return any(f.in_kev for f in self.findings)


def _template_meta(finding):
    for ev in finding.evidence.all():
        meta = (ev.data or {}).get("template")
        if meta:
            return meta
    return {}


def _weakness_key(finding, meta):
    text = " ".join(
        [finding.vulnerability_id, finding.title, " ".join(meta.get("tags") or [])]
    ).lower()
    for needles, family in WEAKNESS_FAMILIES:
        if any(n in text for n in needles):
            product = meta.get("product") or (
                finding.component.product_key if finding.component else ""
            )
            return f"WEAKNESS:{family}" + (f":{_slug(product)}" if product else "")
    return f"WEAKNESS:{_slug(finding.vulnerability_id)}"


def _tech_mismatch(meta, software_keys, software_text, text=""):
    """Producto o tecnología que la plantilla declara (o que nombra el título) ausente del
    software observado del activo."""
    declared = []
    product = (meta.get("product") or "").lower()
    if product:
        declared.append(product)
    for tag in meta.get("tags") or []:
        if tag.lower() in TECH_TAGS:
            declared.append(TECH_TAGS[tag.lower()])
    if not declared and text:
        # Evidencia sin metadatos: «Next.js Middleware Bypass», «WooCommerce plugin…».
        words = set(re.findall(r"[a-z0-9.+-]+", text.lower()))
        for tag, name in TECH_TAGS.items():
            if tag in words or name in words or name.replace(".", "") in words:
                declared.append(name)
    if not declared:
        return None
    for name in declared:
        key = product_key(name)
        if key and key in software_keys:
            return None
        if _slug(name) in software_text:
            return None
    return sorted(set(declared))


# Observaciones de nuclei que solo dicen qué tecnología o versión hay: contexto, no un fallo.
INFORMATIONAL_PATTERNS = (
    "tech-detect",
    "wappalyzer",
    "detect",
    "fingerprint",
    "favicon",
    # Patrones regex genéricos (PII, secretos) sin comparador específico: disparan con horas,
    # IPs o respuestas de terceros; son contexto, no una vulnerabilidad.
    "secrets-patterns",
    "patterns-pii",
)


def _informational_q():
    from django.db.models import Q

    text = Q()
    for pattern in INFORMATIONAL_PATTERNS:
        text |= Q(vulnerability_id__icontains=pattern) | Q(title__icontains=pattern)
    return Q(severity=FindingSeverity.INFO, cve__isnull=True) & text


def is_informational(finding):
    """Detección de tecnología o versión sin CVE (p. ej. «Wappalyzer», «nginx version detect»)."""
    if finding.severity != FindingSeverity.INFO or finding.cve_id:
        return False
    text = f"{finding.vulnerability_id} {finding.title}".lower()
    return any(p in text for p in INFORMATIONAL_PATTERNS)


def consolidable(qs):
    """Observaciones que pueden ser una vulnerabilidad: fuera las informativas (ver arriba)."""
    return qs.exclude(_informational_q())


def informational(asset_id):
    return Finding.objects.filter(asset_id=asset_id, status__in=OPEN_STATUSES).filter(
        _informational_q()
    )


def build_groups(asset_id):
    """Agrupa las observaciones abiertas del activo por CVE o familia de debilidad."""
    components = components_index.current_components([asset_id])
    software_keys = {c.product_key for c in components if c.product_key}
    software_text = " ".join(_slug(f"{c.name} {c.vendor}", 200) for c in components)
    groups: dict[str, Group] = {}
    qs = consolidable(
        Finding.objects.filter(asset_id=asset_id, status__in=OPEN_STATUSES)
        .select_related("cve", "component")
        .prefetch_related("evidence")
    )
    for finding in qs:
        meta = _template_meta(finding)
        key = finding.cve_id or (
            finding.vulnerability_id.upper()
            if finding.vulnerability_id.upper().startswith("CVE-")
            else _weakness_key(finding, meta)
        )
        group = groups.setdefault(key, Group(key))
        group.findings.append(finding)
        mismatch = _tech_mismatch(
            meta, software_keys, software_text, f"{finding.vulnerability_id} {finding.title}"
        )
        sources = set(finding.sources or [])
        if mismatch and FindingSource.CTI_MATCH not in sources:
            # La plantilla habla de un producto que nadie vio en el activo. nmap no ve librerías
            # ni frameworks (PHPUnit, Next.js), así que es duda, no descarte: queda en verificación.
            _flag(group, f"software no observado: {', '.join(mismatch)}", MISMATCH_PLAUSIBILITY)
            group.status_cap = VulnerabilityStatus.NEEDS_VERIFICATION
        component_version = finding.component.version if finding.component else ""
        if sources == {FindingSource.CTI_MATCH} and component_version:
            if precision(component_version) == "IMPRECISE":
                _flag(group, f"versión imprecisa según nmap: «{component_version}»", 0.5)
                group.status_cap = VulnerabilityStatus.NEEDS_VERIFICATION
            elif is_distro_package(component_version):
                _flag(
                    group,
                    f"paquete de distribución «{component_version}»: posible parche retroportado",
                    0.6,
                )
                group.status_cap = VulnerabilityStatus.NEEDS_VERIFICATION
            elif finding.confidence != "LOW":
                group.exact_evidence = True  # versión exacta del producto dentro del rango
        if FindingSource.GRYPE in sources:
            group.exact_evidence = True  # el SBOM declara la librería y su versión exacta
    for group in groups.values():
        sources = {s for f in group.findings for s in (f.sources or [])}
        if len(sources) > 1:
            group.rule_flags.append(f"coinciden {len(sources)} fuentes")
            group.plausibility_cap = 1.0
            group.status_cap = ""  # otra fuente lo vio de verdad: la duda de versión se disipa
            group.exact_evidence = True
        if group.exact_evidence and not group.status_cap:
            group.status_floor = VulnerabilityStatus.LIKELY
            group.rule_flags.append("versión exacta en el rango afectado")
        if group.in_kev:
            group.rule_flags.append("en KEV: explotación activa conocida")
    return list(groups.values()), components


def _flag(group, flag, cap):
    if flag not in group.rule_flags:
        group.rule_flags.append(flag)
    group.plausibility_cap = min(group.plausibility_cap, cap)


def _observation_payload(index, finding):
    meta = _template_meta(finding)
    ev = finding.evidence.all()[:1]
    return {
        "id": index,
        "ref": finding.vulnerability_id,
        "title": clean(finding.title, 160),
        "severity": finding.severity,
        "sources": finding.sources,
        "component": finding.component.label if finding.component else None,
        "cvss": finding.cvss_score,
        "epss": finding.epss_score,
        "kev": finding.in_kev,
        "description": clean(finding.description, 240),
        "evidence": clean(ev[0].summary, 200) if ev else "",
        "template": {
            k: (v if not isinstance(v, str) else clean(v, 160))
            for k, v in meta.items()
            if k in ("tags", "product", "vendor", "cwe", "remediation", "impact")
        }
        or None,
    }


def build_payload(asset_id, groups, components):
    from .profile import get_profile

    context = assets_services.get_asset_context(asset_id)
    asset = assets_services.get_asset_summary(asset_id)
    profile = get_profile()
    observations, index = [], {}
    for group in groups:
        for finding in group.findings:
            index[finding.pk] = len(observations) + 1
            observations.append(_observation_payload(index[finding.pk], finding))
    return {
        "organization": {
            "sector": clean(profile.sector, 120),
            "description": clean(profile.description, 400),
        },
        "asset": {
            "name": clean(asset["name"], 120),
            "type": catalogs.label(catalogs.ASSET_TYPE, asset["asset_type"]) or asset["asset_type"],
            "description": clean(asset.get("description"), 300),
            # Etiquetas legibles, no códigos: el modelo copia en sus textos lo que recibe.
            "business_role": catalogs.label(catalogs.BUSINESS_ROLE, context.business_role) or None,
            "environment": catalogs.label(catalogs.ENVIRONMENT, context.environment) or None,
            "criticality": context.criticality,
            "exposure": context.exposure,
            "data_classification": context.data_classification,
            "data_categories": list(context.data_categories),
        },
        "software": [c.label for c in components[:40]],
        "rule_groups": [
            {
                "key": g.key,
                "observations": [index[f.pk] for f in g.findings],
                "rule_flags": g.rule_flags,
                "rule_plausibility_cap": g.plausibility_cap,
                "rule_status_cap": g.status_cap or None,
                "rule_status_floor": g.status_floor or None,
            }
            for g in groups
        ],
        "observations": observations,
    }, index


def render_user_message(data):
    import json

    payload = json.dumps(data, ensure_ascii=False, indent=1, default=str)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")
    return f"<activo>\n{payload}\n</activo>"


# --------------------------------------------------------------------------
# Salida por regla y simulada
# --------------------------------------------------------------------------


def rule_item(group, index):
    lead = group.lead
    low = group.plausibility_cap <= LOW_PLAUSIBILITY
    if lead.cve_id and lead.cve and lead.cve.description:
        summary = clean(lead.cve.description, 400)
    else:
        summary = clean(lead.description or lead.title, 400)
    meta = _template_meta(lead)
    actions = []
    if meta.get("remediation"):
        actions.append(clean(meta["remediation"], 200))
    if lead.component and lead.component.version:
        actions.append(f"Actualizar {lead.component.label} a una versión corregida.")
    if not actions:
        actions.append("Verificar la observación en el activo y aplicar el parche del fabricante.")
    if low:
        plausibility, status = group.plausibility_cap, "LIKELY_FALSE_POSITIVE"
    elif group.exact_evidence and not group.status_cap:
        plausibility, status = min(EXACT_PLAUSIBILITY, group.plausibility_cap), "LIKELY"
    else:
        plausibility, status = min(0.5, group.plausibility_cap), "NEEDS_VERIFICATION"
    return {
        "observations": [index[f.pk] for f in group.findings],
        "title": rule_title(group.key, lead),
        # Sin IA no hay descripción en español: el texto técnico original va aparte
        # (``technical_description``) y ``VULN_DESCRIBE`` redacta después.
        "summary": "" if not looks_spanish(summary) else summary,
        "business_impact": "",
        "actions": actions[:5],
        "plausibility": plausibility,
        "exploitability": "HIGH" if group.in_kev else "MEDIUM",
        "data_sensitivity": "MEDIUM",
        "business_impact_level": "MEDIUM",
        "compensating_controls": "NONE",
        "adjustment": 0,
        "adjustment_reason": "",
        "status": status,
    }


@register_mock(TASK)
def mock_assessment(request_payload):
    """``LLM_MOCK_MODE=1``: agrupa como las reglas y redacta de forma determinista."""
    items = []
    by_id = {o["id"]: o for o in request_payload["observations"]}
    for group in request_payload["rule_groups"]:
        lead = by_id[group["observations"][0]]
        cap = group["rule_plausibility_cap"]
        low = cap <= LOW_PLAUSIBILITY
        items.append(
            {
                "observations": group["observations"],
                "title": lead["title"],
                "summary": f"Respuesta simulada (LLM_MOCK_MODE=1): {lead['title']}.",
                "business_impact": "Impacto simulado en el negocio.",
                "actions": ["Aplicar el parche del fabricante.", "Verificar tras el cambio."],
                "plausibility": cap if low else 0.9,
                "exploitability": "HIGH" if lead["kev"] else "MEDIUM",
                "data_sensitivity": "MEDIUM",
                "business_impact_level": "HIGH",
                "compensating_controls": "NONE",
                "adjustment": 0,
                "adjustment_reason": "",
                "status": "LIKELY_FALSE_POSITIVE" if low else "CONFIRMED",
            }
        )
    return {"vulnerabilities": items}


# --------------------------------------------------------------------------
# Consolidación
# --------------------------------------------------------------------------


def _event(vuln, kind, message="", actor=None, **data):
    VulnerabilityEvent.objects.create(
        vulnerability=vuln,
        kind=kind,
        occurred_at=timezone.now(),
        actor=actor,
        message=message[:500],
        data=data,
    )


def _validate(parsed, groups, index):
    """Casa cada vulnerabilidad del modelo con observaciones reales; devuelve (items, rechazos).

    Un ítem se queda con las referencias válidas; sin ninguna, se rechaza. Las observaciones que
    el modelo no referenció se cubren por regla con su grupo.
    """
    valid_ids = set(index.values())
    by_index = {i: pk for pk, i in index.items()}
    group_of = {f.pk: g for g in groups for f in g.findings}
    items, rejected, covered = [], [], set()
    for item in parsed.get("vulnerabilities", []):
        refs = [r for r in item["observations"] if r in valid_ids and r not in covered]
        if not refs:
            rejected.append({"title": item.get("title"), "observations": item["observations"]})
            continue
        covered.update(refs)
        # Una vulnerabilidad por (activo, CVE): si el modelo juntó varios CVE del mismo producto
        # en un solo ítem («Vulnerabilidades en OpenSSH…»), se separa por grupo con el mismo texto;
        # si no, el CVE «absorbido» quedaría huérfano y se cerraría como mitigado.
        by_group: dict[str, list] = {}
        for ref in refs:
            group = group_of.get(by_index[ref])
            by_group.setdefault(group.key if group else "", []).append(ref)
        split = len(by_group) > 1
        for key, part in by_group.items():
            extra = {"split_from": item.get("title", "")} if split and key else {}
            items.append(
                {
                    **item,
                    **extra,
                    "observations": part,
                    "finding_pks": [by_index[r] for r in part],
                }
            )
    for group in groups:
        missing = [f for f in group.findings if index[f.pk] not in covered]
        if missing:
            sub = Group(
                group.key,
                missing,
                list(group.rule_flags),
                group.plausibility_cap,
                group.status_cap,
                group.status_floor,
                group.exact_evidence,
            )
            item = rule_item(sub, index)
            items.append({**item, "finding_pks": [f.pk for f in missing], "_by_rule": True})
            covered.update(item["observations"])
    return items, rejected


def _key_for(item, groups_by_pk):
    """Clave estable de la vulnerabilidad: el CVE del grupo de su observación principal."""
    for pk in item["finding_pks"]:
        group = groups_by_pk.get(pk)
        if group is not None:
            return group.key
    return f"WEAKNESS:{_slug(item['title'])}"


def _apply_item(asset_id, item, group, context, *, by_rule, log_obj, now):
    findings = list(Finding.objects.filter(pk__in=item["finding_pks"]).select_related("cve"))
    if not findings:
        return None
    cvss = max((f.cvss_score for f in findings if f.cvss_score is not None), default=None)
    epss = max((f.epss_score for f in findings if f.epss_score is not None), default=None)
    in_kev = any(f.in_kev for f in findings)
    kev_due = next((f.kev_due_at for f in findings if f.kev_due_at), None)
    lead = sorted(findings, key=lambda f: scoring.SEVERITY_SCORE.get(f.severity, 0), reverse=True)[
        0
    ]
    plausibility = min(float(item["plausibility"]), group.plausibility_cap if group else 1.0)
    tech = scoring.technical_score(cvss=cvss, epss=epss, in_kev=in_kev, severity=lead.severity)
    ctx = scoring.contextual_score(
        technical=tech.score,
        criticality=context.criticality,
        exposure=context.exposure,
        data_classification=context.data_classification,
        plausibility=plausibility,
        exploitability=item["exploitability"],
        data_sensitivity=item["data_sensitivity"],
        business_impact_level=item["business_impact_level"],
        compensating_controls=item["compensating_controls"],
        adjustment=item.get("adjustment", 0),
        in_kev=in_kev,
        epss=epss,
    )
    status = item["status"]
    if plausibility <= LOW_PLAUSIBILITY and status in ("CONFIRMED", "LIKELY"):
        status = VulnerabilityStatus.LIKELY_FALSE_POSITIVE
    elif group and group.status_cap and status in ("CONFIRMED", "LIKELY"):
        status = group.status_cap
    elif group and group.status_floor and status == VulnerabilityStatus.NEEDS_VERIFICATION:
        # Versión exacta del producto dentro del rango afectado (o SBOM, o varias fuentes) y el
        # modelo aun así duda: la evidencia manda y la vulnerabilidad queda «probable». Sin el
        # piso, cientos de casos con la versión exacta en rango se quedaban «por verificar» sin
        # que nadie pudiera verificarlos. Piso de plausibilidad acotado para que el puntaje no
        # contradiga el estado; con KEV el piso es más alto.
        status = group.status_floor
        plausibility = max(
            plausibility, KEV_FLOOR_PLAUSIBILITY if group.in_kev else EXACT_FLOOR_PLAUSIBILITY
        )
    elif (
        group
        and group.status_floor
        and group.in_kev
        and status == VulnerabilityStatus.LIKELY_FALSE_POSITIVE
    ):
        # Versión exacta en el rango afectado y explotación activa conocida (KEV): la duda del
        # modelo no basta para descartarla. Piso acotado, como las anclas de riesgo.
        status = group.status_floor
        plausibility = max(plausibility, KEV_FLOOR_PLAUSIBILITY)
    cve = next((f.cve for f in findings if f.cve_id), None)
    key = group.key if group else _key_for(item, {})
    # Textos: la IA escribe para la persona, así que deben estar en español. Lo que venga en
    # inglés se descarta (el título lo pone una regla y la descripción la redacta
    # ``VULN_DESCRIBE`` aparte); la valoración y los factores del modelo se conservan.
    # Un ítem que el modelo fusionó («Vulnerabilidades en Apache…») se partió por CVE: su texto es
    # genérico, así que cada CVE toma título por regla y se redacta aparte, uno por uno.
    split = bool(item.get("split_from"))
    title = clean(item.get("title"), 160)
    if by_rule or split or not title or not looks_spanish(title):
        title = rule_title(key, lead)
    discarded = non_spanish(
        item.get("summary"), item.get("business_impact"), *(item.get("actions") or [])
    )
    described = bool(item.get("summary")) and not by_rule and not discarded and not split
    vuln, created = Vulnerability.objects.get_or_create(
        asset_id=asset_id,
        key=key,
        defaults={
            "title": title[:200],
            "severity": lead.severity,
            "first_detected_at": min(f.first_detected_at for f in findings),
            "last_seen_at": now,
            "status": status,
            "status_source": StatusSource.RULE if by_rule else StatusSource.AI,
            "status_at": now,
        },
    )
    previous_status = vuln.status
    vuln.cve = cve
    vuln.component = lead.component
    keep_text = vuln.summary and vuln.description_source in (StatusSource.AI, StatusSource.HUMAN)
    if described:
        vuln.title = title[:200]
        vuln.summary = fix_spanish(item["summary"])
        vuln.business_impact = fix_spanish(item.get("business_impact", ""))
        vuln.actions = [fix_spanish(a) for a in (item.get("actions") or [])]
        vuln.description_source = StatusSource.AI
        vuln.described_at = now
    elif not keep_text:
        # Nada redactado que conservar: título por regla y acciones por regla si las hay.
        vuln.title = title[:200]
        vuln.summary, vuln.business_impact, vuln.description_source = "", "", ""
        vuln.actions = [] if discarded else list(item.get("actions") or [])
    vuln.technical_description = technical_description(findings)
    vuln.severity = scoring.severity_for(ctx.score)
    vuln.technical_score = tech.score
    vuln.contextual_score = ctx.score
    vuln.score_breakdown = {"technical": tech.breakdown, "contextual": ctx.breakdown}
    vuln.algorithm_version = scoring.ALGORITHM_VERSION
    vuln.plausibility = round(plausibility, 2)
    vuln.factors = {
        "exploitability": item["exploitability"],
        "data_sensitivity": item["data_sensitivity"],
        "business_impact_level": item["business_impact_level"],
        "compensating_controls": item["compensating_controls"],
    }
    vuln.adjustment = ctx.breakdown["adjustment"]
    vuln.adjustment_reason = fix_spanish(item.get("adjustment_reason", ""))[:255]
    vuln.rule_flags = list(group.rule_flags) if group else []
    vuln.assessment_source = StatusSource.RULE if by_rule else StatusSource.AI
    vuln.inference = log_obj if not by_rule else None
    vuln.model = (log_obj.model_responded or log_obj.model) if log_obj and not by_rule else ""
    vuln.prompt_version = PROMPT_VERSION if not by_rule else ""
    vuln.assessed_at = now
    vuln.cvss_score, vuln.epss_score, vuln.in_kev, vuln.kev_due_at = cvss, epss, in_kev, kev_due
    vuln.environment = context.environment or ""
    vuln.last_seen_at = now
    reopened = False
    if not created and not vuln.human_locked:
        if vuln.status in (VulnerabilityStatus.MITIGATED,):
            reopened = True
        vuln.status = status
        vuln.status_source = StatusSource.RULE if by_rule else StatusSource.AI
        vuln.status_at = now
        vuln.resolved_at = None
    vuln.save()
    Finding.objects.filter(pk__in=[f.pk for f in findings]).update(consolidated=vuln)
    if created:
        _event(
            vuln,
            VulnerabilityEventKind.CREATED,
            f"Consolidada a partir de {len(findings)} observación(es)",
            observations=[f.vulnerability_id for f in findings],
            by_rule=by_rule,
        )
    _event(
        vuln,
        VulnerabilityEventKind.ASSESSED,
        "Evaluada por regla (sin IA)" if by_rule else f"Evaluada por IA ({vuln.model})",
        technical=tech.score,
        contextual=ctx.score,
        plausibility=vuln.plausibility,
        algorithm_version=scoring.ALGORITHM_VERSION,
    )
    if discarded:
        _event(
            vuln,
            VulnerabilityEventKind.ASSESSED,
            "La IA respondió en inglés: el texto se descartó y se redactará de nuevo en español",
            discarded=[d[:120] for d in discarded],
        )
    if reopened:
        _event(vuln, VulnerabilityEventKind.REOPENED, "Volvió a observarse")
    if previous_status != vuln.status and not created:
        _event(
            vuln,
            VulnerabilityEventKind.STATUS_AI,
            f"{VulnerabilityStatus(previous_status).label} → {vuln.get_status_display()}",
            by_rule=by_rule,
        )
    return vuln


def _resolve_orphans(asset_id, touched_ids, now):
    """Vulnerabilidades que ya no tienen observación abierta: mitigadas (si nadie decidió otra cosa)."""
    resolved = 0
    qs = Vulnerability.objects.filter(asset_id=asset_id).exclude(pk__in=touched_ids)
    for vuln in qs:
        if vuln.human_locked or not vuln.is_open:
            continue
        vuln.status = VulnerabilityStatus.MITIGATED
        vuln.status_source = StatusSource.RULE
        vuln.status_at = now
        vuln.resolved_at = now
        vuln.save(update_fields=["status", "status_source", "status_at", "resolved_at"])
        _event(vuln, VulnerabilityEventKind.RESOLVED, "Ninguna fuente la observa ya")
        resolved += 1
    return resolved


@dataclass(frozen=True)
class ConsolidationResult:
    groups: int
    vulnerabilities: int
    by_rule: int
    rejected: int
    resolved: int
    llm_calls: int
    llm_ok: bool
    reason: str = ""


def consolidate_asset(asset_id, *, requested_by=None, reason="", use_llm=True):
    """Corre la consolidación completa del activo. Síncrona; la encola ``request_consolidation``."""
    from apps.llm.status import active_model_ready

    now = timezone.now()
    # Las informativas no pertenecen a ninguna vulnerabilidad (aunque antes se hubieran ligado).
    informational(asset_id).filter(consolidated__isnull=False).update(consolidated=None)
    groups, components = build_groups(asset_id)
    context = assets_services.get_asset_context(asset_id)
    groups_by_pk = {f.pk: g for g in groups for f in g.findings}
    chunk_size = max(1, int(getattr(settings, "DETECTION_CONSOLIDATE_CHUNK", 25)))
    touched, by_rule_count, rejected_total, calls, llm_ok = [], 0, 0, 0, True
    use_llm = use_llm and (getattr(settings, "LLM_MOCK_MODE", False) or active_model_ready())
    # Lotes: grupos completos hasta ``chunk_size`` observaciones por llamada.
    chunks, current, count = [], [], 0
    for group in groups:
        if current and count + len(group.findings) > chunk_size:
            chunks.append(current)
            current, count = [], 0
        current.append(group)
        count += len(group.findings)
    if current:
        chunks.append(current)
    for chunk in chunks:
        data, index = build_payload(asset_id, chunk, components)
        log_obj = None
        if use_llm:
            calls += 1
            log_obj = run_structured(
                task=TASK,
                messages=[
                    {"role": "system", "content": load_prompt("vuln_assessment", PROMPT_VERSION)},
                    {"role": "user", "content": render_user_message(data)},
                ],
                schema=VULN_ASSESSMENT_SCHEMA,
                validator=VulnAssessmentOutput,
                model=active_model(),
                prompt_version=PROMPT_VERSION,
                request_payload=data,
                object_ref=f"assets.Asset:{asset_id}",
                requested_by=requested_by,
            )
        if log_obj is not None and log_obj.parsed_ok:
            items, rejected = _validate(log_obj.parsed, chunk, index)
            rejected_total += len(rejected)
            if rejected:
                log.warning("consolidación %s: %d referencia(s) inválidas", asset_id, len(rejected))
        else:
            llm_ok = False
            items = [
                {**rule_item(g, index), "finding_pks": [f.pk for f in g.findings], "_by_rule": True}
                for g in chunk
            ]
        with transaction.atomic():
            for item in items:
                by_rule = bool(item.get("_by_rule")) or log_obj is None or not log_obj.parsed_ok
                group = groups_by_pk.get(item["finding_pks"][0])
                vuln = _apply_item(
                    asset_id, item, group, context, by_rule=by_rule, log_obj=log_obj, now=now
                )
                if vuln is not None:
                    touched.append(vuln.pk)
                    by_rule_count += int(by_rule)
    with transaction.atomic():
        resolved = _resolve_orphans(asset_id, touched, now)
    llm_ok = llm_ok and use_llm
    cache.set(_last_key(asset_id), now.isoformat(), None)
    # Fase 5: las vulnerabilidades consolidadas se expresan como riesgos (ISO/IEC 27005).
    try:
        from . import risks

        risks.derive_risks(asset_id, requested_by=requested_by, use_llm=use_llm)
    except Exception:  # pragma: no cover - un fallo en riesgos no deshace la consolidación
        log.exception("derivación de riesgos del activo %s", asset_id)
    # Lo que quedó sin descripción en español (por regla, o inglés descartado) se redacta aparte,
    # una vulnerabilidad por llamada, de mayor a menor puntaje.
    if use_llm:
        from . import descriptions

        descriptions.queue_missing(asset_id, requested_by=requested_by)
    return ConsolidationResult(
        len(groups), len(touched), by_rule_count, rejected_total, resolved, calls, llm_ok, reason
    )


# --------------------------------------------------------------------------
# Disparadores con retardo
# --------------------------------------------------------------------------


def _pending_key(asset_id):
    return f"detection:consolidate:pending:{asset_id}"


def _last_key(asset_id):
    return f"detection:consolidate:last:{asset_id}"


def rescore_asset(asset_id) -> int:
    """Recalcula el puntaje contextual de las vulnerabilidades abiertas del activo con la versión
    actual del algoritmo y los factores ya guardados (sin LLM). Devuelve cuántas cambiaron."""
    context = assets_services.get_asset_context(asset_id)
    changed = 0
    for vuln in Vulnerability.objects.filter(asset_id=asset_id, status__in=VULN_OPEN_STATUSES):
        factors = vuln.factors or {}
        ctx = scoring.contextual_score(
            technical=vuln.technical_score or 0.0,
            criticality=context.criticality,
            exposure=context.exposure,
            data_classification=context.data_classification,
            plausibility=vuln.plausibility,
            exploitability=factors.get("exploitability", "MEDIUM"),
            data_sensitivity=factors.get("data_sensitivity"),
            business_impact_level=factors.get("business_impact_level"),
            compensating_controls=factors.get("compensating_controls", "NONE"),
            adjustment=vuln.adjustment,
            in_kev=vuln.in_kev,
            epss=vuln.epss_score,
        )
        if ctx.score == vuln.contextual_score and vuln.algorithm_version == ctx.algorithm_version:
            continue
        vuln.contextual_score = ctx.score
        vuln.severity = scoring.severity_for(ctx.score)
        vuln.score_breakdown = {**(vuln.score_breakdown or {}), "contextual": ctx.breakdown}
        vuln.algorithm_version = ctx.algorithm_version
        vuln.save(
            update_fields=[
                "contextual_score",
                "severity",
                "score_breakdown",
                "algorithm_version",
                "updated_at",
            ]
        )
        changed += 1
    return changed


def request_consolidation(asset_id, *, reason="", requested_by=None, delay=None):
    """Encola la consolidación del activo agrupando disparadores cercanos en una sola corrida."""
    from django.db import transaction as tx

    from .tasks import consolidate_asset as task

    if not Finding.objects.filter(asset_id=asset_id).exists():
        return False
    delay = int(getattr(settings, "DETECTION_CONSOLIDATE_DELAY_S", 20)) if delay is None else delay
    key = _pending_key(asset_id)
    if not cache.add(key, reason or "pendiente", timeout=delay + 60):
        return False  # ya hay una corrida programada que recogerá este cambio
    user_id = getattr(requested_by, "pk", None)
    tx.on_commit(
        lambda: task.apply_async(
            args=[str(asset_id)], kwargs={"reason": reason, "user_id": user_id}, countdown=delay
        )
    )
    return True


def is_pending(asset_id):
    return cache.get(_pending_key(asset_id)) is not None


def clear_pending(asset_id):
    cache.delete(_pending_key(asset_id))


def last_consolidated_at(asset_id):
    from datetime import datetime

    value = cache.get(_last_key(asset_id))
    if value:
        return datetime.fromisoformat(value)
    vuln = Vulnerability.objects.filter(asset_id=asset_id).order_by("-assessed_at").first()
    return vuln.assessed_at if vuln else None


# --------------------------------------------------------------------------
# Decisión humana
# --------------------------------------------------------------------------

RESOLVED_STATUSES = (
    VulnerabilityStatus.MITIGATED,
    VulnerabilityStatus.FALSE_POSITIVE,
    VulnerabilityStatus.ACCEPTED,
)
HUMAN_STATUSES = (
    VulnerabilityStatus.CONFIRMED,
    VulnerabilityStatus.NEEDS_VERIFICATION,
    VulnerabilityStatus.FALSE_POSITIVE,
    VulnerabilityStatus.MITIGATED,
    VulnerabilityStatus.ACCEPTED,
)


def set_status(vulnerability_id, *, user, status, note=""):
    """Una persona corrige el estado; desde entonces la IA no lo vuelve a tocar."""
    if status not in HUMAN_STATUSES:
        raise ValueError("Estado no permitido para una persona.")
    note = (note or "").strip()
    if status in (VulnerabilityStatus.ACCEPTED, VulnerabilityStatus.FALSE_POSITIVE) and not note:
        raise ValueError("Aceptar el riesgo o marcar falso positivo exige una nota.")
    now = timezone.now()
    with transaction.atomic():
        vuln = Vulnerability.objects.select_for_update().get(pk=vulnerability_id)
        previous = vuln.get_status_display()
        vuln.status = status
        vuln.status_source = StatusSource.HUMAN
        vuln.status_by = user
        vuln.status_at = now
        vuln.status_note = note
        vuln.resolved_at = None if vuln.is_open else now
        vuln.save()
        _event(
            vuln,
            VulnerabilityEventKind.STATUS_HUMAN,
            f"{previous} → {vuln.get_status_display()}" + (f": {note}" if note else ""),
            actor=user,
        )
    return vuln


def release_to_ai(vulnerability_id, *, user):
    """Devuelve el estado a la IA (la próxima consolidación lo fija de nuevo)."""
    with transaction.atomic():
        vuln = Vulnerability.objects.select_for_update().get(pk=vulnerability_id)
        vuln.status_source = StatusSource.AI
        vuln.status_by = None
        vuln.status_note = ""
        vuln.save(update_fields=["status_source", "status_by", "status_note"])
        _event(vuln, VulnerabilityEventKind.NOTE, "El estado vuelve a decidirlo la IA", actor=user)
    return vuln


def add_note(vulnerability_id, *, user, text):
    text = (text or "").strip()
    if not text:
        raise ValueError("La nota no puede estar vacía.")
    vuln = Vulnerability.objects.get(pk=vulnerability_id)
    _event(vuln, VulnerabilityEventKind.NOTE, text, actor=user)
    return vuln


def summary(asset_id=None):
    qs = Vulnerability.objects.all()
    if asset_id:
        qs = qs.filter(asset_id=asset_id)
    open_qs = qs.filter(status__in=(s for s in VulnerabilityStatus if s in AI_STATUSES))
    return {
        "open": open_qs.count(),
        "confirmed": open_qs.filter(status=VulnerabilityStatus.CONFIRMED).count(),
        "critical": open_qs.filter(severity=FindingSeverity.CRITICAL).count(),
        "high": open_qs.filter(severity=FindingSeverity.HIGH).count(),
        "in_kev": open_qs.filter(in_kev=True).count(),
        "needs_verification": open_qs.filter(status=VulnerabilityStatus.NEEDS_VERIFICATION).count(),
        "likely_fp": open_qs.filter(status=VulnerabilityStatus.LIKELY_FALSE_POSITIVE).count(),
        # Lo que se cerró en los últimos siete días (mitigada, falso positivo o riesgo aceptado):
        # la vista «qué se resolvió y por qué».
        "resolved_week": qs.filter(
            status__in=RESOLVED_STATUSES,
            status_at__gte=timezone.now() - timedelta(days=7),
        ).count(),
    }

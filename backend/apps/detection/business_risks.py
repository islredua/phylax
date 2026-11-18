"""Riesgos de la organización: una consecuencia sobre una función de negocio.

Un riesgo es lo que la organización puede perder (fuga de información, alteración, interrupción)
en una función de negocio (Pagos, API, Correo…), y reúne los escenarios (``Risk``) de los activos
que cumplen esa función. Es el nivel en que las normas le hablan a quien decide: ISO/IEC
27005:2022 separa los escenarios por evento de los escenarios por activo, NIST IR 8286 agrega
los riesgos de los sistemas en el registro de la organización y MAGERIT presenta a la dirección
el riesgo repercutido sobre los servicios.

No tiene tabla propia: se arma con los escenarios abiertos que hay. Así no hay nada que
sincronizar cuando un activo cambia de función o un escenario se cierra, y el eje (hoy la
función de negocio del activo) se puede cambiar sin migrar datos. Dos reglas:

- **El nivel es el de su peor escenario.** No se promedia ni se suma: un activo en nivel crítico
  no se compensa con tres en nivel bajo.
- **Las decisiones viven en los escenarios.** Tratamiento, responsable y plazo son de cada
  escenario; decidir el riesgo es decidir a la vez sus escenarios abiertos. Un activo que entra
  después llega sin decidir: nadie aceptó lo que todavía no existía.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from django.db.models import Count, Q
from django.urls import reverse

from apps.assets import catalogs
from apps.assets.enums import AssetStatus
from apps.assets.models import Asset

from . import business_roles, policy, responsibles, risks
from .models import RISK_OPEN_STATUSES, Risk, RiskConsequence, RiskLevel, RiskTreatment

# En la URL, la función de los activos que no la tienen definida.
NO_ROLE = "-"
NO_ROLE_LABEL = "activos sin función de negocio"
# «Fuga de información en Otro» no dice nada: el cajón de sastre del catálogo se nombra así.
OTHER_ROLE, OTHER_ROLE_LABEL = "OTRO", "otros activos"
NO_ROLE_HELP = (
    "Activos a los que todavía no se les ha dado una función de negocio. Al dársela, sus riesgos "
    "se suman a los de esa función."
)
# Los activos que el inventario tampoco lista: no cuentan como «activos con esta función».
OUT_OF_INVENTORY = (AssetStatus.RETIRED, AssetStatus.IGNORED)
CONSEQUENCE_LABEL = dict(RiskConsequence.choices)
TREATMENT_LABEL = dict(RiskTreatment.choices)
LEVEL_LABEL = dict(RiskLevel.choices)


@dataclass
class BusinessRisk:
    """Un riesgo de la organización con sus escenarios abiertos, el peor primero."""

    consequence: str
    role: str
    scenarios: list = field(default_factory=list)

    @property
    def key(self):
        return f"{self.consequence}:{self.role or NO_ROLE}"

    @property
    def consequence_label(self):
        return CONSEQUENCE_LABEL.get(self.consequence, self.consequence or "Sin consecuencia")

    @property
    def role_label(self):
        if not self.role:
            return NO_ROLE_LABEL
        if self.role == OTHER_ROLE:
            return OTHER_ROLE_LABEL
        return catalogs.label(catalogs.BUSINESS_ROLE, self.role) or self.role

    @property
    def title(self):
        return f"{self.consequence_label} en {self.role_label}"

    @property
    def url(self):
        return reverse(
            "detection:business_risk", args=[self.consequence or NO_ROLE, self.role or NO_ROLE]
        )

    @property
    def worst(self):
        return self.scenarios[0]

    @property
    def level(self):
        return self.worst.level

    @property
    def level_label(self):
        return LEVEL_LABEL.get(self.level, self.level)

    @property
    def likelihood(self):
        return self.worst.likelihood

    @property
    def impact(self):
        return self.worst.impact

    @property
    def score(self):
        return self.worst.likelihood * self.worst.impact

    @property
    def assets(self):
        """Los activos del riesgo, primero el del peor escenario."""
        seen = {}
        for scenario in self.scenarios:
            seen.setdefault(scenario.asset_id, scenario.asset)
        return list(seen.values())

    @property
    def undecided(self):
        return sum(1 for s in self.scenarios if not s.treatment)

    @property
    def vulnerabilities(self):
        return sum(getattr(s, "vuln_count", 0) or 0 for s in self.scenarios)

    @property
    def kev(self):
        """Vulnerabilidades del riesgo que ya se explotan (catálogo KEV de CISA)."""
        return sum(getattr(s, "kev_count", 0) or 0 for s in self.scenarios)

    @property
    def deadlines(self):
        return [s.deadline for s in self.scenarios if getattr(s, "deadline", None)]

    @property
    def deadline(self):
        """El plazo más próximo entre sus escenarios (``None`` si ninguno corre)."""
        return min(self.deadlines, key=lambda d: d.date, default=None)

    @property
    def overdue(self):
        return sum(1 for d in self.deadlines if d.overdue)

    @property
    def treatments(self):
        """«sin decidir», «mitigar» o «2 mitigar · 1 sin decidir»: cómo van sus escenarios."""
        counts = Counter(
            TREATMENT_LABEL.get(s.treatment, s.treatment).lower() if s.treatment else "sin decidir"
            for s in self.scenarios
        )
        if len(counts) == 1:
            return next(iter(counts))
        order = sorted(counts.items(), key=lambda kv: (kv[0] == "sin decidir", -kv[1], kv[0]))
        return " · ".join(f"{n} {label}" for label, n in order)

    @property
    def responsibles(self):
        """Quién lleva sus escenarios, sin repetir («sin responsable» incluido)."""
        names = Counter(responsibles.of(s).label or "sin responsable" for s in self.scenarios)
        return [name for name, _ in names.most_common()]


def _in_role(role) -> Q:
    """Los escenarios de los activos de una función; «sin función» es tanto vacío como nulo."""
    if role:
        return Q(asset__business_role=role)
    return Q(asset__business_role="") | Q(asset__business_role__isnull=True)


def scenarios(queryset=None):
    """Escenarios abiertos en orden de trabajo, con lo que las listas necesitan de cada uno."""
    if queryset is None:
        queryset = Risk.objects.filter(status__in=RISK_OPEN_STATUSES)
    queryset = queryset.annotate(
        kev_count=Count("vulnerabilities", filter=Q(vulnerabilities__in_kev=True), distinct=True),
        vuln_count=Count("vulnerabilities", distinct=True),
    )
    return risks.triage_order(policy.with_kev_due(responsibles.with_people(queryset)))


def _order(risk):
    return (risks.LEVEL_ORDER.get(risk.level, 9), -risk.score, -len(risk.scenarios), risk.title)


def group(open_scenarios) -> list[BusinessRisk]:
    """Agrupa escenarios (ya en orden de trabajo: el primero de cada grupo es el peor) en riesgos
    de la organización, el más grave primero."""
    groups = {}
    for scenario in open_scenarios:
        key = (scenario.consequence or "", scenario.asset.business_role or "")
        groups.setdefault(key, BusinessRisk(*key)).scenarios.append(scenario)
    return sorted(groups.values(), key=_order)


def register(queryset=None, rules=None) -> list[BusinessRisk]:
    """El registro de riesgos de la organización, con el plazo de cada escenario."""
    return group(policy.attach(list(scenarios(queryset)), rules))


def get(consequence, role, rules=None) -> BusinessRisk | None:
    """Un riesgo por su consecuencia y su función (``NO_ROLE`` = activos sin función)."""
    role = "" if role == NO_ROLE else role
    consequence = "" if consequence == NO_ROLE else consequence
    found = register(
        Risk.objects.filter(_in_role(role), status__in=RISK_OPEN_STATUSES, consequence=consequence),
        rules,
    )
    return found[0] if found else None


def of(scenario) -> BusinessRisk:
    """El riesgo de la organización al que pertenece un escenario (aunque esté cerrado: entonces
    reúne los que siguen abiertos, que pueden ser ninguno)."""
    role = scenario.asset.business_role or ""
    found = group(
        scenarios(
            Risk.objects.filter(
                _in_role(role), status__in=RISK_OPEN_STATUSES, consequence=scenario.consequence
            )
        )
    )
    return found[0] if found else BusinessRisk(scenario.consequence or "", role)


def counts(queryset=None) -> dict:
    """Cuántos riesgos de la organización hay abiertos, de qué nivel y cuántos tienen algún
    escenario sin decidir, sin cargar los escenarios: para los indicadores de Inicio y sus
    instantáneas."""
    if queryset is None:
        queryset = Risk.objects.filter(status__in=RISK_OPEN_STATUSES)
    worst, undecided = {}, set()
    for consequence, role, level, treatment in queryset.values_list(
        "consequence", "asset__business_role", "level", "treatment"
    ):
        key = (consequence or "", role or "")
        rank = risks.LEVEL_ORDER.get(level, 9)
        if key not in worst or rank < worst[key][0]:
            worst[key] = (rank, level)
        if not treatment:
            undecided.add(key)
    by_level = Counter(level for _, level in worst.values())
    return {
        "open": len(worst),
        "by_level": {level: by_level.get(level, 0) for level in LEVEL_LABEL},
        "undecided": len(undecided),
    }


def summary(found) -> dict:
    """Los números del registro: riesgos, niveles y lo que espera a una persona."""
    levels = Counter(r.level for r in found)
    return {
        "open": len(found),
        "critical": levels.get(RiskLevel.CRITICAL, 0),
        "very_high": levels.get(RiskLevel.VERY_HIGH, 0),
        "high": levels.get(RiskLevel.HIGH, 0),
        "undecided": sum(1 for r in found if r.undecided),
        "overdue": sum(1 for r in found if r.overdue),
        "scenarios": sum(len(r.scenarios) for r in found),
        "assets": len({a.pk for r in found for a in r.assets}),
    }


def grid(found) -> dict:
    """El mapa de la organización: una fila por función de negocio, una columna por
    consecuencia y en cada casilla el riesgo (o nada). Las funciones, por su riesgo más grave."""
    present = {r.consequence for r in found}
    columns = [c for c in RiskConsequence.values if c in present]
    columns += sorted(present - set(columns))
    rows = {}
    for risk in found:  # ya vienen del más grave al menos grave
        row = rows.setdefault(
            risk.role,
            {"label": risk.role_label, "dialog_id": dialog_id(risk.role), "cells": {}},
        )
        row["cells"][risk.consequence] = risk
    return {
        "columns": [(c, CONSEQUENCE_LABEL.get(c, c or "Sin consecuencia")) for c in columns],
        "rows": [{**row, "cells": [row["cells"].get(c) for c in columns]} for row in rows.values()],
    }


def dialog_id(role) -> str:
    """El id del cuadro que explica una función de negocio (``role_cards``)."""
    return f"funcion-{(role or 'sin-funcion').lower().replace('_', '-')}"


def _card(role, here, assets, user=None) -> dict:
    entry = catalogs.get(catalogs.BUSINESS_ROLE, role) if role else None
    worst = {}
    for risk in here:
        for scenario in risk.scenarios:
            rank = risks.LEVEL_ORDER.get(scenario.level, 9)
            if rank < worst.get(scenario.asset_id, (99, ""))[0]:
                worst[scenario.asset_id] = (rank, scenario.level)
    # Los activos con escenarios van siempre (aunque el inventario ya no los liste) y primero.
    listed = {a.pk: a for a in assets}
    for risk in here:
        for asset in risk.assets:
            listed.setdefault(asset.pk, asset)
    rows = sorted(
        ({"asset": a, "level": worst.get(a.pk, (99, ""))[1]} for a in listed.values()),
        key=lambda row: (worst.get(row["asset"].pk, (99, ""))[0], row["asset"].name.lower()),
    )
    label = BusinessRisk("", role).role_label
    # Qué es la función en esta organización: lo que cuenta el inventario de sus activos y el
    # párrafo que la IA arma con sus descripciones (solo de los activos que siguen en inventario).
    context = business_roles.context_of(role, assets, user=user)
    return {
        "role": role,
        "dialog_id": dialog_id(role),
        "label": label[:1].upper() + label[1:],
        "description": ((entry or {}).get("description") or "") if role else NO_ROLE_HELP,
        "context": context,
        "identity": bool(entry and entry["is_identity_control"]),
        "risks": here,
        "assets": rows,
        "with_risk": len(worst),
    }


def role_cards(found, user=None) -> list[dict]:
    """Lo que el registro explica de cada función de negocio que tiene riesgos: qué es (la
    descripción del catálogo, que se edita en Administración), qué puede perder la organización
    en ella y qué activos la cumplen, tengan riesgos abiertos o no."""
    by_role = {}
    for risk in found:
        by_role.setdefault(risk.role, []).append(risk)
    named = [role for role in by_role if role]
    wanted = Q(business_role__in=named)
    if "" in by_role:
        wanted |= Q(business_role="") | Q(business_role__isnull=True)
    assets = {}
    if by_role:
        inventory = Asset.objects.filter(wanted).exclude(status__in=OUT_OF_INVENTORY)
        for asset in inventory.order_by("name"):
            assets.setdefault(asset.business_role or "", []).append(asset)
    return [_card(role, here, assets.get(role, []), user) for role, here in by_role.items()]


def role_card(role, user=None) -> dict:
    """El cuadro de una sola función (la página de uno de sus riesgos), con todos sus riesgos."""
    role = "" if role == NO_ROLE else (role or "")
    found = register(Risk.objects.filter(_in_role(role), status__in=RISK_OPEN_STATUSES))
    cards = role_cards(found, user)
    return cards[0] if cards else _card(role, [], [], user)


def describe(risk) -> list[tuple[str, str]]:
    """El riesgo en tres líneas, sin modelo de por medio: qué puede pasar, dónde y por qué tiene
    ese nivel."""
    names = [a.name for a in risk.assets]
    listed = ", ".join(names[:4]) + (f" y {len(names) - 4} más" if len(names) > 4 else "")
    one = len(names) == 1
    where = (
        f"En {'el activo' if one else f'{len(names)} activos'} "
        f"{'sin función de negocio definida' if not risk.role else f'con la función «{risk.role_label}»'}"
        f": {listed}."
    )
    what = risks.CONSEQUENCE_PLAIN.get(risk.consequence)
    worst = risk.worst
    why = (
        f"{risk.level_label}: es el de su peor escenario, {worst.asset.name} "
        f"(probabilidad {worst.likelihood} × impacto {worst.impact} = {risk.score})."
    )
    if len(risk.scenarios) > 1:
        levels = Counter(LEVEL_LABEL.get(s.level, s.level).lower() for s in risk.scenarios[1:])
        rest = ", ".join(f"{n} en nivel {label}" for label, n in levels.items())
        why += f" Los demás: {rest}."
    lines = [("Dónde", where), ("Nivel", why)]
    if what:
        lines.insert(0, ("Qué puede pasar", what[0].upper() + what[1:] + "."))
    return lines

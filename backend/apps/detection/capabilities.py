"""Qué puede hacer Atalaya con un activo, **antes** de preguntarle al LLM.

El planificador elige una acción de una lista cerrada, pero varias de esas acciones dependen
de condiciones que el sistema conoce de antemano: escanear la red exige una IP dentro de un
rango autorizado; reanalizar un SBOM exige tener uno; reconciliar exige software registrado.
Pedirle al modelo que decida entre acciones imposibles solo produce «revisión humana» sin
contenido. Aquí se calcula, de forma determinista, la lista de acciones viables y los motivos
de las que no lo son; el planificador la recibe en su entrada y la interfaz la muestra como
«qué no se pudo hacer y cómo arreglarlo».
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from apps.assets import services as assets_services

from . import components as components_index
from .models import OPEN_STATUSES, Action, AssetDetectionState, Finding

# Acciones que siempre están disponibles: no tocan la red ni el activo.
ALWAYS_ALLOWED = (Action.FLAG_HUMAN, Action.NO_ACTION)


@dataclass(frozen=True)
class Capabilities:
    asset_id: str
    can_scan_network: bool
    scan_blocker: str = ""
    scan_blocker_range_id: str | None = None
    has_image_or_sbom: bool = False
    components: int = 0
    open_findings: int = 0
    open_findings_in_kev: int = 0
    reachable: bool | None = None
    reachability_checked_at: datetime | None = None
    last_service_scan_at: datetime | None = None
    last_vuln_scan_at: datetime | None = None
    last_sbom_scan_at: datetime | None = None
    last_evaluated_at: datetime | None = None
    extra: dict = field(default_factory=dict)

    @property
    def allowed_actions(self) -> list[str]:
        allowed = []
        if self.components:
            allowed.append(Action.RECONCILE)
        if self.can_scan_network:
            allowed += [Action.RESCAN_SERVICES, Action.DETECT_VULNS]
        if self.has_image_or_sbom:
            allowed.append(Action.REANALYZE_SBOM)
        return [str(a) for a in (*allowed, *ALWAYS_ALLOWED)]

    @property
    def unavailable_actions(self) -> dict[str, str]:
        reasons = {}
        if not self.components:
            reasons[str(Action.RECONCILE)] = "no hay software registrado contra el que comparar"
        if not self.can_scan_network:
            reasons[str(Action.RESCAN_SERVICES)] = self.scan_blocker
            reasons[str(Action.DETECT_VULNS)] = self.scan_blocker
        if not self.has_image_or_sbom:
            reasons[str(Action.REANALYZE_SBOM)] = "el activo no tiene imagen ni SBOM"
        return reasons

    @property
    def can_evaluate(self) -> bool:
        """¿Hay alguna acción con contenido (más allá de «no hacer nada» o «que lo vea alguien»)?"""
        return any(a not in ALWAYS_ALLOWED for a in self.allowed_actions)

    @property
    def blockers(self) -> list[str]:
        """Frases para personas: qué impide evaluar el activo."""
        items = []
        if not self.can_scan_network:
            items.append(self.scan_blocker)
        if not self.has_image_or_sbom:
            items.append("no tiene SBOM ni imagen")
        if not self.components:
            items.append("no hay software registrado")
        return items

    @property
    def remedies(self) -> list[dict]:
        """Siguientes pasos viables, en orden de utilidad. ``key`` lo interpreta la plantilla."""
        steps = []
        if self.can_scan_network and not self.components:
            steps.append({"key": "rescan", "label": "Escanear servicios"})
        if not self.can_scan_network:
            if self.scan_blocker_range_id:
                steps.append(
                    {
                        "key": "renew_range",
                        "label": "Renovar la autorización del rango",
                        "range_id": str(self.scan_blocker_range_id),
                    }
                )
            elif "no tiene dirección IP" in self.scan_blocker or "excluido" in self.scan_blocker:
                steps.append({"key": "edit_asset", "label": "Editar el activo"})
            else:
                steps.append({"key": "register_range", "label": "Registrar el rango de red"})
        if not self.has_image_or_sbom:
            steps.append({"key": "upload_sbom", "label": "Cargar un SBOM"})
        return steps

    def explain(self, asset_name="") -> str:
        name = f" «{asset_name}»" if asset_name else ""
        blockers = self.blockers
        return (
            f"No se puede evaluar{name} todavía: {'; '.join(blockers)}. "
            "Registra el rango de red que lo contiene (con autorización vigente), escanea sus "
            "servicios o carga un SBOM, y vuelve a pedir la evaluación."
        )


def for_asset(asset_id) -> Capabilities:
    from apps.discovery import services as discovery

    summary = assets_services.get_asset_summary(asset_id)
    blocker, range_id = discovery.scan_blocker_for_asset_id(asset_id)
    state = AssetDetectionState.objects.filter(asset_id=asset_id).first()
    open_findings = Finding.objects.filter(asset_id=asset_id, status__in=OPEN_STATUSES)
    return Capabilities(
        asset_id=str(asset_id),
        can_scan_network=not blocker,
        scan_blocker=blocker,
        scan_blocker_range_id=range_id,
        has_image_or_sbom=bool(summary["has_image"] or summary["has_sbom"]),
        components=len(components_index.current_components([asset_id])),
        open_findings=open_findings.count(),
        open_findings_in_kev=open_findings.filter(in_kev=True).count(),
        reachable=summary["reachable"],
        reachability_checked_at=summary["reachability_checked_at"],
        last_service_scan_at=state.last_service_scan_at if state else None,
        last_vuln_scan_at=state.last_vuln_scan_at if state else None,
        last_sbom_scan_at=state.last_sbom_scan_at if state else None,
        last_evaluated_at=state.last_evaluated_at if state else None,
    )

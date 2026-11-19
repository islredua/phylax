"""Pantallas del módulo de detección: permisos por rol, flujos y seguridad de salida."""

import json
from pathlib import Path

import pytest

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CtiSource
from apps.detection import actions, automation, components, events, findings, planner, profile
from apps.detection.models import ActionStatus, DetectionEvent, EventKind, Finding, PlannedAction
from apps.scanners import services as scanners
from apps.scanners.runner import CommandResult
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"
NUCLEI = (Path(__file__).resolve().parents[1] / "scanners/fixtures/nuclei.jsonl").read_text()
READ_PAGES = [
    "/detection/",
    "/detection/vulnerabilities/",
    "/detection/observations/",
    "/detection/activity/",
    "/detection/activity/?kind=decision",
    "/detection/queue/",
    "/detection/sources/",
    "/detection/automation/",
    "/administration/organization/",
]


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True
    cti.ensure_sources()
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    automation.invalidate()
    profile.invalidate()


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


@pytest.fixture
def fake_tool(monkeypatch):
    monkeypatch.setattr(
        scanners,
        "run_command",
        lambda argv, timeout=None, env=None: CommandResult(NUCLEI, "", 0, 0.1),
    )


def _asset():
    NetworkRangeFactory(cidr="10.7.0.0/24")
    asset = AssetFactory(name="web-norte")
    AssetIdentifierFactory(asset=asset, value="10.7.0.10")
    ServiceFactory(asset=asset, port=80, product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    return asset


def _finding(asset=None):
    asset = asset or _asset()
    cti.import_fixture(json.loads(LAB_CTI.read_text()))
    return Finding.objects.get(asset=asset, vulnerability_id="CVE-2025-23419")


# --- Acceso por rol -----------------------------------------------------------------


@pytest.mark.parametrize("role", [ADMIN, OPERATOR, AUDITOR])
@pytest.mark.parametrize("path", READ_PAGES)
def test_every_role_can_read_detection(client, as_role, role, path):
    as_role(role)
    assert client.get(path).status_code == 200


def test_roleless_user_is_forbidden(client, user):
    client.force_login(user)
    assert client.get("/detection/").status_code == 403


def test_navigation_splits_detection_into_results_and_machinery(client, as_role):
    as_role(OPERATOR)
    nav = client.get("/detection/queue/").context["nav"]
    # La maquinaria (qué hizo el sistema, qué espera aprobación) va en Operación.
    assert nav.section.key == "operation"
    assert [t.key for t in nav.tabs] == ["activity", "queue"]
    assert [t.key for t in nav.tabs if t.active] == ["queue"]
    # Riesgos es una sección por sí misma, sin barra de pestañas.
    nav = client.get("/detection/").context["nav"]
    assert nav.section.key == "risks" and nav.tabs == []
    # Las vulnerabilidades y su materia prima.
    nav = client.get("/detection/observations/").context["nav"]
    assert nav.section.key == "vulnerabilities"
    assert [t.key for t in nav.tabs] == ["panel", "observations"]
    assert [t.key for t in nav.tabs if t.active] == ["observations"]


def test_auditor_cannot_change_anything(client, as_role):
    as_role(AUDITOR)
    finding = _finding()
    assert client.post(f"/detection/findings/{finding.pk}/note/", {"text": "x"}).status_code == 403
    assert client.post("/detection/automation/", {"mode": "MANUAL"}).status_code == 403
    assert client.post("/detection/automation/pause/", {"paused": "1"}).status_code == 403
    assert client.post("/administration/organization/", {"name": "x"}).status_code == 403
    assert client.post("/detection/sources/", {"kind": "KEV"}).status_code == 403
    assert client.post(f"/detection/assets/{finding.asset_id}/evaluate/").status_code == 403


def test_operator_cannot_manage_but_can_work(client, as_role):
    as_role(OPERATOR)
    assert client.post("/detection/automation/", {"mode": "MANUAL"}).status_code == 403
    assert client.post("/administration/organization/", {"name": "x"}).status_code == 403
    assert client.post("/detection/sources/KEV/sync/").status_code == 403
    finding = _finding()
    response = client.post(f"/detection/findings/{finding.pk}/note/", {"text": "Lo reviso hoy"})
    assert response.status_code == 302
    finding.refresh_from_db()
    assert finding.note == "Lo reviso hoy"
    # W6: la ruta para cambiar a mano el estado de una observación se retiró.
    assert client.post(f"/detection/findings/{finding.pk}/transition/", {}).status_code == 404


# --- Panel y detalle ----------------------------------------------------------------


def test_observations_list_does_not_query_once_per_row(client, as_role):
    """Revisión del 2026-11-16, R2: «Consolidada en» costaba una consulta por fila (25 de 35) y
    la lista traía todas las observaciones para ordenar en memoria las 25 que muestra."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from apps.detection import consolidation
    from apps.detection.views import SEVERITY_ORDER

    as_role(OPERATOR)
    asset = _finding().asset

    def queries():
        with CaptureQueriesContext(connection) as captured:
            response = client.get("/detection/observations/")
        return len(captured), response

    queries()
    few, _ = queries()
    for n in range(12):
        findings.upsert_finding(
            asset_id=asset.pk,
            vulnerability_id=f"CVE-2024-10{n:02d}",
            source="NUCLEI",
            title=f"Falla {n} en nginx",
            severity=("CRITICAL", "HIGH", "MEDIUM", "LOW")[n % 4],
            evidence_summary="plantilla",
        )
    consolidation.consolidate_asset(asset.pk)
    assert Finding.objects.filter(asset=asset, consolidated__isnull=False).count() >= 12
    many, response = queries()
    assert many == few
    # El orden que antes se hacía en memoria lo hace ahora la base, igual.
    listed = list(response.context["findings"])
    assert len(listed) == Finding.objects.filter(asset=asset).count()

    def priority(f):
        return (
            f.priority_score if f.priority_score is not None else -1,
            int(f.in_kev),
            SEVERITY_ORDER.get(f.severity, 0),
            f.epss_score or 0,
            f.first_detected_at,
        )

    assert [f.pk for f in listed] == [f.pk for f in sorted(listed, key=priority, reverse=True)]
    assert "Falla 3 en nginx" in response.content.decode()


def test_observations_list_and_filters(client, as_role):
    as_role(OPERATOR)
    finding = _finding()
    body = client.get("/detection/observations/").content.decode()
    # Con Celery en modo inmediato la consolidación ya corrió: la observación enlaza su vulnerabilidad.
    assert (
        "CVE-2025-23419" in body and "web-norte" in body and "/detection/vulnerabilities/" in body
    )
    response = client.get("/detection/observations/?severity=CRITICAL")
    assert response.context["paginator"].count == 0
    response = client.get(f"/detection/observations/?asset={finding.asset_id}&q=nginx")
    assert response.context["paginator"].count == 1
    # W6: la lista dice la situación (lo único que cambia), no un «estado» que nadie decide.
    assert "Situación" in body and "vigente" in body and ">Nuevo<" not in body
    assert "Ya no se observan" in body and "Reaparecidos" in body
    findings.mark_unreported(
        [finding.pk], "CTI_MATCH", reason="El software afectado ya no se observa en el activo."
    )
    assert client.get("/detection/observations/").context["paginator"].count == 0
    assert client.get("/detection/observations/?status=all").context["paginator"].count == 1
    response = client.get("/detection/observations/?status=MITIGATED")
    assert response.context["paginator"].count == 1
    assert "ya no se observa" in response.content.decode()
    # Si la fuente vuelve a verla, reaparece y la lista lo dice.
    findings.upsert_finding(
        asset_id=finding.asset_id, vulnerability_id=finding.vulnerability_id, source="CTI_MATCH"
    )
    response = client.get("/detection/observations/?status=REOPENED")
    assert response.context["paginator"].count == 1 and "reapareció" in response.content.decode()
    assert client.get("/detection/observations/").context["paginator"].count == 1
    assert client.get("/detection/observations/?in_kev=1&source=CTI_MATCH").status_code == 200
    # El panel ahora son vulnerabilidades: sin consolidar, explica que hay observaciones esperando.
    body = client.get(f"/detection/vulnerabilities/?asset={finding.asset_id}").content.decode()
    assert "Vulnerabilidades" in body and "Reevaluar con IA" in body


def test_finding_detail_actions_and_escaping(client, as_role):
    operator = as_role(OPERATOR)
    finding = _finding()
    findings.add_note(finding.pk, user=operator, text="<script>alert(1)</script>")
    body = client.get(f"/detection/findings/{finding.pk}/").content.decode()
    assert "&lt;script&gt;" in body and "<script>alert" not in body
    assert "Línea de tiempo" in body and "Rango afectado" in body
    # La observación no ofrece cambiar su estado a mano (eso vive en la vulnerabilidad) y la
    # ruta ya no existe; su cabecera dice la situación.
    assert "/transition/" not in body and "vigente" in body
    assert client.post(f"/detection/findings/{finding.pk}/transition/", {}).status_code == 404
    client.post(f"/detection/findings/{finding.pk}/note/", {"text": ""})
    assert (
        client.get("/detection/findings/00000000-0000-0000-0000-000000000000/").status_code == 404
    )


def test_asset_detail_links_findings_and_evaluate(client, as_role, fake_tool):
    as_role(OPERATOR)
    finding = _finding()
    body = client.get(f"/inventory/{finding.asset_id}/").content.decode()
    assert (
        "?tab=riesgos" in body and "?tab=vulnerabilidades" in body and "?tab=observaciones" in body
    )
    assert (
        body.index("?tab=riesgos")
        < body.index("?tab=vulnerabilidades")
        < body.index("?tab=observaciones")
    )
    assert f"/detection/assets/{finding.asset_id}/pipeline/" in body
    # La capa cruda se lee dentro del activo, sin cambiar de módulo.
    tab = client.get(f"/inventory/{finding.asset_id}/?tab=observaciones").content.decode()
    assert (
        finding.vulnerability_id in tab
        and f"/detection/observations/?asset={finding.asset_id}" in tab
    )
    strip = client.get(f"/detection/assets/{finding.asset_id}/pipeline/").content.decode()
    assert "Evaluar ahora" in strip
    response = client.post(f"/detection/assets/{finding.asset_id}/evaluate/", follow=True)
    assert "Evaluación en curso" in response.content.decode()
    event = DetectionEvent.objects.get(kind=EventKind.MANUAL_EVALUATION, asset_id=finding.asset_id)
    assert event.status == "PLANNED"
    response = client.post(f"/detection/assets/{finding.asset_id}/evaluate/", follow=True)
    assert "pendiente" in response.content.decode() or "Evaluación" in response.content.decode()


# --- Actividad y detalles ----------------------------------------------------------


def test_activity_feed_and_detail_pages(client, as_role, fake_tool):
    as_role(OPERATOR)
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    body = client.get("/detection/activity/").content.decode()
    assert "Evaluación pedida a mano" in body and "Planificador" in body and "nuclei" in body
    fragment = client.get("/detection/activity/", HTTP_HX_REQUEST="true").content.decode()
    assert fragment.lstrip().startswith('<div id="activity-feed"') and "app-shell" not in fragment
    event_body = client.get(f"/detection/events/{event.pk}/").content.decode()
    assert (
        "Decisión: Detectar vulnerabilidades" in event_body
        and "Entrada que recibió el modelo" in event_body
    )
    action = PlannedAction.objects.get(event=event)
    action_body = client.get(f"/detection/actions/{action.pk}/").content.decode()
    assert "Guardarraíles verificados" in action_body and "Concurrencia de escaneos" in action_body
    execution = action.executions.get()
    exec_body = client.get(f"/detection/executions/{execution.pk}/").content.decode()
    assert "-jsonl" in exec_body and "CVE-2021-41773" in exec_body
    assert "data-output-cut" not in exec_body and "data-output-repeated" not in exec_body
    assert "salida recortada" not in body.lower() and "output_incomplete" not in action.result


def test_a_cut_scan_output_is_visible_in_its_page_and_in_the_feed(client, as_role, monkeypatch):
    """Un escaneo cuya salida se cortó en el límite termina como exitoso (corrida limpia del
    2026-11-18): quien lo abre, o lo ve en Actividad, tiene que enterarse."""
    as_role(OPERATOR)
    asset = _asset()
    monkeypatch.setattr(
        scanners,
        "run_command",
        lambda argv, timeout=None, env=None: CommandResult(
            NUCLEI, "", 0, 0.1, truncated=True, repeated={"secrets-patterns-pii": 11819}
        ),
    )
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    action = PlannedAction.objects.get(event=event)
    execution = action.executions.get()
    assert execution.status == "SUCCEEDED" and execution.output_incomplete
    body = client.get(f"/detection/executions/{execution.pk}/").content.decode()
    assert "data-output-cut" in body and "Pasó de 50 MB y se guardó hasta ese punto." in body
    assert "Puede faltar parte de lo que encontró la herramienta." in body
    assert "data-output-repeated" in body and "secrets-patterns-pii 11819" in body
    assert "Se guardan hasta 200 líneas por plantilla y objetivo." in body
    feed = client.get("/detection/activity/?kind=execution").content.decode()
    assert "salida recortada" in feed
    assert action.result["output_incomplete"] is True
    action_body = client.get(f"/detection/actions/{action.pk}/").content.decode()
    assert "salida recortada: sí" in action_body


def test_activity_shows_one_row_per_action_with_its_steps_folded(client, as_role, fake_tool):
    """P7: una acción ocupaba cuatro filas o más (enviada, ejecución terminada, acción
    ejecutada, herramienta completada). Ahora es una fila con sus pasos dentro."""
    from apps.detection import activity
    from apps.detection.models import AutomationLogEntry, LogKind

    as_role(OPERATOR)
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    # Algo que no cuelga de ningún evento: va como fila suelta.
    AutomationLogEntry.objects.create(kind=LogKind.PAUSED, message="Pausa por mantenimiento")

    threads = activity.threads()
    thread = next(t for t in threads if t.key == str(event.pk))
    kinds = [step.kind for step in thread.steps]
    assert kinds[0] == "event" and {"decision", "action", "execution", "log"} <= set(kinds)
    assert [step.at for step in thread.steps] == sorted(step.at for step in thread.steps)
    # La fila se resume con la acción y con lo que dijo la herramienta.
    assert thread.head.kind == "action" and thread.head.label == "Detectar vulnerabilidades"
    assert "hallazgo" in thread.summary and thread.at == thread.steps[-1].at
    loose = next(t for t in threads if not t.key)
    assert loose.head.label == "Pausa de emergencia" and loose.steps == []

    response = client.get("/detection/activity/")
    body = response.content.decode()
    assert body.count(f'data-thread="{event.pk}"') == 1
    assert f'id="hilo-{event.pk}"' in body and f"{len(thread.steps)} pasos" in body
    assert "Pausa por mantenimiento" in body and "data-keep-open" in body
    # Cada paso conserva su enlace al detalle.
    action = PlannedAction.objects.get(event=event)
    assert f"/detection/actions/{action.pk}/" in body
    assert f"/detection/executions/{action.executions.get().pk}/" in body

    # Las pestañas por tipo siguen siendo el listado plano de un solo tipo.
    flat = client.get("/detection/activity/?kind=log")
    assert flat.context["threads"] is None and "data-thread" not in flat.content.decode()
    assert "Enviada a ejecutar" in flat.content.decode()


def test_activity_lists_nmap_discoveries_with_who_asked(client, as_role, make_user):
    """Un barrido de nmap lanzado desde el inventario no dejaba fila en Actividad: tras una
    tarde de trabajo lo más reciente de la lista decía «ayer» y parecía un desfase de fechas
    (2026-11-18). Ahora cada descubrimiento es una fila con lo que encontró y quién lo pidió; el
    que salió de una decisión es un paso más de esa acción."""
    from django.contrib.auth.models import Permission

    from apps.detection import activity
    from apps.detection.models import PlannerDecision
    from apps.discovery.models import DiscoveryRun
    from tests.factories import NetworkRangeFactory

    user = as_role(ADMIN)
    asset = _asset()
    rng = NetworkRangeFactory(cidr="10.60.30.0/24")
    by_hand = DiscoveryRun.objects.create(
        network_range=rng,
        profile="HOST_SWEEP",
        status="SUCCEEDED",
        requested_by=user,
        hosts_up=3,
        assets_created=1,
    )
    scheduled = DiscoveryRun.objects.create(
        network_range=rng, profile="HOST_SWEEP", status="SUCCEEDED", hosts_up=0
    )
    failed = DiscoveryRun.objects.create(
        network_range=rng, profile="HOST_SWEEP", status="FAILED", error="nmap no respondió"
    )
    # El que ordenó el planificador cuelga del evento de su acción.
    event = DetectionEvent.objects.create(
        kind=EventKind.ASSET_SERVICES_CHANGED, asset=asset, dedupe_key="cambio"
    )
    decision = PlannerDecision.objects.create(
        event=event, asset=asset, action="RESCAN_SERVICES", prompt_version="v3"
    )
    by_planner = DiscoveryRun.objects.create(
        target_asset=asset,
        profile="SERVICE_SCAN",
        status="SUCCEEDED",
        services_seen=4,
        assets_updated=1,
    )
    PlannedAction.objects.create(
        decision=decision,
        event=event,
        asset=asset,
        action="RESCAN_SERVICES",
        discovery_run=by_planner,
    )

    tools = {e.url: e for e in activity.recent(kinds=["execution"])}
    assert len(tools) == 4 and all(e.kind == "execution" for e in tools.values())
    row = tools[f"/discovery/runs/{by_hand.pk}/"]
    assert row.label == "nmap · barrido de hosts" and row.subject == "10.60.30.0/24"
    assert row.text == f"3 hosts activos · 1 activo nuevo · lo pidió {user.get_username()}"
    assert row.badge == "SUCCEEDED" and row.thread == ""
    assert tools[f"/discovery/runs/{scheduled.pk}/"].text == "0 hosts activos · por calendario"
    assert tools[f"/discovery/runs/{failed.pk}/"].text == "nmap no respondió · por calendario"
    row = tools[f"/discovery/runs/{by_planner.pk}/"]
    assert row.label == "nmap · escaneo de servicios" and row.subject == asset.name
    assert row.text == ("4 servicios vistos · 1 activo actualizado · por decisión del planificador")
    assert row.thread == str(event.pk)

    # «Todo»: tres filas sueltas y el del planificador dentro del hilo de su acción.
    threads = activity.threads()
    loose = [t for t in threads if not t.key and t.head.label.startswith("nmap")]
    assert len(loose) == 3 and all(t.steps == [] for t in loose)
    thread = next(t for t in threads if t.key == str(event.pk))
    assert [step.kind for step in thread.steps].count("execution") == 1
    assert "4 servicios vistos" in thread.summary

    body = client.get("/detection/activity/").content.decode()
    assert body.count("nmap · barrido de hosts") == 3
    assert f"lo pidió {user.get_username()}" in body and "por calendario" in body
    assert f'href="/discovery/runs/{by_hand.pk}/"' in body
    assert body.count(f'data-thread="{event.pk}"') == 1 and "nmap · escaneo de servicios" in body
    flat = client.get("/detection/activity/?kind=execution").content.decode()
    assert flat.count("nmap · ") == 4 and "los descubrimientos de nmap" in flat
    # Y en el pulso de Inicio, que usa la misma lista.
    assert "nmap · barrido de hosts" in client.get("/home/block/pulse/").content.decode()

    # Quien ve la actividad pero no puede abrir un descubrimiento ve la fila, sin enlace.
    reader = make_user(username="solo-actividad")
    reader.groups.clear()
    reader.user_permissions.add(Permission.objects.get(codename="view_detectionevent"))
    client.force_login(reader)
    body = client.get("/detection/activity/?kind=execution").content.decode()
    assert body.count("nmap · ") == 4 and "/discovery/runs/" not in body


def test_model_mismatch_warning_is_visible(client, as_role):
    as_role(OPERATOR)
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    decision = event.decisions.get()
    type(decision).objects.filter(pk=decision.pk).update(
        model_mismatch=True, model_responded="otro:modelo"
    )
    body = client.get(f"/detection/events/{event.pk}/").content.decode()
    assert "modelo sustituido" in body and "otro:modelo" in body


# --- Cola de aprobación -------------------------------------------------------------


def test_queue_approve_reject_and_bulk(client, as_role, fake_tool):
    operator = as_role(OPERATOR)
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    first = _asset()
    e1, b1 = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, first.pk)
    events.process_batch(b1.pk)
    second = AssetFactory(name="api-sur")
    AssetIdentifierFactory(asset=second, value="10.7.0.11")
    e2, b2 = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, second.pk)
    events.process_batch(b2.pk)
    a1, a2 = PlannedAction.objects.get(event=e1), PlannedAction.objects.get(event=e2)
    body = client.get("/detection/queue/").content.decode()
    assert "data-queue" in body and "web-norte" in body and "api-sur" in body
    # Sin motivo no se rechaza; con el campo por tarjeta («note_<id>») sí.
    client.post(f"/detection/actions/{a2.pk}/reject/", {})
    a2.refresh_from_db()
    assert a2.status != ActionStatus.REJECTED
    client.post(f"/detection/actions/{a2.pk}/reject/", {f"note_{a2.pk}": "no hoy"})
    a2.refresh_from_db()
    assert a2.status == ActionStatus.REJECTED and a2.rejected_by == operator
    assert a2.review_note == "no hoy"
    client.post("/detection/queue/bulk/", {"ids": [str(a1.pk), str(a2.pk)], "decision": "approve"})
    a1.refresh_from_db()
    assert a1.status == ActionStatus.DONE and a1.approved_in_bulk
    assert "aprobada en lote" in client.get(f"/detection/actions/{a1.pk}/").content.decode()
    response = client.post("/detection/queue/bulk/", {"decision": "approve"}, follow=True)
    assert "Selecciona" in response.content.decode()


def test_queue_bulk_reject_and_cancel(client, as_role):
    as_role(OPERATOR)
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    asset = _asset()
    event, batch = events.ingest_asset_event(EventKind.MANUAL_EVALUATION, asset.pk)
    events.process_batch(batch.pk)
    action = PlannedAction.objects.get(event=event)
    # Rechazar en lote sin motivo no hace nada: el motivo queda en la bitácora.
    response = client.post(
        "/detection/queue/bulk/", {"ids": [str(action.pk)], "decision": "reject"}, follow=True
    )
    action.refresh_from_db()
    assert action.status == ActionStatus.PROPOSED
    assert "Indica el motivo del rechazo" in response.content.decode()
    client.post(
        "/detection/queue/bulk/",
        {"ids": [str(action.pk)], "decision": "reject", "note": "ventana de cambios cerrada"},
    )
    action.refresh_from_db()
    assert action.status == ActionStatus.REJECTED
    assert action.review_note == "Rechazada en lote: ventana de cambios cerrada"
    automation.set_paused(True, user=None)
    event2, batch2 = events.ingest_asset_event(EventKind.ASSET_CONFIRMED, asset.pk)
    from apps.detection.models import PlannerDecision

    decision = PlannerDecision.objects.create(
        event=event2, asset=asset, action="DETECT_VULNS", urgency="CRITICAL", rationale="x"
    )
    approved = actions.enqueue_from_decision(decision)  # crítica escalada, pero en pausa
    assert approved.status == ActionStatus.APPROVED
    client.post(f"/detection/actions/{approved.pk}/cancel/")
    approved.refresh_from_db()
    assert approved.status == ActionStatus.CANCELLED


# --- Automatización -----------------------------------------------------------------


def test_admin_changes_automation_and_pauses(client, as_role):
    admin = as_role(ADMIN)
    response = client.post(
        "/detection/automation/",
        {
            "mode": "MANUAL",
            "env_LAB": "AUTO",
            "escalate_critical": "on",
            "defer_heavy_actions": "on",
            "off_hours_start": "21:00",
            "off_hours_end": "05:00",
            "off_hours_days": ["0", "1", "2", "3", "4"],
            "max_scans_per_hour": "4",
            "max_concurrent_executions": "1",
            "max_planner_calls_per_hour": "30",
        },
    )
    assert response.status_code == 302
    config = automation.current_settings()
    assert config.mode == "MANUAL" and config.environment_modes == {"LAB": "AUTO"}
    assert config.off_hours_days == [0, 1, 2, 3, 4] and config.max_scans_per_hour == 4
    assert config.updated_by == admin
    client.post("/detection/automation/pause/", {"paused": "1", "reason": "Cambio de ventana"})
    body = client.get("/detection/automation/").content.decode()
    assert (
        "Pausa de emergencia activada" in body
        and "Cambio de ventana" in body
        and "Reanudar" in body
    )
    client.post("/detection/automation/pause/", {"paused": "0"})
    assert not automation.current_settings().paused
    assert "Bitácora" in client.get("/detection/automation/").content.decode()
    response = client.post("/detection/automation/", {"mode": "MANUAL", "max_scans_per_hour": "x"})
    assert response.status_code == 200 and response.context["form"].errors


# --- Perfil de la organización ------------------------------------------------------


def test_admin_edits_profile_and_requests_draft(client, as_role):
    admin = as_role(ADMIN)
    response = client.post(
        "/administration/organization/",
        {
            "name": "Aseguradora Norte",
            "sector": "Seguros",
            "location": "Monterrey",
            "description": "Vende pólizas.",
        },
    )
    assert response.status_code == 302
    assert profile.get_profile().name == "Aseguradora Norte"
    assert profile.get_profile().updated_by == admin
    response = client.post("/administration/organization/draft/", follow=True)
    body = response.content.decode()
    assert "Borrador" in body and "simulado" in body
    fragment = client.get("/administration/organization/", HTTP_HX_REQUEST="true").content.decode()
    assert fragment.lstrip().startswith('<section id="draft-status"')
    client.post("/administration/organization/draft/", {"discard": "1"})
    assert profile.get_profile().draft_state == "NONE"
    response = client.post("/administration/organization/", {"description": "x" * 1300})
    assert response.status_code == 200 and response.context["form"].errors


# --- Fuentes CTI --------------------------------------------------------------------


def test_sources_page_edit_and_sync(client, as_role, monkeypatch):
    as_role(ADMIN)
    body = client.get("/detection/sources/").content.decode()
    assert "CISA KEV" in body and "sin descargas" in body  # CTI_ONLINE=0 en pruebas
    response = client.post(
        "/detection/sources/",
        {
            "kind": "KEV",
            "KEV-url": "https://kev.test/x.json",
            "KEV-enabled": "on",
            "KEV-interval_hours": "2",
        },
    )
    assert response.status_code == 302
    source = CtiSource.objects.get(kind="KEV")
    assert source.interval_hours == 2 and source.url == "https://kev.test/x.json"
    calls = []
    from apps.cti import tasks

    monkeypatch.setattr(tasks.sync_cti_source, "delay", lambda *a: calls.append(a))
    client.post("/detection/sources/KEV/sync/")
    assert calls and calls[0][0] == "KEV"
    CtiSource.objects.filter(kind="KEV").update(enabled=False)
    response = client.post("/detection/sources/KEV/sync/", follow=True)
    assert "deshabilitada" in response.content.decode()
    assert client.post("/detection/sources/XXX/sync/", follow=True).status_code == 200


def test_every_detection_page_has_breadcrumbs(client, as_role):
    as_role(ADMIN)
    finding = _finding()
    for path, section in (
        (f"/detection/findings/{finding.pk}/", "vulnerabilities"),
        ("/detection/queue/", "operation"),
        ("/detection/automation/", "administration"),
    ):
        response = client.get(path)
        assert response.context["nav"].section.key == section
        assert 'class="breadcrumbs"' in response.content.decode()


def test_planner_mock_decisions_render_without_llm(client, as_role, fake_tool):
    as_role(OPERATOR)
    _asset()
    assert planner.planner_calls_this_hour() == 0


def test_old_organization_url_redirects_to_administration(client, as_role):
    as_role(ADMIN)
    response = client.get("/detection/organization/?x=1")
    assert response.status_code == 301
    assert response["Location"] == "/administration/organization/?x=1"
    assert (
        client.get("/detection/organization/draft/")["Location"]
        == "/administration/organization/draft/"
    )

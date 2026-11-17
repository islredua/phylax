"""Revisión del 2026-11-16, bloque 4: cerrar el ciclo y repartir el trabajo (W4, W5, W6, N5).

- W6: una observación se cierra cuando **todas** sus fuentes dejan de verla; no hay «estado» que
  alguien cambie a mano.
- W5: «Ya lo corregí: comprobar» en el riesgo reescanea con las fuentes que lo vieron y cierra lo
  que deje de observarse.
- W4: cada riesgo tiene un responsable efectivo (asignado, o heredado del activo), se puede
  filtrar «a mi nombre» y asignar uno o varios.
- N5: «Exportar lo filtrado» en las listas de riesgos y de vulnerabilidades.

Sin red, sin LLM real (modo simulado) y sin herramientas.
"""

import csv
import io
import json
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.assets.models import Service
from apps.cti import services as cti
from apps.cti.models import CtiSource
from apps.detection import (
    actions,
    automation,
    components,
    consolidation,
    findings,
    matching,
    responsibles,
    risks,
    verification,
)
from apps.detection.models import (
    ActionStatus,
    Finding,
    FindingEventKind,
    FindingStatus,
    PlannedAction,
    Risk,
    RiskEventKind,
    RiskStatus,
    RiskVerification,
    VerificationStatus,
    Vulnerability,
)
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db
LAB_CTI = Path(__file__).resolve().parents[3] / "datasets/cti-lab-sample.json"


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings, db):
    from django.core.cache import cache
    from django.db import transaction

    from apps.discovery import services as discovery

    cache.clear()
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    # El reescaneo de servicios se encola, no corre nmap.
    monkeypatch.setattr(discovery, "_enqueue", lambda run_id: None)
    settings.LLM_MOCK_MODE = True
    cti.import_fixture(json.loads(LAB_CTI.read_text()))
    CtiSource.objects.filter(kind="NVD").update(enabled=False)
    automation.invalidate()


@pytest.fixture
def as_role(client, make_user):
    def login(role, **kwargs):
        user = make_user(role, mfa=role == ADMIN, **kwargs)
        client.force_login(user)
        return user

    return login


def _nginx_asset(name="web-oriente", ip="10.9.0.10", **kwargs):
    if not NetworkRangeFactory._meta.model.objects.filter(cidr="10.9.0.0/24").exists():
        NetworkRangeFactory(cidr="10.9.0.0/24")
    asset = AssetFactory(**{"name": name, "criticality": "ALTO", **kwargs})
    AssetIdentifierFactory(asset=asset, value=ip)
    ServiceFactory(asset=asset, port=443, service_name="https", product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    return asset


def _risk_of(asset):
    return Risk.objects.filter(asset=asset, status__in=("OPEN", "TREATED", "ACCEPTED")).first()


def _observe(asset, key, source, **kwargs):
    return findings.upsert_finding(
        asset_id=asset.pk, vulnerability_id=key, source=source, **kwargs
    ).finding


def _silent(finding, source, **kwargs):
    closed = findings.mark_unreported(
        [finding.pk], source, reason=f"{source} la revisó y ya no la reporta.", **kwargs
    )
    finding.refresh_from_db()
    return closed


# --------------------------------------------------------------------------
# W6 · la observación se cierra cuando todas sus fuentes dejan de verla
# --------------------------------------------------------------------------


def test_observation_closes_only_when_every_source_stops_seeing_it():
    asset = AssetFactory()
    both = _observe(asset, "CVE-2030-0001", "CTI_MATCH")
    _observe(asset, "CVE-2030-0001", "GRYPE")
    # Grype deja de reportarla, pero la versión instalada sigue en el rango afectado.
    assert _silent(both, "GRYPE") == 0
    assert both.status == FindingStatus.NEW and both.unseen == {"GRYPE": 1}
    note = both.events.filter(kind=FindingEventKind.RESCANNED).last()
    assert "Sigue abierta" in note.message and "la sigue reportando" in note.message
    # Cuando la reconciliación tampoco la ve, se cierra.
    assert _silent(both, "CTI_MATCH") == 1
    assert both.status == FindingStatus.MITIGATED and both.resolved_at is not None
    assert both.events.last().kind == FindingEventKind.AUTO_RESOLVED


def test_nuclei_needs_two_silent_passes_unless_a_person_asked_to_verify():
    asset = AssetFactory()
    finding = _observe(asset, "CVE-2030-0002", "NUCLEI")
    # Una plantilla puede fallar por un tiempo de espera: una pasada en silencio no basta.
    assert _silent(finding, "NUCLEI") == 0 and finding.unseen == {"NUCLEI": 1}
    assert "1 de 2" in finding.events.last().message
    # Si la vuelve a ver, la cuenta empieza de cero.
    finding = _observe(asset, "CVE-2030-0002", "NUCLEI")
    assert finding.unseen == {}
    assert _silent(finding, "NUCLEI") == 0
    assert _silent(finding, "NUCLEI") == 1 and finding.status == FindingStatus.MITIGATED
    # Pedida por quien dice haberlo corregido, una pasada basta.
    other = _observe(asset, "CVE-2030-0003", "NUCLEI")
    assert _silent(other, "NUCLEI", verified=True) == 1
    assert other.status == FindingStatus.MITIGATED


def test_what_a_person_registered_is_never_closed_by_a_tool():
    asset = AssetFactory()
    finding = _observe(asset, "CVE-2030-0004", "MANUAL")
    _observe(asset, "CVE-2030-0004", "NUCLEI")
    assert _silent(finding, "NUCLEI", verified=True) == 0
    assert finding.is_open and "la registró una persona" in finding.events.last().message


def test_closed_port_counts_as_no_longer_seen_by_the_network_tool():
    asset = AssetFactory()
    service = ServiceFactory(asset=asset, port=22, service_name="ssh")
    evidence = {"type": "tcp", "host": "10.9.0.20:22", "matched-at": "10.9.0.20:22"}
    ssh = _observe(asset, "CVE-2030-0005", "NUCLEI", evidence_data=evidence)
    never_scanned = _observe(
        asset, "CVE-2030-0006", "NUCLEI", evidence_data={"host": "10.9.0.20:8443"}
    )
    both = _observe(asset, "CVE-2030-0007", "CTI_MATCH")
    _observe(asset, "CVE-2030-0007", "NUCLEI", evidence_data=evidence)
    # Con el puerto abierto no pasa nada.
    assert findings.resolve_closed_services(asset.pk) == 0
    # El escaneo de servicios marca el puerto cerrado: nuclei ya no tiene dónde verla.
    Service.objects.filter(pk=service.pk).update(state="closed")
    assert findings.resolve_closed_services(asset.pk) == 1
    ssh.refresh_from_db()
    assert ssh.status == FindingStatus.MITIGATED
    assert "(22) ya no está abierto" in ssh.events.last().message
    # Un puerto que el inventario no conoce no demuestra nada.
    never_scanned.refresh_from_db()
    assert never_scanned.is_open and never_scanned.unseen == {}
    # Con otra fuente que la sigue viendo queda abierta, y no se vuelve a anotar en cada vuelta.
    both.refresh_from_db()
    assert both.is_open and both.unseen == {"NUCLEI": 2}
    before = both.events.count()
    assert findings.resolve_closed_services(asset.pk) == 0
    assert both.events.count() == before


def test_software_that_disappears_closes_the_observation_and_the_risk():
    asset = _nginx_asset()
    risk = _risk_of(asset)
    assert risk is not None and Finding.objects.filter(asset=asset, status="NEW").exists()
    # La versión corregida ya no está en el rango afectado.
    Service.objects.filter(asset=asset).update(version="99.0.0")
    components.refresh_components(asset.pk)
    result = matching.reconcile_assets([asset.pk])
    findings.apply_matches(result)
    assert findings.resolve_vanished(asset.pk, result) >= 1
    assert not Finding.objects.filter(asset=asset, status__in=("NEW", "REOPENED")).exists()
    # Sin esperar el turno del modelo: las reglas cierran la vulnerabilidad y el riesgo.
    assert consolidation.resolve_unobserved(asset.pk) >= 1
    assert risks.close_resolved(asset.pk) == 1
    risk.refresh_from_db()
    assert risk.status == RiskStatus.CLOSED
    assert "Ninguna de sus vulnerabilidades sigue abierta" in risk.events.last().message


# --------------------------------------------------------------------------
# W5 · «Ya lo corregí: comprobar»
# --------------------------------------------------------------------------


def _run_service_scan(action, status="SUCCEEDED"):
    """La acción sale de la cola y el reescaneo de servicios termina con ese resultado."""
    from apps.discovery.signals import run_finished

    automation.update_settings(user=None, fields={"defer_heavy_actions": False})
    PlannedAction.objects.filter(pk=action.pk).update(not_before=None)
    actions.dispatch_due()
    action.refresh_from_db()
    assert action.status == ActionStatus.QUEUED and action.discovery_run_id
    run_finished.send(
        sender=None, run_id=action.discovery_run_id, status=status, asset_id=action.asset_id
    )
    action.refresh_from_db()
    return action


def test_plan_asks_each_source_that_saw_the_risk(make_user):
    asset = _nginx_asset()
    risk = _risk_of(asset)
    plan = verification.plan(risk)
    # Lo vio la versión del servicio: basta reescanear los servicios.
    assert plan["actions"] == ["RESCAN_SERVICES"] and plan["can_request"]
    assert verification.describe_plan(plan) == "reescanear sus servicios (versiones)"
    # Si además lo vio nuclei, también se vuelve a pasar nuclei.
    vuln = risk.vulnerabilities.first()
    cve = vuln.observations.first().vulnerability_id
    _observe(asset, cve, "NUCLEI")
    plan = verification.plan(risk)
    assert plan["actions"] == ["RESCAN_SERVICES", "DETECT_VULNS"]
    assert (
        verification.describe_plan(plan)
    ) == "reescanear sus servicios (versiones) y volver a pasar nuclei"
    # Lo que vio Grype pide el SBOM o la imagen; sin ellos se dice por qué no se puede.
    _observe(asset, cve, "GRYPE")
    plan = verification.plan(risk)
    assert "REANALYZE_SBOM" in plan["blocked"] and "REANALYZE_SBOM" not in plan["actions"]
    # Una vulnerabilidad que solo registró una persona no la comprueba ninguna herramienta.
    Finding.objects.filter(consolidated=vuln).update(sources=["MANUAL"])
    manual_only = verification.plan(risk)
    assert vuln in manual_only["manual"]


def test_verify_button_rescans_and_closes_what_is_no_longer_observed(client, as_role):
    from apps.assets.signals_domain import services_changed

    operator = as_role(OPERATOR)
    asset = _nginx_asset()
    risk = _risk_of(asset)
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Ya lo corregí: comprobar" in body and "reescanear sus servicios" in body
    assert 'data-verification="none"' in body
    # Sin tratamiento decidido, lo primero en la ficha es decidirlo; comprobar va después.
    assert body.index('id="tratamiento"') < body.index('id="comprobacion"')

    response = client.post(f"/detection/risks/{risk.pk}/verify/", follow=True)
    body = response.content.decode()
    assert "Comprobación pedida" in body and 'data-verification="pending"' in body
    assert "hx-get" in body and "comprobando" in body
    check = RiskVerification.objects.get(risk=risk)
    assert check.status == VerificationStatus.PENDING and check.requested_by == operator
    action = check.actions.get()
    assert action.action == "RESCAN_SERVICES" and verification.requested_for(action.pk)
    assert [b["key"] for b in check.baseline] == sorted(
        risk.vulnerabilities.values_list("key", flat=True)
    )
    event = risk.events.filter(kind=RiskEventKind.VERIFICATION).get()
    assert "Se pidió comprobar la corrección" in event.message and event.actor == operator
    # Mientras está en curso no se pide otra.
    again = client.post(f"/detection/risks/{risk.pk}/verify/", follow=True).content.decode()
    assert "Ya hay una comprobación en curso" in again
    assert RiskVerification.objects.filter(risk=risk).count() == 1

    # Con la comprobación pedida, su tarjeta pasa arriba del tratamiento.
    assert again.index('id="comprobacion"') < again.index('id="tratamiento"')

    # La persona sí actualizó nginx: el reescaneo cambia el inventario y luego termina.
    actions.dispatch_due()
    action.refresh_from_db()
    assert verification.view(risk)["steps"][0]["state"] == "en cola"
    action.discovery_run.status = "RUNNING"
    action.discovery_run.save(update_fields=["status"])
    # La acción sigue «en cola» hasta terminar, pero su herramienta ya corre: se dice eso.
    assert verification.view(risk)["steps"][0]["state"] == "corriendo"
    Service.objects.filter(asset=asset).update(version="99.0.0")
    services_changed.send(sender=None, asset_id=asset.pk)
    check.refresh_from_db()
    assert check.status == VerificationStatus.PENDING  # la pasada aún no termina
    _run_service_scan(action)

    check.refresh_from_db()
    risk.refresh_from_db()
    assert check.status == VerificationStatus.DONE and check.result["risk_closed"]
    assert check.summary.startswith("Corregido") and not check.result["still"]
    assert risk.status == RiskStatus.CLOSED
    assert not Vulnerability.objects.filter(
        asset=asset, status__in=("CONFIRMED", "LIKELY")
    ).exists()
    assert "Comprobación: Corregido" in risk.events.filter(kind="VERIFY").last().message
    assert not verification.requested_for(action.pk)
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert 'data-verification="done"' in body and "Corregido" in body
    assert 'data-outcome="fixed"' in body
    assert "Ya lo corregí: comprobar" not in body and "Comprobar de nuevo" not in body
    # El fragmento que se refresca solo.
    fragment = client.get(f"/detection/risks/{risk.pk}/verification/").content.decode()
    assert "Corregido" in fragment and "hx-get" not in fragment

    # Alguien revierte la corrección: la versión vulnerable vuelve y el riesgo se reabre. La
    # tarjeta deja de decir «corregido»: no puede contradecir al estado del riesgo.
    Service.objects.filter(asset=asset).update(version="1.27.3")
    components.refresh_components(asset.pk)
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=False)
    risk.refresh_from_db()
    assert risk.status == RiskStatus.OPEN
    state = verification.view(risk)
    assert state["outcome"] == "returned" and state["returned_at"] is not None
    card = client.get(f"/detection/risks/{risk.pk}/verification/").content.decode()
    assert 'data-outcome="returned"' in card and "reapareció" in card
    assert "Volvió a observarse después de comprobarse corregido." in card
    assert ">corregido<" not in card and "El riesgo quedó cerrado" not in card
    assert "Comprobar de nuevo" in card


def test_verification_says_what_is_still_there(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    risk = _risk_of(asset)
    check = verification.request(risk.pk, user=None)
    _run_service_scan(check.actions.get())
    check.refresh_from_db()
    risk.refresh_from_db()
    # Nadie cambió nada: la versión sigue en el rango afectado.
    assert check.status == VerificationStatus.DONE and not check.result["risk_closed"]
    assert check.result["still"] and not check.result["fixed"]
    assert "observándose" in check.summary and risk.status != RiskStatus.CLOSED
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Comprobar de nuevo" in body and "observándose (" in body
    # El titular no repite la lista: en la tarjeta cada vulnerabilidad va una vez, con enlace.
    assert "Sigue ahí: las fuentes lo volvieron a ver." in body
    card = client.get(f"/detection/risks/{risk.pk}/verification/").content.decode()
    still = check.result["still"][0]
    assert card.count(still["key"]) == 1
    assert f"/detection/vulnerabilities/{still['pk']}/" in card


def test_open_but_not_reviewed_is_not_reported_as_still_there():
    """La pasada corrió pero no pudo revisar la observación (perfil, puerto u objetivo sin
    respuesta): no se dice «sigue ahí», se dice que no se pudo comprobar."""
    asset = _nginx_asset()
    risk = _risk_of(asset)
    Finding.objects.filter(asset=asset).update(sources=["NUCLEI"])
    check = RiskVerification.objects.create(
        risk=risk,
        baseline=[
            {"pk": str(v.pk), "key": v.key, "title": v.title, "actions": ["DETECT_VULNS"]}
            for v in risk.vulnerabilities.all()
        ],
    )
    planned = actions.request_manual_many(asset.pk, ["RESCAN_SERVICES"], user=None)
    PlannedAction.objects.filter(pk=planned[0].pk).update(
        action="DETECT_VULNS", status=ActionStatus.DONE
    )
    check.actions.set(planned)
    settled = verification.settle(check.pk)
    assert settled.status == VerificationStatus.FAILED
    assert settled.summary.startswith("No se pudo comprobar") and not settled.result["still"]
    assert settled.result["unchecked"]
    # En cambio, si nuclei la reportó de nuevo durante la comprobación, sí sigue ahí.
    again = RiskVerification.objects.create(risk=risk, baseline=check.baseline)
    again.actions.set(planned)
    seen = Finding.objects.filter(asset=asset).first()
    _observe(asset, seen.vulnerability_id, "NUCLEI")
    settled = verification.settle(again.pk)
    assert settled.status == VerificationStatus.DONE and settled.result["still"]


def test_verification_that_cannot_run_says_so(client, as_role, make_user):
    operator = as_role(OPERATOR)
    asset = _nginx_asset()
    risk = _risk_of(asset)
    # En modo manual la pasada espera aprobación y la ficha lo dice.
    automation.update_settings(user=None, fields={"mode": "MANUAL"})
    body = client.post(f"/detection/risks/{risk.pk}/verify/", follow=True).content.decode()
    assert "Antes debe aprobarse en la cola de aprobación" in body and "espera aprobación" in body
    check = RiskVerification.objects.get(risk=risk)
    action = check.actions.get()
    assert action.status == ActionStatus.PROPOSED
    assert "Espera aprobación" in risk.events.filter(kind="VERIFY").get().message
    # Alguien la rechaza: nadie más avisa, lo recoge la vuelta periódica.
    actions.reject(action.pk, user=make_user(ADMIN, mfa=True), note="Ventana de cambios")
    assert verification.settle_pending() == 1
    check.refresh_from_db()
    assert check.status == VerificationStatus.FAILED and "No se pudo comprobar" in check.summary
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "sin comprobar" in body and "Comprobar de nuevo" in body
    # Un reescaneo que falla tampoco se da por bueno.
    automation.update_settings(user=None, fields={"mode": "AUTO"})
    second = verification.request(risk.pk, user=operator)
    _run_service_scan(second.actions.get(), status="FAILED")
    second.refresh_from_db()
    assert second.status == VerificationStatus.FAILED
    risk.refresh_from_db()
    assert risk.status != RiskStatus.CLOSED


def test_verification_permissions_and_limits(client, as_role, make_user):
    as_role(AUDITOR)
    asset = _nginx_asset()
    risk = _risk_of(asset)
    assert client.post(f"/detection/risks/{risk.pk}/verify/").status_code == 403
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Ya lo corregí: comprobar" not in body and "¿Ya se corrigió?" in body
    with pytest.raises(PermissionDenied):
        verification.request(risk.pk, user=make_user(AUDITOR))
    # Lo que solo registró una persona no lo comprueba ninguna herramienta.
    Finding.objects.filter(asset=asset).update(sources=["MANUAL"])
    with pytest.raises(ValidationError, match="ninguna herramienta puede comprobarlas"):
        verification.request(risk.pk, user=None)
    # Un riesgo cerrado no se comprueba.
    Risk.objects.filter(pk=risk.pk).update(status=RiskStatus.CLOSED)
    with pytest.raises(ValidationError, match="ya está cerrado"):
        verification.request(risk.pk, user=None)
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "no hay nada que comprobar" in body


# --------------------------------------------------------------------------
# W4 · responsables con dueño real
# --------------------------------------------------------------------------


def test_risk_inherits_the_asset_owner_until_someone_is_assigned(make_user):
    owner = make_user(OPERATOR, first_name="Ana", last_name="Ríos")
    other = make_user(OPERATOR, username="beto")
    operator = make_user(OPERATOR)
    asset = _nginx_asset(technical_owner=owner)
    risk = _risk_of(asset)
    who = responsibles.of(responsibles.with_people(Risk.objects).get(pk=risk.pk))
    assert who.label == "Ana Ríos" and who.inherited and who.has_account
    assert who.note == "del activo"
    assert Risk.objects.filter(responsibles.mine_filter(owner)).get() == risk
    assert not Risk.objects.filter(responsibles.mine_filter(other)).exists()

    assert responsibles.assign([risk.pk], user=operator, choice=str(other.pk)) == 1
    risk = responsibles.with_people(Risk.objects).get(pk=risk.pk)
    who = responsibles.of(risk)
    assert who.label == "beto" and not who.inherited and who.user_id == other.pk
    assert risk.assigned_by == operator and risk.assigned_at is not None
    event = risk.events.filter(kind=RiskEventKind.ASSIGNED).get()
    assert event.message == "Responsable: beto" and event.actor == operator
    assert Risk.objects.filter(responsibles.mine_filter(other)).get() == risk
    assert not Risk.objects.filter(responsibles.mine_filter(owner)).exists()
    # Asignar lo mismo no cambia nada ni ensucia la bitácora.
    assert responsibles.assign([risk.pk], user=operator, choice=str(other.pk)) == 0
    assert risk.events.filter(kind=RiskEventKind.ASSIGNED).count() == 1

    # Un equipo sin cuenta: se anota, pero nadie lo ve en «a mi nombre».
    responsibles.assign([risk.pk], user=operator, choice="other", text="Proveedor de hosting")
    who = responsibles.of(responsibles.with_people(Risk.objects).get(pk=risk.pk))
    assert who.label == "Proveedor de hosting" and who.note == "sin cuenta"
    assert not Risk.objects.filter(responsibles.mine_filter(other)).exists()
    # De vuelta al activo.
    responsibles.assign([risk.pk], user=operator, choice="inherit")
    who = responsibles.of(responsibles.with_people(Risk.objects).get(pk=risk.pk))
    assert who.label == "Ana Ríos" and who.inherited
    assert "lo hereda del activo (Ana Ríos)" in risk.events.filter(kind="ASSIGNED").last().message

    with pytest.raises(ValidationError, match="Escribe el equipo"):
        responsibles.assign([risk.pk], user=operator, choice="other", text="  ")
    with pytest.raises(ValidationError, match="cuenta activa"):
        responsibles.assign([risk.pk], user=operator, choice="999999")
    with pytest.raises(PermissionDenied):
        responsibles.assign([risk.pk], user=make_user(AUDITOR), choice="inherit")


def test_asset_without_owner_falls_back_to_the_business_owner_or_nobody():
    asset = _nginx_asset(business_owner="Dirección Comercial")
    risk = responsibles.with_people(Risk.objects).get(pk=_risk_of(asset).pk)
    who = responsibles.of(risk)
    assert who.label == "Dirección Comercial" and who.inherited and not who.has_account
    assert not Risk.objects.filter(responsibles.unassigned_filter()).exists()
    assert Risk.objects.filter(responsibles.name_filter("comercial")).get() == risk
    asset.business_owner = ""
    asset.save()
    risk = responsibles.with_people(Risk.objects).get(pk=risk.pk)
    assert not responsibles.of(risk)
    assert Risk.objects.filter(responsibles.unassigned_filter()).get() == risk


def test_register_shows_who_carries_what_and_filters_mine(client, as_role, make_user):
    me = as_role(OPERATOR, username="yo")
    colleague = make_user(OPERATOR, username="colega")
    mine = _risk_of(_nginx_asset("web-mia", "10.9.0.11", technical_owner=me))
    theirs = _risk_of(_nginx_asset("web-suya", "10.9.0.12"))
    orphan = _risk_of(_nginx_asset("web-sin", "10.9.0.13"))
    responsibles.assign([theirs.pk], user=None, choice=str(colleague.pk))

    page = client.get("/detection/")
    body = page.content.decode()
    assert "Por responsable" in body and "sin responsable" in body
    # El responsable va en la celda del tratamiento: una columna más no cabe a 1440 px.
    assert "Tratamiento y responsable" in body and body.count("data-risk-responsible") == 3
    assert "a cargo de" in body and "(del activo)" in body
    rows = {(o["owner"], o["total"], o["mine"], o["nobody"]) for o in page.context["owners"]}
    assert rows == {("yo", 1, True, False), ("colega", 1, False, False), ("", 1, False, True)}
    assert page.context["owners"][0]["mine"]  # la fila de quien mira va primero
    # «Hoy» empieza por lo que tengo a mi nombre, con su cola de trabajo.
    item = page.context["today"][0]
    assert "a tu nombre" in item["text"] and item["count"] == 1 and "mine=1" in item["url"]
    assert item["work_url"] and "riesgo a tu nombre (1 sin decidir)" in body

    # Inicio también: es donde la persona llega.
    home = client.get("/")
    first = home.context["today"][0]
    assert first["text"] == "riesgo a tu nombre (1 sin decidir)" and first["work_url"]
    assert "riesgo a tu nombre" in home.content.decode()

    assert [r.pk for r in client.get("/detection/?mine=1").context["risks"]] == [mine.pk]
    assert [r.pk for r in client.get("/detection/?owner=colega").context["risks"]] == [theirs.pk]
    assert [r.pk for r in client.get("/detection/?unassigned=1").context["risks"]] == [orphan.pk]
    assert [r.pk for r in client.get("/detection/?owner=yo").context["risks"]] == [mine.pk]


def test_risk_page_assigns_and_treatment_keeps_the_choice(client, as_role, make_user):
    me = as_role(OPERATOR, username="yo")
    colleague = make_user(OPERATOR, username="colega")
    risk = _risk_of(_nginx_asset())
    body = client.get(f"/detection/risks/{risk.pk}/").content.decode()
    assert "Sin responsable: ni el riesgo ni el activo tienen uno" in body
    assert 'name="responsible"' in body and "Otro equipo o persona sin cuenta" in body
    assert "El del activo (hoy no tiene)" in body

    response = client.post(
        f"/detection/risks/{risk.pk}/assign/", {"responsible": str(colleague.pk)}, follow=True
    )
    body = response.content.decode()
    assert "Responsable: colega." in body and "recibirá el aviso" in body
    assert "Lo ve en «a mi nombre» y recibe el aviso" in body
    risk.refresh_from_db()
    assert risk.assignee == colleague and risk.assigned_by == me and risk.treatment == ""
    # Un equipo sin cuenta exige el nombre.
    response = client.post(
        f"/detection/risks/{risk.pk}/assign/", {"responsible": "other", "owner": ""}, follow=True
    )
    assert "Escribe el equipo o la persona responsable" in response.content.decode()

    # Al decidir el tratamiento, el selector trae el responsable actual y se puede cambiar.
    due = "2031-01-15"
    client.post(
        f"/detection/risks/{risk.pk}/treatment/",
        {"treatment": "MITIGATE", "responsible": str(me.pk), "target_date": due},
    )
    risk.refresh_from_db()
    assert risk.assignee == me and risk.owner == "" and risk.status == RiskStatus.TREATED
    assert "responsable yo" in risk.events.filter(kind="TREATMENT").last().message
    client.post(
        f"/detection/risks/{risk.pk}/treatment/",
        {"treatment": "MITIGATE", "responsible": "other", "owner": "Redes", "target_date": due},
    )
    risk.refresh_from_db()
    assert risk.assignee is None and risk.owner == "Redes"
    # El servicio sigue aceptando el texto libre de antes.
    risks.set_treatment(risk.pk, user=me, treatment="ACCEPT", note="Compensado", owner="CISO")
    risk.refresh_from_db()
    assert risk.owner == "CISO" and risk.assignee is None
    # El auditor no asigna.
    as_role(AUDITOR)
    assert (
        client.post(f"/detection/risks/{risk.pk}/assign/", {"responsible": "inherit"}).status_code
        == 403
    )


def test_bulk_assign_does_not_decide_the_treatment(client, as_role, make_user):
    as_role(OPERATOR)
    colleague = make_user(OPERATOR, username="colega")
    first = _risk_of(_nginx_asset("web-a", "10.9.0.21"))
    second = _risk_of(_nginx_asset("web-b", "10.9.0.22"))
    body = client.get("/detection/").content.decode()
    assert "Asignar responsable" in body and "Cada uno conserva el suyo" in body
    ids = [str(first.pk), str(second.pk)]
    response = client.post(
        "/detection/risks/bulk/",
        {"ids": ids, "treatment": "ASSIGN", "responsible": str(colleague.pk)},
        follow=True,
    )
    assert "2 riesgos → responsable: colega." in response.content.decode()
    first.refresh_from_db(), second.refresh_from_db()
    assert first.assignee == colleague and second.assignee == colleague
    assert first.treatment == "" and first.status == RiskStatus.OPEN
    # Sin elegir a quién, no hace nada y lo dice.
    response = client.post(
        "/detection/risks/bulk/", {"ids": ids, "treatment": "ASSIGN"}, follow=True
    )
    assert "Elige a quién asignar" in response.content.decode()
    # Un tratamiento en lote sin tocar el responsable conserva el de cada uno.
    client.post(
        "/detection/risks/bulk/",
        {"ids": ids, "treatment": "ACCEPT", "note": "Compensado por el WAF"},
    )
    first.refresh_from_db()
    assert first.status == RiskStatus.ACCEPTED and first.assignee == colleague


# --------------------------------------------------------------------------
# N5 · exportar lo filtrado
# --------------------------------------------------------------------------


def _csv(response):
    assert response.status_code == 200 and response["Content-Type"].startswith("text/csv")
    assert "attachment" in response["Content-Disposition"]
    text = response.content.decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(text)))


def test_risk_list_exports_what_is_filtered(client, as_role, make_user):
    as_role(AUDITOR)  # exportar es leer: quien ve la lista la descarga
    owner = make_user(OPERATOR, username="ana")
    first = _risk_of(_nginx_asset("web-a", "10.9.0.31", technical_owner=owner))
    second = _risk_of(_nginx_asset("web-b", "10.9.0.32"))
    body = client.get("/detection/").content.decode()
    assert "Exportar la lista" in body and "?export=csv" in body
    body = client.get(f"/detection/?asset={first.asset_id}&owner=ana").content.decode()
    assert "Exportar lo filtrado" in body and "owner=ana" in body.split("data-export")[0][-300:]

    rows = _csv(client.get("/detection/?export=csv"))
    assert {r["activo"] for r in rows} == {"web-a", "web-b"}
    mine = next(r for r in rows if r["activo"] == "web-a")
    assert mine["responsable"] == "ana"
    assert mine["responsable_origen"] == "responsable técnico del activo"
    assert mine["riesgo"] == first.title and mine["vulnerabilidades"] and mine["plazo_politica"]
    rows = _csv(client.get("/detection/?export=csv&owner=ana"))
    assert [r["activo"] for r in rows] == ["web-a"]
    rows = _csv(client.get(f"/detection/?export=csv&asset={second.asset_id}&page=7"))
    assert [r["activo"] for r in rows] == ["web-b"] and rows[0]["responsable"] == ""
    assert _csv(client.get("/detection/?export=csv&level=LOW&status=CLOSED")) == []


def test_vulnerability_list_exports_one_row_per_vulnerability(client, as_role):
    as_role(AUDITOR)
    first = _nginx_asset("web-a", "10.9.0.41")
    _nginx_asset("web-b", "10.9.0.42")
    total = Vulnerability.objects.count()
    body = client.get("/detection/vulnerabilities/").content.decode()
    assert "Exportar la lista" in body and "export=csv" in body
    rows = _csv(client.get("/detection/vulnerabilities/?export=csv"))
    # La lista agrupa por software; el archivo trae una fila por vulnerabilidad.
    assert len(rows) == total and {r["activo"] for r in rows} == {"web-a", "web-b"}
    assert all(r["clave"].startswith("CVE-") and r["software"] for r in rows)
    assert all(r["fuentes"] and r["estado"] and r["detectada"] for r in rows)
    rows = _csv(client.get(f"/detection/vulnerabilities/?export=csv&asset={first.pk}"))
    assert rows and {r["activo"] for r in rows} == {"web-a"}
    key = rows[0]["clave"]
    rows = _csv(client.get(f"/detection/vulnerabilities/?export=csv&q={key}&view=flat"))
    assert rows and {r["clave"] for r in rows} == {key}
    # Inicio descarga con las mismas columnas.
    home = _csv(client.get("/home/export/vulnerabilities.csv"))
    assert home and set(home[0]) == set(rows[0])

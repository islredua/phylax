"""Revisión del 2026-11-16, bloque 1: que el trabajo quepa en una jornada (W1, W2, W3).

- W1: las vulnerabilidades se ven por lo que hay que corregir (un software en un activo).
- W2: el mismo tratamiento para varios riesgos a la vez.
- W3: plazos por nivel de riesgo, que proponen la fecha compromiso y miden lo que va tarde.

Sin red, sin LLM real (modo simulado) y sin herramientas.
"""

import datetime
import json
from pathlib import Path

import pytest
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti import services as cti
from apps.cti.models import CveProduct
from apps.detection import components, consolidation, findings, grouping, matching, policy, risks
from apps.detection.models import (
    AutomationLogEntry,
    FindingEvidence,
    FindingSource,
    Risk,
    RiskStatus,
    StatusSource,
    Vulnerability,
    VulnerabilityStatus,
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

    cache.clear()
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    settings.LLM_MOCK_MODE = True
    cti.import_fixture(json.loads(LAB_CTI.read_text()))


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
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


def _risk(asset, level, *, days_ago=0, key=None, **extra):
    return Risk.objects.create(
        asset=asset,
        key=key or f"K:{level}:{days_ago}",
        title=f"Pérdida de datos en {asset.name} por fallo {level}",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=4,
        impact=4,
        level=level,
        first_identified_at=timezone.now() - datetime.timedelta(days=days_ago),
        **extra,
    )


# --------------------------------------------------------------------------
# W1 · por software a corregir
# --------------------------------------------------------------------------


def test_panel_groups_vulnerabilities_by_software_to_fix(client, as_role):
    as_role(OPERATOR)
    first = _nginx_asset()
    second = _nginx_asset("web-poniente", "10.9.0.11")
    total = Vulnerability.objects.count()
    assert total >= 2

    response = client.get("/detection/vulnerabilities/")
    body = response.content.decode()
    groups = response.context["groups"]
    assert response.context["view"] == "software"
    assert {g["asset"].pk for g in groups} == {first.pk, second.pk}
    assert sum(g["total"] for g in groups) == total == response.context["total_vulnerabilities"]
    assert response.context["total_groups"] == len(groups)
    assert "Por software a corregir" in body and "Una por una" in body
    assert "nginx 1.27.3" in body and 'name="groups"' in body and 'name="ids"' not in body

    # La lista de siempre sigue ahí; una búsqueda de texto va directo a ella.
    listed = client.get("/detection/vulnerabilities/?view=list")
    assert listed.context["view"] == "list" and 'name="ids"' in listed.content.decode()
    assert listed.context["paginator"].count == total
    assert client.get("/detection/vulnerabilities/?q=nginx").context["view"] == "list"

    # Abrir un grupo lleva a sus fallas, y solo a las suyas.
    group = next(g for g in groups if g["asset"].pk == first.pk)
    opened = client.get(group["url"])
    assert opened.context["view"] == "list"
    assert opened.context["paginator"].count == group["total"]
    assert opened.context["software_label"].startswith("nginx 1.27.3")
    assert {v.asset_id for v in opened.context["vulnerabilities"]} == {first.pk}

    # Los filtros valen para las dos vistas y un filtro sin resultado lo dice.
    assert client.get("/detection/vulnerabilities/?status=MITIGATED").context["groups"] == []
    empty = client.get("/detection/vulnerabilities/?status=MITIGATED").content.decode()
    assert "Sin coincidencias para estos filtros" in empty


def test_group_fix_version_comes_from_nvd_range_or_grype_never_from_the_model():
    asset = _nginx_asset()
    vuln = Vulnerability.objects.filter(asset=asset).select_related("component").first()
    component = vuln.component
    CveProduct.objects.filter(cve_id=vuln.cve_id).delete()
    CveProduct.objects.create(
        cve_id=vuln.cve_id,
        product_key=component.product_key,
        vendor=component.vendor,
        product="nginx",
        version_start_including="1.27.0",
        version_end_excluding="1.27.4",
    )
    # Otra rama del mismo producto no aplica a la versión instalada.
    CveProduct.objects.create(
        cve_id=vuln.cve_id,
        product_key=component.product_key,
        product="nginx",
        version_start_including="1.20.0",
        version_end_excluding="1.26.3",
    )
    qs = Vulnerability.objects.filter(asset=asset)

    def fix():
        (row,) = grouping.decorate(grouping.groups(qs.filter(pk=vuln.pk)), qs.filter(pk=vuln.pk))
        return row["fix"]

    assert fix() == {
        "version": "1.27.4",
        "covered": 1,
        "total": 1,
        "missing": 0,
        "unfixed": 0,
        "source": "NVD",
    }
    # Si Grype reportó la versión corregida del paquete, manda Grype (la de su misma rama).
    FindingEvidence.objects.create(
        finding=vuln.observations.first(),
        source=FindingSource.GRYPE,
        summary="Grype",
        data={"fix": "fixed 1.26.9, 1.27.9"},
        observed_at=timezone.now(),
    )
    assert fix()["version"] == "1.27.9" and fix()["source"] == "Grype"
    # Un paquete de distribución no se compara con NVD: sin Grype, no se propone versión.
    FindingEvidence.objects.all().delete()
    component.version = "1.27.3-1ubuntu4"
    component.save(update_fields=["version"])
    assert fix() is None

    assert grouping._nearest_above(["2.15.0", "2.12.2", "2.3.1"], "2.14.1") == "2.15.0"
    assert grouping._nearest_above(["2.12.2"], "2.14.1") is None
    assert grouping._grype_fix("not-fixed") == ("not-fixed", [])
    assert grouping.parse_key("no-es-una-clave") is None


def test_bulk_status_applies_to_every_vulnerability_of_the_marked_software(client, as_role):
    operator = as_role(OPERATOR)
    first = _nginx_asset()
    second = _nginx_asset("web-poniente", "10.9.0.11")
    mine = list(Vulnerability.objects.filter(asset=first))
    key = grouping.group_key(first.pk, mine[0].component_id)

    response = client.post(
        "/detection/vulnerabilities/bulk/",
        {"groups": [key], "query": "", "status": "CONFIRMED", "note": ""},
        follow=True,
    )
    assert "software → confirmar, fijado por ti" in response.content.decode()
    for vuln in Vulnerability.objects.filter(asset=first):
        assert vuln.status == VulnerabilityStatus.CONFIRMED
        assert vuln.status_source == StatusSource.HUMAN and vuln.status_by == operator
    assert not Vulnerability.objects.filter(asset=second, status_source=StatusSource.HUMAN).exists()

    # El grupo marcado son sus vulnerabilidades dentro de los filtros con los que se veía.
    client.post(
        "/detection/vulnerabilities/bulk/",
        {"groups": [key], "query": "status=NEEDS_VERIFICATION", "status": "MITIGATED"},
    )
    assert not Vulnerability.objects.filter(asset=first, status="MITIGATED").exists()
    # Una clave inventada no toca nada y lo dice.
    response = client.post(
        "/detection/vulnerabilities/bulk/",
        {"groups": ["no-existe"], "status": "CONFIRMED"},
        follow=True,
    )
    assert "Marca al menos una vulnerabilidad o un software" in response.content.decode()
    as_role(AUDITOR)
    denied = client.post(
        "/detection/vulnerabilities/bulk/", {"groups": [key], "status": "MITIGATED"}
    )
    assert denied.status_code == 403


# --------------------------------------------------------------------------
# W3 · plazos por nivel
# --------------------------------------------------------------------------


def test_policy_deadline_by_level_and_by_cisa_matches_the_overdue_filter():
    asset = _nginx_asset()
    Risk.objects.all().delete()
    today = timezone.localdate()
    late = _risk(asset, "CRITICAL", days_ago=10)
    fresh = _risk(asset, "CRITICAL", days_ago=2)
    high = _risk(asset, "HIGH", days_ago=10)
    accepted = _risk(asset, "CRITICAL", days_ago=40, key="acc", status=RiskStatus.ACCEPTED)
    treated = _risk(asset, "CRITICAL", days_ago=40, key="tr", status=RiskStatus.TREATED)

    due = policy.deadline(late)
    assert due.overdue and due.late_days == 3 and due.state == "late" and due.basis == "level"
    assert due.when == "venció hace 3 días" and "7 días para un riesgo crítico" in due.rule
    assert (
        policy.deadline(fresh).remaining == 5 and policy.deadline(fresh).when == "vence en 5 días"
    )
    assert policy.deadline(high).remaining == 20 and policy.deadline(high).state == "ok"
    # Un riesgo aceptado no tiene plazo; uno en tratamiento sigue midiéndose contra la política.
    assert policy.deadline(accepted) is None
    assert policy.deadline(treated).overdue
    assert policy.suggested_target(fresh) == today + datetime.timedelta(days=5)
    assert policy.suggested_target(late) is None

    def overdue_pks():
        return set(Risk.objects.filter(policy.overdue_filter()).values_list("pk", flat=True))

    assert overdue_pks() == {late.pk, treated.pk}

    # Un plazo de CISA vigente al identificarse y más corto que el del nivel manda.
    vuln = Vulnerability.objects.filter(asset=asset).first()
    high.vulnerabilities.add(vuln)
    Vulnerability.objects.filter(pk=vuln.pk).update(
        in_kev=True, kev_due_at=today - datetime.timedelta(days=1)
    )
    due = policy.deadline(high)
    assert due.basis == "cisa" and due.overdue and "CISA" in due.rule
    assert high.pk in overdue_pks()
    annotated = policy.with_kev_due(Risk.objects.filter(pk=high.pk)).get()
    assert policy.deadline(annotated).basis == "cisa"
    # Uno que ya había vencido cuando el riesgo se identificó no es un plazo que se pueda cumplir.
    Vulnerability.objects.filter(pk=vuln.pk).update(kev_due_at=today - datetime.timedelta(days=400))
    assert policy.deadline(high).basis == "level" and high.pk not in overdue_pks()
    # Y con la opción apagada, CISA no cuenta.
    Vulnerability.objects.filter(pk=vuln.pk).update(kev_due_at=today - datetime.timedelta(days=1))
    rules = policy.current()
    rules.use_cisa_deadline = False
    rules.save()
    assert policy.deadline(high).basis == "level" and high.pk not in overdue_pks()

    summary = risks.summary()
    assert summary["policy_overdue"] == len(overdue_pks())
    assert policy.overview()["late"] == len(overdue_pks())


def test_policy_page_saves_logs_and_rejects_inverted_deadlines(client, as_role):
    admin = as_role(ADMIN)
    page = client.get("/detection/risks/policy/")
    assert page.status_code == 200 and "Plazos para tratar un riesgo" in page.content.decode()
    data = {
        "critical_days": 5,
        "very_high_days": 10,
        "high_days": 20,
        "moderate_days": 60,
        "low_days": 120,
        "accept_review_days": 90,
        "use_cisa_deadline": "on",
    }
    assert client.post("/detection/risks/policy/", data).status_code == 302
    rules = policy.current()
    assert (rules.critical_days, rules.low_days, rules.accept_review_days) == (5, 120, 90)
    assert rules.updated_by == admin
    entry = AutomationLogEntry.objects.latest("timestamp")
    assert "Plazos de tratamiento" in entry.message and "7 → 5" in entry.message

    # Un riesgo más grave no puede tener más plazo que uno menos grave.
    response = client.post("/detection/risks/policy/", {**data, "critical_days": 40})
    assert response.status_code == 200
    assert "más grave no puede tener más plazo" in response.content.decode()
    assert policy.current().critical_days == 5

    # Aceptar sin fecha de revisión usa el plazo de la política, no un número fijo.
    asset = _nginx_asset()
    risk = Risk.objects.filter(asset=asset).first()
    risks.set_treatment(risk.pk, user=admin, treatment="ACCEPT", note="Sistema por retirar")
    risk.refresh_from_db()
    assert risk.review_at == timezone.localdate() + datetime.timedelta(days=90)

    # El Analista la consulta; solo el administrador la cambia.
    as_role(OPERATOR)
    body = client.get("/detection/risks/policy/").content.decode()
    assert "Solo un administrador cambia los plazos" in body
    assert client.post("/detection/risks/policy/", data).status_code == 403
    assert policy.current().critical_days == 5


def test_risk_pages_show_the_policy_deadline_and_propose_it_as_commitment(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    Risk.objects.all().delete()
    fresh = _risk(asset, "CRITICAL", days_ago=0)
    late = _risk(asset, "HIGH", days_ago=45)
    today = timezone.localdate()

    body = client.get(f"/detection/risks/{fresh.pk}/").content.decode()
    proposed = (today + datetime.timedelta(days=7)).isoformat()
    assert "Plazo según la política" in body and "vence en 7 días" in body
    assert f'name="target_date" type="date" class="form-input" value="{proposed}"' in body
    assert "Propuesta: el plazo de la política" in body

    body = client.get(f"/detection/risks/{late.pk}/").content.decode()
    assert "venció hace 15 días" in body and "Ya venció" in body
    assert 'name="target_date" type="date" class="form-input" value=""' in body

    page = client.get("/detection/")
    body = page.content.decode()
    assert "vence en 7 días" in body and "venció hace 15 días" in body
    assert "Fuera de plazo" in body and page.context["summary"]["policy_overdue"] == 1
    assert "riesgo fuera del plazo que fija la política" in body
    only = client.get("/detection/?policy_overdue=1")
    assert [r.pk for r in only.context["risks"]] == [late.pk]
    item = next(i for i in risks.today() if "fuera del plazo" in i["text"])
    assert item["count"] == 1 and "policy_overdue=1" in item["url"] and item["work_url"]


# --------------------------------------------------------------------------
# W2 · el mismo tratamiento para varios riesgos
# --------------------------------------------------------------------------


def test_bulk_treatment_decides_several_risks_with_the_policy_deadline(client, as_role):
    operator = as_role(OPERATOR)
    asset = _nginx_asset()
    Risk.objects.all().delete()
    fresh = _risk(asset, "CRITICAL", days_ago=0)
    other = _risk(asset, "HIGH", days_ago=1, owner="Redes")
    late = _risk(asset, "CRITICAL", days_ago=30, key="late")
    closed = _risk(asset, "LOW", days_ago=1, key="closed", status=RiskStatus.CLOSED)
    today = timezone.localdate()

    body = client.get("/detection/").content.decode()
    assert "Para los marcados" in body and body.count('name="ids"') == 3
    assert 'data-require="risk-bulk-note"' in body

    ids = [str(r.pk) for r in (fresh, other, late, closed)]
    response = client.post(
        "/detection/risks/bulk/",
        {"ids": ids, "treatment": "MITIGATE", "owner": "", "note": "Parche del fabricante"},
        follow=True,
    )
    body = response.content.decode()
    assert "2 riesgos → mitigar · compromiso según el plazo de la política" in body
    assert "1 no se cambió: su plazo según la política ya venció" in body
    assert "1 no se cambió: está cerrado y no admite tratamiento" in body
    (
        fresh.refresh_from_db(),
        other.refresh_from_db(),
        late.refresh_from_db(),
        closed.refresh_from_db(),
    )
    assert fresh.status == RiskStatus.TREATED and fresh.decided_by == operator
    assert fresh.target_date == today + datetime.timedelta(days=7)
    assert other.target_date == today + datetime.timedelta(days=29)
    assert other.owner == "Redes"  # el responsable vacío conserva el que ya tenía
    assert late.treatment == "" and closed.treatment == ""

    # Con fecha y responsable explícitos se aplican a todos los que admiten tratamiento.
    target = today + datetime.timedelta(days=20)
    response = client.post(
        "/detection/risks/bulk/",
        {
            "ids": ids,
            "treatment": "TRANSFER",
            "owner": "Proveedor",
            "target_date": target.isoformat(),
        },
        follow=True,
    )
    assert "3 riesgos → transferir · responsable: Proveedor" in response.content.decode()
    late.refresh_from_db(), other.refresh_from_db()
    assert late.treatment == "TRANSFER" and late.target_date == target
    assert other.owner == "Proveedor"

    # Aceptar sin nota no se aplica a ninguno; con nota queda aceptado con fecha de revisión.
    response = client.post(
        "/detection/risks/bulk/", {"ids": ids[:2], "treatment": "ACCEPT"}, follow=True
    )
    assert "2 no se cambiaron: Aceptar un riesgo exige una nota" in response.content.decode()
    client.post(
        "/detection/risks/bulk/",
        {"ids": ids[:1], "treatment": "ACCEPT", "note": "Se retira en enero"},
    )
    fresh.refresh_from_db()
    assert fresh.status == RiskStatus.ACCEPTED
    assert fresh.review_at == today + datetime.timedelta(days=180)

    assert (
        "Marca al menos un riesgo"
        in client.post(
            "/detection/risks/bulk/", {"treatment": "MITIGATE"}, follow=True
        ).content.decode()
    )
    as_role(AUDITOR)
    assert (
        client.post("/detection/risks/bulk/", {"ids": ids, "treatment": "AVOID"}).status_code == 403
    )
    assert 'name="ids"' not in client.get("/detection/").content.decode()

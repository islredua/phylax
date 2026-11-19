"""Revisión del 2026-11-16, O4: lo que solo crece tiene un plazo de retención.

Tres registros crecían sin límite: las señales que el filtro descartó, los cambios de las fuentes
de inteligencia y las inferencias del modelo. La política dice cuántos días se conserva cada uno;
lo que algo vigente sigue citando no se quita nunca.
"""

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.cti.models import CtiChange, CtiSyncRun, CveRecord
from apps.detection.models import (
    AutomationLogEntry,
    DetectionEvent,
    EventStatus,
    LogKind,
    PlannerDecision,
)
from apps.llm.models import InferenceLog
from apps.presentation import indicators, retention
from apps.presentation.models import HealthNarrative, RetentionPolicy
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db


def _aged(obj, days):
    """Deja ``obj`` como si se hubiera creado hace ``days`` días."""
    type(obj).objects.filter(pk=obj.pk).update(created_at=timezone.now() - timedelta(days=days))
    return obj


def _event(days, status=EventStatus.FILTERED, key=None):
    event = DetectionEvent.objects.create(
        kind="CTI_NEW_CVE", status=status, dedupe_key=key or f"cve:{days}:{status}"
    )
    return _aged(event, days)


def _inference(days, task="VULN_DESCRIBE"):
    log = InferenceLog.objects.create(task=task, model="m", prompt_version="v1", parsed_ok=True)
    return _aged(log, days)


def _change(days, run, cve):
    return _aged(CtiChange.objects.create(run=run, cve=cve, kind="CVE_MODIFIED"), days)


def test_defaults_keep_three_months_of_noise_and_six_of_inferences():
    policy = retention.current()
    assert (policy.discarded_events_days, policy.cti_changes_days, policy.inference_days) == (
        90,
        90,
        180,
    )
    rows = {row["key"]: row for row in retention.overview()["rows"]}
    assert list(rows) == ["events", "cti_changes", "inferences"]
    assert all(row["pending"] == 0 and not row["raised"] for row in rows.values())


def test_only_old_discarded_signals_without_decisions_are_removed():
    old = _event(120)
    recent = _event(10)
    decided = _event(120, key="con-decision")
    PlannerDecision.objects.create(event=decided, action="RECONCILE")
    worked = _event(120, status=EventStatus.RECONCILED)

    assert retention.apply(dry_run=True)["events"] == 1
    assert DetectionEvent.objects.count() == 4  # contar no borra
    result = retention.apply()

    assert result["events"] == 1 and result["capped"] is False
    assert not DetectionEvent.objects.filter(pk=old.pk).exists()
    assert set(DetectionEvent.objects.values_list("pk", flat=True)) == {
        recent.pk,
        decided.pk,
        worked.pk,
    }
    assert PlannerDecision.objects.count() == 1


def test_intelligence_changes_go_and_the_catalogue_stays():
    run = CtiSyncRun.objects.create(source="NVD")
    cve = CveRecord.objects.create(cve_id="CVE-2026-0001")
    old, recent = _change(120, run, cve), _change(5, run, cve)

    assert retention.apply()["cti_changes"] == 1

    assert list(CtiChange.objects.all()) == [recent]
    assert not CtiChange.objects.filter(pk=old.pk).exists()
    assert CtiSyncRun.objects.filter(pk=run.pk).exists()
    assert CveRecord.objects.filter(pk=cve.pk).exists()


def test_an_inference_something_still_cites_is_never_removed():
    """Incluida la que protege la base de datos: borrar la inferencia de una sugerencia de
    criticidad fallaría (``PROTECT``); la retención ni lo intenta."""
    from apps.assets.models import CriticalitySuggestion

    replaced = _inference(400)
    recent = _inference(20)
    narrated = _inference(400, task="HEALTH_NARRATIVE")
    HealthNarrative.objects.create(
        payload_hash="h", status="OK", headline="t", summary="s", inference=narrated
    )
    suggested = _inference(400, task="ASSET_CRITICALITY")
    CriticalitySuggestion.objects.create(
        asset=AssetFactory(), llm_class="BAJO", suggested="BAJO", rationale="", inference=suggested
    )

    assert retention.apply()["inferences"] == 1

    assert not InferenceLog.objects.filter(pk=replaced.pk).exists()
    assert set(InferenceLog.objects.values_list("pk", flat=True)) == {
        recent.pk,
        narrated.pk,
        suggested.pk,
    }
    # Cuando lo que la citaba desaparece, la siguiente pasada ya puede quitarla.
    HealthNarrative.objects.all().delete()
    assert retention.apply()["inferences"] == 1
    assert not InferenceLog.objects.filter(pk=narrated.pk).exists()


def test_every_reference_to_an_inference_is_taken_from_the_schema():
    """Una relación nueva hacia ``InferenceLog`` queda protegida sin tocar la retención."""
    names = {
        (rel.related_model._meta.label, rel.field.name)
        for rel in retention.citing_relations(InferenceLog)
    }
    assert {
        ("assets.CriticalitySuggestion", "inference"),
        ("detection.Vulnerability", "inference"),
        ("detection.Risk", "inference"),
        ("detection.PlannerDecision", "inference"),
        ("presentation.HealthNarrative", "inference"),
    } <= names
    assert {rel.related_model.__name__ for rel in retention.citing_relations(DetectionEvent)} == {
        "PlannerDecision",
        "PlannedAction",
    }


def test_zero_means_keep_forever():
    RetentionPolicy.objects.update_or_create(
        pk=1, defaults={"discarded_events_days": 0, "cti_changes_days": 0, "inference_days": 0}
    )
    _event(900)
    _inference(900)
    run = CtiSyncRun.objects.create(source="NVD")
    _change(900, run, CveRecord.objects.create(cve_id="CVE-2026-0002"))

    assert retention.apply() == {"events": 0, "cti_changes": 0, "inferences": 0, "capped": False}
    assert DetectionEvent.objects.count() == InferenceLog.objects.count() == 1
    assert CtiChange.objects.count() == 1


def test_nothing_inside_the_period_home_shows_is_removed():
    """Inicio cuenta las señales y las inferencias de su periodo: aunque la política diga menos,
    lo que cae dentro se conserva, y la pantalla lo dice."""
    RetentionPolicy.objects.update_or_create(
        pk=1, defaults={"discarded_events_days": 30, "inference_days": 30, "cti_changes_days": 30}
    )
    settings_row = indicators.get_settings()
    settings_row.trend_days = 60
    settings_row.save()
    inside, outside = _event(45, key="dentro"), _event(75, key="fuera")
    run = CtiSyncRun.objects.create(source="NVD")
    change = _change(45, run, CveRecord.objects.create(cve_id="CVE-2026-0003"))

    rows = {row["key"]: row for row in retention.overview()["rows"]}
    assert rows["events"]["effective_days"] == 60 and rows["events"]["raised"]
    assert rows["cti_changes"]["effective_days"] == 30 and not rows["cti_changes"]["raised"]
    assert rows["events"]["pending"] == 1 and rows["cti_changes"]["pending"] == 1

    retention.apply()
    assert DetectionEvent.objects.filter(pk=inside.pk).exists()
    assert not DetectionEvent.objects.filter(pk=outside.pk).exists()
    assert not CtiChange.objects.filter(pk=change.pk).exists()  # Inicio no cuenta cambios


def test_a_big_first_purge_is_spread_over_several_runs(monkeypatch):
    monkeypatch.setattr(retention, "MAX_ROWS_PER_RUN", 3)
    monkeypatch.setattr(retention, "BATCH", 2)
    for index in range(5):
        _event(200, key=f"ruido-{index}")

    first = retention.apply()
    assert first["events"] == 3 and first["capped"] is True
    assert retention.overview()["last_capped"] is True
    second = retention.apply()
    assert second["events"] == 2 and second["capped"] is False
    assert DetectionEvent.objects.count() == 0


def test_the_daily_task_applies_it_and_leaves_a_trace(settings):
    from apps.presentation import tasks

    scheduled = {entry["task"] for entry in settings.CELERY_BEAT_SCHEDULE.values()}
    assert "apps.presentation.tasks.apply_retention" in scheduled
    _event(200)
    assert tasks.apply_retention()["events"] == 1
    summary = retention.overview()
    assert summary["last_run_at"] is not None
    assert summary["last_removed"] == [("Señales descartadas por el filtro", 1)]


def test_command_counts_without_deleting_and_then_deletes(capsys):
    _event(200)
    call_command("apply_retention", "--dry-run")
    assert "se quitarían 1" in capsys.readouterr().out
    assert DetectionEvent.objects.count() == 1
    assert retention.current().last_run_at is None
    call_command("apply_retention")
    assert "se quitaron 1 (se conservan 90 días)" in capsys.readouterr().out
    assert DetectionEvent.objects.count() == 0


def test_only_an_administrator_changes_it_and_it_is_logged(make_user):
    from django.core.exceptions import PermissionDenied, ValidationError

    admin, analyst = make_user(ADMIN, mfa=True), make_user(OPERATOR)
    with pytest.raises(PermissionDenied):
        retention.update(user=analyst, fields={"cti_changes_days": 30})
    with pytest.raises(ValidationError, match="de 7 a 3650"):
        retention.update(user=admin, fields={"cti_changes_days": 3})
    # Menos que el periodo de Inicio descuadraría sus cifras.
    with pytest.raises(ValidationError, match="periodo que muestra Inicio"):
        retention.update(user=admin, fields={"discarded_events_days": 14})
    assert retention.current().cti_changes_days == 90

    retention.update(
        user=admin,
        fields={"cti_changes_days": 30, "discarded_events_days": 0, "inference_days": 180},
    )
    policy = retention.current()
    assert (policy.cti_changes_days, policy.discarded_events_days) == (30, 0)
    assert policy.updated_by == admin
    entry = AutomationLogEntry.objects.get(kind=LogKind.SETTINGS_CHANGED)
    assert entry.user == admin and entry.message.startswith("Retención de datos: ")
    assert "90 → 30" in entry.message and "90 → 0" in entry.message
    assert "inferencias" not in entry.message  # lo que no cambió no se anota


# --- La pantalla: Administración › Sistema -------------------------------------------------


@pytest.fixture
def screen(monkeypatch, settings):
    """La pantalla de Sistema sin servicios que consultar."""
    settings.CELERY_TASK_ALWAYS_EAGER = True
    return "/administration/system/"


def test_administrator_sees_and_changes_retention_on_the_system_screen(client, make_user, screen):
    client.force_login(make_user(ADMIN, mfa=True))
    _event(200)
    body = client.get(screen).content.decode()
    assert 'id="retencion"' in body and "Retención de datos" in body
    assert 'name="discarded_events_days"' in body and 'value="90"' in body
    assert "Guardar retención" in body
    assert "Todavía no ha corrido ninguna depuración." in body
    row = body.split('data-retention="events"')[1].split("</li>")[0]
    assert "Señales descartadas por el filtro" in row and 'data-pending="1"' in row

    response = client.post(
        "/administration/system/retention/",
        {"discarded_events_days": 120, "cti_changes_days": 0, "inference_days": 365},
    )
    assert response.status_code == 302 and response["Location"].endswith("#retencion")
    policy = retention.current()
    assert (policy.discarded_events_days, policy.cti_changes_days, policy.inference_days) == (
        120,
        0,
        365,
    )
    body = client.get(screen).content.decode()
    assert "Retención guardada." in body and "0: se conserva siempre." in body


def test_a_value_out_of_range_comes_back_with_what_was_typed(client, make_user, screen):
    client.force_login(make_user(ADMIN, mfa=True))
    response = client.post(
        "/administration/system/retention/",
        {"discarded_events_days": 90, "cti_changes_days": 3, "inference_days": 180},
    )
    body = response.content.decode()
    assert response.status_code == 200
    assert "de 7 a 3650 días, o 0 para conservar siempre" in body
    assert 'name="cti_changes_days" value="3"' in body
    assert retention.current().cti_changes_days == 90


def test_auditor_reads_retention_and_cannot_change_it(client, make_user, screen):
    client.force_login(make_user(AUDITOR))
    body = client.get(screen).content.decode()
    assert "Retención de datos" in body and "Solo un administrador cambia la retención." in body
    assert 'name="cti_changes_days"' not in body and "Guardar retención" not in body
    response = client.post("/administration/system/retention/", {"cti_changes_days": 30})
    assert response.status_code == 403
    assert retention.current().cti_changes_days == 90

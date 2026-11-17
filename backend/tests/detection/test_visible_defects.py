"""Revisión del 2026-11-16, bloque 2: defectos a la vista (W8, P2, P5, P6, C1).

Sin red, sin LLM real (modo simulado) y sin herramientas.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.utils import timezone

from apps.accounts.roles import ADMIN, OPERATOR
from apps.cti import services as cti
from apps.cti import wording
from apps.cti.models import CtiSource, CtiSyncRun, CveProduct, SourceKind, SyncStatus
from apps.detection import (
    components,
    consolidation,
    descriptions,
    findings,
    matching,
    tasks,
    titles,
)
from apps.detection.models import StatusSource, Vulnerability, VulnerabilityStatus
from apps.llm.language import looks_spanish
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


def _nginx_asset(use_llm=True, name="web-oriente", ip="10.9.0.10"):
    from apps.assets.models import NetworkRange

    if not NetworkRange.objects.filter(cidr="10.9.0.0/24").exists():
        NetworkRangeFactory(cidr="10.9.0.0/24")
    asset = AssetFactory(name=name, criticality="ALTO")
    AssetIdentifierFactory(asset=asset, value=ip)
    ServiceFactory(asset=asset, port=443, service_name="https", product="nginx", version="1.27.3")
    components.refresh_components(asset.pk)
    findings.apply_matches(matching.reconcile_assets([asset.pk]))
    consolidation.consolidate_asset(asset.pk, use_llm=use_llm)
    return asset


def _component(name="wordpress (detectado por wordpress-detect)", key="wordpress", version="4.7"):
    return SimpleNamespace(name=name, product_key=key, version=version)


# --------------------------------------------------------------------------
# W8 · «Corregir estado» no viene elegido de antemano
# --------------------------------------------------------------------------


def test_status_correction_starts_empty_and_an_empty_choice_changes_nothing(client, as_role):
    as_role(OPERATOR)
    asset = _nginx_asset()
    vuln = Vulnerability.objects.filter(asset=asset).first()
    before = (vuln.status, vuln.status_source)
    body = client.get(f"/detection/vulnerabilities/{vuln.pk}/").content.decode()
    assert '<option value="" selected disabled>Elige el estado…</option>' in body
    assert 'id="status" name="status" class="form-input" required' in body
    response = client.post(
        f"/detection/vulnerabilities/{vuln.pk}/status/", {"status": "", "note": ""}, follow=True
    )
    assert "Elige un estado válido" in response.content.decode()
    vuln.refresh_from_db()
    assert (vuln.status, vuln.status_source) == before


# --------------------------------------------------------------------------
# P2 · la lista de vulnerabilidades cabe en la pantalla
# --------------------------------------------------------------------------


def test_vulnerability_list_has_one_priority_column(client, as_role):
    as_role(OPERATOR)
    _nginx_asset()
    body = client.get("/detection/vulnerabilities/?view=list").content.decode()
    table = body[
        body.index("<thead>", body.index('name="query"')) : body.index(
            "</thead>", body.index('name="query"')
        )
    ]
    headers = [h.split(">")[-1] for h in table.split("</th>")[:-1]]
    assert [h for h in headers if h] == [
        "Vulnerabilidad",
        "Activo · software",
        "Prioridad",
        "Estado",
        "Evaluada",
    ]
    assert "técnico <span" in body and "plausible <span" in body


# --------------------------------------------------------------------------
# P5 · miles y plurales
# --------------------------------------------------------------------------


def test_texts_built_by_the_code_use_real_plurals_and_thousands(client, as_role):
    from apps.detection import progress
    from apps.detection.models import AutomationLogEntry, LogKind

    as_role(ADMIN)
    asset = _nginx_asset()
    assert progress.plural(1, "riesgo", "riesgos") == "1 riesgo"
    assert progress.plural(1053, "abierta", "abiertas") == "1,053 abiertas"
    assert progress._seen_label(None) == "… hallazgos vistos"
    assert progress._seen_label(1) == "1 hallazgo visto"
    # Un texto guardado antes de la regla se arregla al mostrarlo, sin cambiar la base.
    entry = AutomationLogEntry.objects.create(
        kind=LogKind.FINISHED,
        asset=asset,
        message="nuclei cves-web: 9 hallazgo(s) distintos de 33753 resultado(s)",
    )
    for path in ("/detection/automation/", "/detection/activity/"):
        body = client.get(path).content.decode()
        assert "9 hallazgos distintos de 33,753 resultados" in body, path
        assert "(s)" not in body and "(es)" not in body, path
    entry.refresh_from_db()
    assert "hallazgo(s)" in entry.message


# --------------------------------------------------------------------------
# P6 · Fuentes CTI sin diccionarios ni excepciones
# --------------------------------------------------------------------------


def test_sync_detail_and_errors_are_phrases():
    assert wording.run_detail({"since": "2026-11-10T21:20:52.945250+00:00"}).startswith(
        "cambios publicados desde el 10 nov 2026"
    )
    assert wording.run_detail({"version": "2026.11.06"}) == "catálogo versión 2026.11.06"
    assert wording.run_detail({"score_date": "2026-11-08"}) == "puntajes del 8 nov 2026"
    assert wording.run_detail({"product": "squid", "vendor": "squid-cache"}) == (
        "cobertura del producto squid (squid-cache)"
    )
    assert wording.run_detail({"product": "php", "vendor": "php"}) == "cobertura del producto php"
    assert wording.run_detail({"items": 1}) == "1 registro de un archivo de ejemplo"
    assert wording.run_detail({}) == "" and "{" not in wording.run_detail({"otro": 3})

    assert wording.error_phrase("ReadTimeout: The read operation timed out") == (
        "La fuente tardó demasiado en responder"
    )
    assert "sin DNS" in wording.error_phrase(
        "ConnectError: [Errno -3] Temporary failure in name resolution"
    )
    assert wording.error_phrase("HTTPStatusError: Client error '403 Forbidden' for url") == (
        "La fuente rechazó la petición (HTTP 403)"
    )
    assert "HTTP 503" in wording.error_phrase("HTTPStatusError: Server error '503' for url x")
    assert wording.error_phrase("ZeroDivisionError: division by zero") == (
        "La sincronización falló por un error inesperado"
    )
    # Un mensaje que ya es nuestro se deja como está.
    assert wording.error_phrase(cti.INTERRUPTED_MESSAGE) == cti.INTERRUPTED_MESSAGE
    assert wording.changes_phrase(0) == "sin cambios"
    assert (
        wording.changes_phrase(4582) == "4,582 cambios" and wording.changes_phrase(1) == "1 cambio"
    )


def test_sources_page_shows_phrases_not_raw_values(client, as_role):
    as_role(ADMIN)
    cti.ensure_sources()
    now = timezone.now()
    CtiSyncRun.objects.create(
        source=SourceKind.NVD,
        status=SyncStatus.SUCCEEDED,
        finished_at=now,
        records_seen=90966,
        changes=4582,
        detail={"since": "2026-11-10T21:20:52.945250+00:00"},
    )
    CtiSyncRun.objects.create(
        source=SourceKind.NVD,
        status=SyncStatus.FAILED,
        finished_at=now,
        detail={"product": "wordpress"},
        error="ReadTimeout: The read operation timed out",
    )
    # Lo que quedó guardado con el texto de antes se arregla al mostrarlo.
    CtiSource.objects.filter(kind=SourceKind.NVD).update(
        last_status=SyncStatus.SUCCEEDED, last_detail="4582 cambio(s)", last_success_at=now
    )
    CtiSource.objects.filter(kind=SourceKind.KEV).update(
        last_status=SyncStatus.FAILED, last_detail="ReadTimeout: The read operation timed out"
    )
    body = client.get("/detection/sources/").content.decode()
    assert "cambios publicados desde el 10 nov 2026" in body and "90,966" in body
    assert "La fuente tardó demasiado en responder" in body
    assert "cobertura del producto wordpress" in body and "mensaje original" in body
    assert "4,582 cambios" in body and "cambio(s)" not in body
    assert "{&#x27;" not in body and "{'" not in body

    # Y lo que se guarda de aquí en adelante ya sale bien escrito.
    source = CtiSource.objects.get(kind=SourceKind.EPSS)
    run = CtiSyncRun.objects.create(source=SourceKind.EPSS, changes=15)
    cti._finish(run, source)
    source.refresh_from_db()
    assert source.last_detail == "15 cambios"


# --------------------------------------------------------------------------
# C1 · el título corresponde al software observado
# --------------------------------------------------------------------------


def test_title_rule_swaps_catalog_keys_and_returns_the_version_to_its_software():
    apache = _component("Apache httpd", "http_server", "2.4.49")
    title, notes = titles.coherent("Buffer overflow en mod_lua de http_server 2.4.49", apache)
    assert title == "Buffer overflow en mod_lua de Apache httpd 2.4.49" and notes
    # Un nombre propio con guion bajo se conserva; un título sano no cambia.
    same = "Escritura fuera de límites en mod_sed de Apache httpd 2.4.49"
    assert titles.coherent(same, apache) == (same, [])
    assert titles.coherent("Apache http_server 2.4.49 expone rutas", apache)[0] == (
        "Apache httpd 2.4.49 expone rutas"
    )

    wordpress = _component()
    title, notes = titles.coherent("Ejecución remota de código en PHPMailer 4.7", wordpress)
    assert title == "Ejecución remota de código en PHPMailer (en wordpress 4.7)"
    assert "la versión 4.7 es de wordpress" in notes[0]
    ok = "Inyección de objeto en PHPMailer 6.1.8 en WordPress 4.7"
    assert titles.coherent(ok, wordpress) == (ok, [])
    php = _component("php (detectado por php-detect)", "php", "5.6.29")
    assert titles.coherent("Denegación de servicio en PCRE 8.38 5.6.29", php)[0] == (
        "Denegación de servicio en PCRE 8.38 (en php 5.6.29)"
    )
    # «PHPMailer» no cuenta como mención de php.
    assert not titles.mentions("Falla en PHPMailer", php) and titles.mentions("Falla en PHP 5", php)

    # Una clave de otro producto no se arregla por código: manda la regla.
    with pytest.raises(titles.UnfixableTitleError):
        titles.coherent("Ejecución remota en horizon_daas", None, extra_keys=["horizon_daas"])
    assert (
        titles.reviewed("Ejecución remota en horizon_daas", None, extra_keys=["horizon_daas"])[0]
        is None
    )
    assert (
        titles.readable_product("horizon_daas") == ""
        and titles.readable_product("nginx") == "nginx"
    )
    assert not titles.suspicious("Falla en WordPress 4.7", wordpress)
    assert titles.suspicious("Falla en PHPMailer 4.7", wordpress)

    # Una versión que no sale de lo observado ni del texto técnico se quita, por tramos: si un
    # extremo del rango no tiene sustento se va el rango entero (no queda «Samba 4.0.0»).
    known = "Samba 4.0.0 onwards is affected. PHPMailer 6.1.8 through 6.4.0. wordpress 4.7"
    cut = titles.strip_ungrounded
    assert cut("Bypass de firma en Samba smbd 4.0.0 - 4.2.13", known) == (
        "Bypass de firma en Samba smbd",
        ["4.0.0", "4.2.13"],
    )
    assert cut("Ejecución remota en ESXi y Horizon DaaS (OpenSLP) 6.5.x, 6.7.x", known)[0] == (
        "Ejecución remota en ESXi y Horizon DaaS (OpenSLP)"
    )
    assert cut("Modificación de ACL en Samba smbd 4.0.x < 4.1.23", known)[0] == (
        "Modificación de ACL en Samba smbd"
    )
    assert cut("Falla en Samba 4.9.0 a 4.9.5 permite leer archivos", known)[0] == (
        "Falla en Samba permite leer archivos"
    )
    grounded = "Inyección de objeto en PHPMailer 6.1.8-6.4.0 en WordPress 4.7"
    assert cut(grounded, known) == (grounded, [])
    title, notes = titles.coherent("Enumeración de usuarios en crm-legacy 1.0", None, grounding="")
    assert title == "Enumeración de usuarios en crm-legacy"
    assert notes == ["se quitó la versión 1.0: no sale de lo observado ni del texto técnico"]
    # La versión del propio componente siempre tiene sustento; sin `grounding` no se revisa.
    assert titles.coherent("Falla en WordPress 4.7", wordpress, grounding="")[0] == (
        "Falla en WordPress 4.7"
    )
    assert titles.coherent("Falla en nginx 9.9.9", None)[0] == "Falla en nginx 9.9.9"
    # Si al quitarla el título ya no dice nada, manda la regla.
    assert titles.reviewed("Samba 4.2.13", None, grounding="")[0] is None

    # El portugués no pasa por español.
    assert not looks_spanish(
        "Inconsistência na interpretação de solicitações HTTP em servidor web Apache"
    )
    assert looks_spanish(
        "Inconsistencia en la interpretación de solicitudes HTTP en el servidor web Apache"
    )


def _model_says(monkeypatch, title):
    """El modelo «responde» con ese título (lo demás, la redacción simulada de siempre)."""
    real = descriptions.run_structured

    def fake(**kwargs):
        log_obj = real(**kwargs)
        log_obj.parsed = {**log_obj.parsed, "title": title}
        return log_obj

    monkeypatch.setattr(descriptions, "run_structured", fake)


def test_description_adjusts_or_rejects_the_models_title(monkeypatch):
    asset = _nginx_asset(use_llm=False)
    vuln = (
        Vulnerability.objects.filter(asset=asset, key="CVE-2025-23419")
        .select_related("component")
        .get()
    )
    assert vuln.component.version == "1.27.3"
    rule = descriptions.fallback_title(vuln)

    # La versión observada pegada a otro producto vuelve a su software.
    _model_says(monkeypatch, "Denegación de servicio en OpenSSL 1.27.3")
    assert descriptions.describe_vulnerability(vuln.pk).parsed_ok
    vuln.refresh_from_db()
    assert vuln.title == "Denegación de servicio en OpenSSL (en nginx 1.27.3)"
    assert "título ajustado por regla" in vuln.events.filter(kind="DESCRIBED").last().message

    # Versiones que no vienen de nada de lo que el modelo recibió: fuera.
    _model_says(monkeypatch, "Desbordamiento de memoria en nginx 9.9.9 a 9.9.12")
    descriptions.describe_vulnerability(vuln.pk)
    vuln.refresh_from_db()
    assert vuln.title == "Desbordamiento de memoria en nginx"
    assert "se quitaron las versiones 9.9.9, 9.9.12" in (
        vuln.events.filter(kind="DESCRIBED").last().message
    )

    # Una clave de catálogo de otro producto: se descarta y queda el título de la regla.
    CveProduct.objects.create(cve_id=vuln.cve_id, product_key="f5:nginx_plus", product="nginx_plus")
    _model_says(monkeypatch, "Denegación de servicio en nginx_plus")
    descriptions.describe_vulnerability(vuln.pk)
    vuln.refresh_from_db()
    assert vuln.title == rule[:200] and "nginx_plus" not in vuln.title
    assert "se descartó" in vuln.events.filter(kind="DESCRIBED").last().message

    # Portugués: tampoco pasa.
    _model_says(monkeypatch, "Inconsistência na interpretação de solicitações em nginx")
    descriptions.describe_vulnerability(vuln.pk)
    vuln.refresh_from_db()
    assert vuln.title == rule[:200]

    # El modelo ya no recibe claves: ni en el título de referencia ni en la evidencia.
    payload = descriptions.build_payload(vuln)["vulnerability"]
    assert "_" not in payload["reference_title"]
    assert any("nginx 1.27.3 está en el rango afectado" in line for line in payload["evidence"])


def test_stored_titles_are_reviewed_once_in_the_periodic_task(monkeypatch):
    asset = _nginx_asset(use_llm=False)
    other = _nginx_asset(use_llm=False, name="web-poniente", ip="10.9.0.11")
    fixable = Vulnerability.objects.select_related("component").get(
        asset=asset, key="CVE-2025-23419"
    )
    unfixable = Vulnerability.objects.get(asset=other, key="CVE-2025-23419")
    human = Vulnerability.objects.create(
        asset=asset,
        key="MANUAL:X",
        title="Falla en PHPMailer 1.27.3",
        component=fixable.component,
        severity="HIGH",
        first_detected_at=timezone.now(),
        last_seen_at=timezone.now(),
        status=VulnerabilityStatus.CONFIRMED,
        status_at=timezone.now(),
        summary="Texto de una persona.",
        description_source=StatusSource.HUMAN,
    )
    CveProduct.objects.create(
        cve_id=unfixable.cve_id, product_key="f5:nginx_plus", product="nginx_plus"
    )
    Vulnerability.objects.filter(pk=fixable.pk).update(
        title="Ejecución remota de código en PHPMailer 1.27.3",
        summary="Texto.",
        description_source=StatusSource.AI,
    )
    Vulnerability.objects.filter(pk=unfixable.pk).update(
        title="Ejecución remota de código en nginx_plus",
        summary="Texto.",
        description_source=StatusSource.AI,
    )
    queued = []
    monkeypatch.setattr(descriptions, "active_model_ready", lambda: True)
    monkeypatch.setattr(tasks.describe_vulnerability, "apply_async", lambda **kw: queued.append(kw))

    result = tasks.describe_pending_vulnerabilities()
    assert result["titles"] == {"fixed": 1, "redone": 1}
    fixable.refresh_from_db(), unfixable.refresh_from_db(), human.refresh_from_db()
    assert fixable.title == "Ejecución remota de código en PHPMailer (en nginx 1.27.3)"
    event = fixable.events.filter(kind="DESCRIBED").last()
    assert "Título ajustado por regla" in event.message
    assert event.data["previous_title"] == "Ejecución remota de código en PHPMailer 1.27.3"
    # El que no se arregla por código vuelve al título de la regla y se pide de nuevo al modelo.
    assert unfixable.title == descriptions.fallback_title(unfixable)[:200]
    assert [q["args"] for q in queued] == [[str(unfixable.pk)]]
    assert human.title == "Falla en PHPMailer 1.27.3"  # lo que fijó una persona no se toca

    # Una vez por versión de las reglas; y repetirlo no cambia nada.
    assert "titles" not in tasks.describe_pending_vulnerabilities()
    assert descriptions.review_titles() == {"fixed": 0, "redone": 0}

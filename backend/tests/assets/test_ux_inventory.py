"""Correcciones de la revisión UX del 2026-11-09, bloque Inventario, Descubrimiento y
Administración (A1–A12, F6, F7, T5). Sin red, sin LLM real y sin nmap."""

import pytest
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile

from apps.accounts.roles import ADMIN, OPERATOR
from apps.assets.enums import AssetStatus, Criticality, CriticalitySource, IdentifierKind
from apps.assets.models import CriticalitySuggestion, PendingUpload
from apps.discovery.models import DiscoveryRun
from apps.llm import status as llm_status
from tests.factories import AssetFactory, AssetIdentifierFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


@pytest.fixture(autouse=True)
def _setup(monkeypatch, settings):
    from django.db import transaction

    settings.LLM_MOCK_MODE = True
    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


# --- A6: lista ordenable, chips que conservan filtros, «Revisar IA» -----------------------


def test_list_sorts_by_criticality_and_filters_ai_unreviewed(client, as_role):
    as_role(OPERATOR)
    AssetFactory(name="bajo", criticality=Criticality.BAJO)
    AssetFactory(name="critico", criticality=Criticality.CRITICO)
    AssetFactory(name="sin", criticality=None)
    AssetFactory(
        name="auto", criticality=Criticality.ALTO, criticality_source=CriticalitySource.LLM_AUTO
    )
    names = [a.name for a in client.get("/inventory/?sort=-criticality").context["assets"]]
    assert names[:3] == ["critico", "auto", "bajo"] and names[-1] == "sin"
    names = [a.name for a in client.get("/inventory/?sort=criticality").context["assets"]]
    assert names[0] == "sin" and names[-1] == "critico"  # los sin clasificar van juntos
    assert [a.name for a in client.get("/inventory/?sort=basura").context["assets"]][0] == "auto"
    response = client.get("/inventory/?criticality=llm_auto&environment=PROD")
    assert [a.name for a in response.context["assets"]] == ["auto"]
    body = response.content.decode()
    assert "Revisar IA · 1" in body
    # Los chips de estado conservan el resto de los filtros.
    assert "criticality=llm_auto" in body.split("Activos <span")[1].split("</div>")[0]
    assert "aria-sort" not in client.get("/inventory/").content.decode()
    assert 'aria-sort="descending"' in client.get("/inventory/?sort=-criticality").content.decode()


def test_list_bulk_bar_starts_collapsed_hint_and_empty_state(client, as_role):
    as_role(OPERATOR)
    body = client.get("/inventory/").content.decode()
    assert "data-bulk-hint-empty" in body and "Todavía no hay activos" in body
    body = client.get("/inventory/?q=zzz").content.decode()
    assert "Sin activos para estos filtros" in body and "Limpiar filtros" in body


# --- A1, A4, A5: detalle del activo --------------------------------------------------------


def test_detail_tabs_grouped_and_labels(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(
        criticality=Criticality.ALTO, criticality_source=CriticalitySource.LLM_AUTO
    )
    body = client.get(f"/inventory/{asset.pk}/").content.decode()
    assert "Más acciones" in body and "Sugerencias LLM" not in body
    assert "Servicios y escaneos" in body and "Criticidad (IA)" in body
    assert "Autorizado para escaneo" in body and "Conectividad desde Atalaya" in body
    assert "Alcance de escaneo" not in body and "Alcance desde Atalaya" not in body
    assert "por IA, sin revisar" in body
    # Un solo badge de criticidad en la cabecera; «Ignorar» y «Retirar» explican su diferencia.
    toolbar = body.split('class="toolbar"', 1)[1].split("</div>\n</div>", 1)[0]
    assert toolbar.count("badge-high") == 1
    assert "se puede restaurar" in body and "no se puede reactivar" in body
    # La pestaña antigua «descubrimientos» sigue abriendo (ahora dentro de Servicios).
    body = client.get(f"/inventory/{asset.pk}/?tab=descubrimientos").content.decode()
    assert "Escaneos y descubrimientos que lo tocaron" in body


def test_detection_tabs_are_capped_with_link_to_detection(client, as_role, monkeypatch):
    from apps.detection import findings
    from apps.detection import views as detection_views

    as_role(OPERATOR)
    monkeypatch.setattr(detection_views, "ASSET_TAB_LIMIT", 1)
    asset = AssetFactory()
    for i in range(2):
        findings.upsert_finding(
            asset_id=asset.pk,
            vulnerability_id=f"MANUAL:X{i}",
            source="MANUAL",
            title=f"Hallazgo {i}",
            severity="LOW",
            evidence_summary="visto",
        )
    body = client.get(f"/inventory/{asset.pk}/?tab=observaciones").content.decode()
    assert "Se muestran las 1 más recientes de 2" in body and "Ver todas en Observaciones" in body
    assert body.count("MANUAL:X") == 1


def test_history_shows_booleans_in_spanish(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(in_scope=True)
    asset.in_scope = False
    asset.save()
    body = client.get(f"/inventory/{asset.pk}/?tab=historial").content.decode()
    assert ">False<" not in body and "True" not in body
    assert '<span class="text-muted line-through">sí</span> → no' in body


# --- A10: formulario de alta por secciones y errores en su campo --------------------------


def test_create_form_sections_and_authorization_error_on_its_field(client, as_role):
    as_role(ADMIN)
    body = client.get("/inventory/new/").content.decode()
    assert "Identidad" in body and "Contexto para la IA" in body and "recomendado" in body
    assert "Comprobar conectividad" in body and "Verificar alcance" not in body
    assert 'for="id_ident-0-kind"' in body  # identificadores con etiqueta accesible
    response = client.post(
        "/inventory/new/",
        {
            "name": "publico",
            "asset_type": "HOST",
            "environment": "PROD",
            "business_role": "API",
            "in_scope": "on",
            "authorize_scan": "on",
            "authorization_reference": "",
            "ident-TOTAL_FORMS": "1",
            "ident-INITIAL_FORMS": "0",
            "ident-0-kind": "IPV4",
            "ident-0-value": "8.8.8.8",
        },
    )
    form = response.context["form"]
    assert "authorization_reference" in form.errors and not form.non_field_errors()
    assert "dirección pública" in str(form.errors["authorization_reference"])


def test_confirm_page_has_cancel_and_ai_hint(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(status=AssetStatus.UNCONFIRMED)
    body = client.get(
        f"/inventory/{asset.pk}/confirm/?next=/inventory/unconfirmed/"
    ).content.decode()
    assert "Cancelar" in body and "recomendada para la IA" in body


# --- F6: confirmación en lote desde la ejecución ------------------------------------------


def test_bulk_confirm_from_run_inherits_environment_and_role(client, as_role, monkeypatch):
    from apps.discovery import services as discovery_services

    monkeypatch.setattr(discovery_services, "_enqueue", lambda run_id: None)
    as_role(OPERATOR)
    rng = NetworkRangeFactory(cidr="10.93.0.0/24", environment="PROD")
    run = DiscoveryRun.objects.create(network_range=rng, profile="HOST_SWEEP", status="SUCCEEDED")
    hosts = []
    for i in (1, 2):
        host = AssetFactory(
            name=f"10.93.0.{i}",
            status=AssetStatus.UNCONFIRMED,
            environment=None,
            business_role=None,
        )
        AssetIdentifierFactory(asset=host, kind=IdentifierKind.IPV4, value=f"10.93.0.{i}")
        hosts.append(host)
    known = AssetFactory(name="conocido")
    run.assets_touched.add(*hosts, known)
    body = client.get(f"/discovery/runs/{run.pk}/").content.decode()
    assert "Agregar <span" in body and 'name="ids"' in body and "Progreso</th>" in body
    assert '<option value="PROD" selected' in body  # hereda el entorno del rango
    response = client.post(
        "/inventory/confirm/bulk/",
        {
            "ids": [str(h.pk) for h in hosts] + [str(known.pk)],
            "environment": "PROD",
            "business_role": "API",
            "next": f"/discovery/runs/{run.pk}/",
        },
        follow=True,
    )
    for host in hosts:
        host.refresh_from_db()
        assert host.status == AssetStatus.ACTIVE
        assert host.environment == "PROD" and host.business_role == "API"
    text = response.content.decode()
    assert "2 activos agregados al inventario" in text
    assert DiscoveryRun.objects.filter(target_asset__in=hosts).count() == 2  # escaneo automático
    # Sin ids o sin herencia elegida no se confirma nada.
    response = client.post("/inventory/confirm/bulk/", {"environment": "PROD"}, follow=True)
    assert "Marca al menos un host" in response.content.decode()
    response = client.post(
        "/inventory/confirm/bulk/", {"ids": [str(known.pk)], "environment": ""}, follow=True
    )
    assert "Elige el entorno" in response.content.decode()


def test_run_detail_shows_progress_after_confirm(client, as_role):
    as_role(OPERATOR)
    run = DiscoveryRun.objects.create(
        network_range=NetworkRangeFactory(cidr="10.94.0.0/24"),
        profile="HOST_SWEEP",
        status="SUCCEEDED",
        scan_mode="privileged",
    )
    pending = AssetFactory(name="calculando", criticality=None)
    CriticalitySuggestion.objects.create(asset=pending, state="PENDING", trigger="CONFIRM")
    scanning = AssetFactory(name="escaneando", criticality=None)
    DiscoveryRun.objects.create(target_asset=scanning, profile="SERVICE_SCAN", status="RUNNING")
    done = AssetFactory(name="listo", criticality=Criticality.MEDIO)
    none = AssetFactory(name="nada", criticality=None)
    run.assets_touched.add(pending, scanning, done, none)
    body = client.get(f"/discovery/runs/{run.pk}/").content.decode()
    assert "la IA calcula la criticidad" in body and "escaneando servicios" in body
    assert "1 sin criticidad" in body  # los que están en curso no cuentan como pendientes
    assert "con privilegios" in body and ">privileged<" not in body
    # Hosts primero, evidencia técnica plegada después (A12).
    assert body.index("Hosts observados") < body.index("Comandos ejecutados")
    assert "Evidencia técnica" in body


# --- A2: descubrimiento desde la lista, filtros, renovar ---------------------------------


def test_discovery_list_launches_filters_and_offers_renewal(client, as_role, monkeypatch):
    from datetime import timedelta

    from django.utils import timezone

    from apps.discovery import services as discovery_services

    monkeypatch.setattr(discovery_services, "_enqueue", lambda run_id: None)
    as_role(ADMIN)
    body = client.get("/discovery/runs/").content.decode()
    assert "Todavía no hay rangos de red" in body and "Sin ejecuciones todavía" in body
    rng = NetworkRangeFactory(cidr="10.95.0.0/24", name="Oficinas")
    expired = NetworkRangeFactory(
        cidr="10.96.0.0/24",
        name="Vieja",
        authorization_expires_at=timezone.now() - timedelta(days=1),
    )
    body = client.get("/discovery/runs/").content.decode()
    launch = body.split("Descubrir un rango")[1].split("</form>")[0]
    assert "Oficinas" in launch and "Vieja" not in launch  # caducado: no se puede descubrir
    response = client.post(
        "/discovery/runs/launch/", {"network_range": str(rng.pk), "profile": "HOST_SWEEP"}
    )
    run = DiscoveryRun.objects.get()
    assert response.url == f"/discovery/runs/{run.pk}/"
    assert client.get("/discovery/runs/?status=active").context["paginator"].count == 1
    assert client.get("/discovery/runs/?status=SUCCEEDED").context["paginator"].count == 0
    assert client.get("/discovery/runs/?profile=SERVICE_SCAN").context["paginator"].count == 0
    body = client.get("/discovery/runs/?status=SUCCEEDED").content.decode()
    assert "Ninguna ejecución coincide" in body
    # El rango caducado ofrece renovar; el vigente, descubrir.
    body = client.get("/inventory/ranges/").content.decode()
    assert "Renovar autorización" in body and "caducada" in body and "Descubrir</button>" in body
    body = client.get(f"/inventory/ranges/{expired.pk}/").content.decode()
    assert "La autorización caducó" in body and "renovar=1" in body
    body = client.get(f"/inventory/ranges/{expired.pk}/edit/?renovar=1").content.decode()
    assert "Renovar la autorización de Vieja" in body and "Vigente hasta" in body


# --- A7, A9: estados vacíos y clasificación ----------------------------------------------


def test_empty_states_offer_next_step(client, as_role):
    as_role(ADMIN)
    body = client.get("/inventory/unconfirmed/").content.decode()
    assert "No hay hosts por confirmar" in body and "Registrar un rango" in body
    body = client.get("/inventory/ranges/").content.decode()
    assert "Registrar el primero" in body
    body = client.get("/inventory/images/").content.decode()
    assert "Sin imágenes de contenedor" in body and "Registrar imagen" in body
    body = client.get("/inventory/registries/").content.decode()
    assert "Registros de imágenes" in body and "Registries" not in body
    body = client.get("/inventory/conflicts/").content.decode()
    assert "Nada que hacer por ahora" in body


def test_classification_explains_and_counts(client, as_role):
    as_role(OPERATOR)
    AssetFactory(criticality=Criticality.ALTO, criticality_source=CriticalitySource.LLM_AUTO)
    AssetFactory(criticality=None)
    body = client.get("/inventory/classification/").content.decode()
    assert "La IA calcula la criticidad" in body
    assert "Calculadas por IA sin revisar" in body and "criticality=llm_auto" in body
    assert "Fallidas en 24 h" in body and "Sin criticidad" in body


# --- A8: importación con referencia y columnas explicadas --------------------------------


def test_import_page_lists_columns_and_stores_reference(client, as_role):
    as_role(ADMIN)
    body = client.get("/inventory/import/").content.decode()
    assert "Columnas del CSV" in body and "Referencia de la autorización" in body
    assert "PROD (" in body and "Función de negocio" in body
    csv = b"name,asset_type,ipv4,environment,business_role\nweb,HOST,10.97.0.1,PROD,API\n"
    client.post(
        "/inventory/import/",
        {
            "file": SimpleUploadedFile("activos.csv", csv, "text/csv"),
            "authorize_hosts": "1",
            "authorization_reference": "Oficio DG-2026-117",
        },
    )
    upload = PendingUpload.objects.get()
    assert upload.meta["authorization_reference"] == "Oficio DG-2026-117"
    from apps.assets import csv_io

    assert csv_io.authorize_reference(upload) == "Oficio DG-2026-117"
    body = client.get(f"/inventory/import/{upload.pk}/").content.decode()
    assert "Oficio DG-2026-117" in body


# --- F7: LLM caído -------------------------------------------------------------------------


def test_llm_down_disables_ai_buttons_and_says_so(client, as_role, settings):
    settings.LLM_MOCK_MODE = False
    cache.set(llm_status.CACHE_KEY, {"available": False, "accelerator": "gpu", "installed": None})
    assert not llm_status.active_model_ready()
    assert "no responde" in llm_status.unavailable_reason()
    as_role(OPERATOR)
    asset = AssetFactory(criticality=None)
    body = client.get(f"/inventory/{asset.pk}/?tab=sugerencias").content.decode()
    assert "Sugerencia con IA no disponible" in body and "no responde" in body
    assert "fijar a mano" in body
    body = client.get("/inventory/classification/").content.decode()
    assert "Fijar a mano" in body or "no responde" in body
    strip = client.get(f"/detection/assets/{asset.pk}/pipeline/").content.decode()
    assert "no responde" in strip and "se puede fijar a mano" in strip
    cache.set(llm_status.CACHE_KEY, {"available": True, "accelerator": "gpu", "installed": None})
    assert llm_status.active_model_ready() and llm_status.unavailable_reason() == ""


# --- A11, A12, T5: administración y textos --------------------------------------------------


def test_admin_labels_filters_and_readable_metadata(client, as_role, make_user):
    from apps.accounts.audit import record_event
    from apps.accounts.models import AuditEvent

    admin = as_role(ADMIN)
    body = client.get("/administration/").content.decode()
    assert "temp=1" in body
    temp = make_user(OPERATOR, must_change_password=True)
    make_user(OPERATOR)
    page = client.get("/users/?status=active&temp=1")
    assert [u.pk for u in page.context["users"]] == [temp.pk]
    body = client.get(f"/users/{temp.pk}/").content.decode()
    assert "Resetear" not in body
    record_event(AuditEvent.PASSWORD_CHANGED, user=admin, sessions_closed=3, matched_account=True)
    body = client.get("/accounts/audit-log/").content.decode()
    assert 'sesiones cerradas: <span class="font-mono">3</span>' in body
    assert 'cuenta coincidente: <span class="font-mono">sí</span>' in body
    assert "sessions_closed" not in body
    body = client.get("/accounts/me/security/").content.decode()
    assert "data-confirm" in body or "Cerrar las demás" not in body
    body = client.get("/inventory/catalogs/?kind=ASSET_TYPE").content.decode()
    assert ">IPV4<" not in body
    body = client.get("/accounts/login/verify/", follow=True).content.decode()
    assert body  # sin MFA pendiente redirige al login; el texto se prueba en la plantilla
    from django.template.loader import render_to_string

    html = render_to_string("registration/login_verify.html", {"form": None})
    assert "en el mismo campo" in html


def test_llm_settings_show_errors_and_fold_commands(client, as_role, settings):
    from apps.llm.models import InferenceLog

    settings.LLM_MOCK_MODE = False
    settings.LLM_AVAILABLE_MODELS = ["a:1", "falta:2"]
    cache.set(
        llm_status.CACHE_KEY, {"available": False, "accelerator": "cpu", "installed": ["a:1"]}
    )
    InferenceLog.objects.create(
        task="ASSET_CRITICALITY",
        model="a:1",
        parsed_ok=False,
        error="Connection refused por Ollama",
    )
    as_role(ADMIN)
    body = client.get("/llm/").content.decode()
    assert "no responde" in body and "Connection refused" in body
    assert "cómo descargarlos" in body and "ollama pull falta:2" in body


def test_profile_sector_is_plain_text_and_longer(as_role):
    from apps.detection import profile

    admin = as_role(ADMIN)
    saved = profile.update_profile(
        user=admin,
        fields={"name": "Aseguradora", "sector": "**Seguros** y " + "fianzas " * 20},
    )
    assert "**" not in saved.sector and len(saved.sector) > 120


# --- Postura de cada activo en la lista (revisión del 2026-11-16, P9) -----------------


def _risk(asset, level, key, status="OPEN"):
    from django.utils import timezone

    from apps.detection.models import Risk

    return Risk.objects.create(
        asset=asset,
        key=key,
        title=f"Riesgo {key}",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=3,
        impact=3,
        level=level,
        status=status,
        first_identified_at=timezone.now(),
    )


def _names(response):
    return [a.name for a in response.context["assets"]]


def test_asset_list_shows_and_sorts_by_risk_posture(client, as_role):
    as_role(OPERATOR)
    worst = AssetFactory(name="b-critico")
    busy = AssetFactory(name="c-altos")
    quiet = AssetFactory(name="a-sin-riesgos")
    closed_only = AssetFactory(name="d-cerrado")
    _risk(worst, "CRITICAL", "k1")
    _risk(worst, "LOW", "k2")
    for n in range(3):
        _risk(busy, "HIGH", f"h{n}", status="TREATED" if n else "OPEN")
    # Un riesgo cerrado no cuenta en la postura.
    _risk(closed_only, "CRITICAL", "c1", status="CLOSED")

    response = client.get("/inventory/")
    posture = {a.name: (a.risk_level, a.risk_count) for a in response.context["assets"]}
    assert posture == {
        "b-critico": ("CRITICAL", 2),
        "c-altos": ("HIGH", 3),
        "a-sin-riesgos": (None, 0),
        "d-cerrado": (None, 0),
    }
    body = response.content.decode()
    assert "Riesgo</a>" in body and "Último escaneo</a>" in body
    assert f"/detection/?asset={worst.pk}" in body and 'data-posture="CRITICAL"' in body
    assert "2 riesgos abiertos; el más alto es de nivel crítico" in body
    assert body.count('data-posture="none"') == 2 and "Sin riesgos abiertos" in body
    # El primer clic en «Riesgo» trae lo peor primero; el segundo invierte.
    assert "?sort=-risk" in body
    worst_first = client.get("/inventory/", {"sort": "-risk"})
    assert _names(worst_first)[:2] == ["b-critico", "c-altos"]
    assert "?sort=risk" in worst_first.content.decode()
    assert 'aria-sort="descending"' in worst_first.content.decode()
    assert _names(client.get("/inventory/", {"sort": "risk"}))[-2:] == ["c-altos", "b-critico"]
    # A igual nivel, el que más riesgos tiene.
    _risk(quiet, "HIGH", "q1")
    assert _names(client.get("/inventory/", {"sort": "-risk"}))[:3] == [
        "b-critico",
        "c-altos",
        "a-sin-riesgos",
    ]
    # La exportación usa el mismo filtro y no se rompe con la postura anotada.
    assert client.get("/inventory/export.csv").status_code == 200


def test_asset_list_shows_and_sorts_by_last_scan(client, as_role):
    from datetime import timedelta

    from django.utils import timezone

    from apps.detection.models import AssetDetectionState

    as_role(OPERATOR)
    now = timezone.now()
    recent = AssetFactory(name="reciente")
    old = AssetFactory(name="viejo")
    AssetFactory(name="nunca")
    # El más reciente de los tres tipos de escaneo es el que cuenta.
    AssetDetectionState.objects.create(
        asset=recent,
        last_service_scan_at=now - timedelta(days=9),
        last_vuln_scan_at=now - timedelta(hours=3),
    )
    AssetDetectionState.objects.create(asset=old, last_sbom_scan_at=now - timedelta(days=12))

    response = client.get("/inventory/", {"sort": "scan"})
    body = response.content.decode()
    # De menos a más reciente: primero el que nunca se revisó.
    assert _names(response) == ["nunca", "viejo", "reciente"]
    assert _names(client.get("/inventory/", {"sort": "-scan"})) == ["reciente", "viejo", "nunca"]
    assert "hace 3 h" in body and "hace 12 días" in body
    assert "Ninguna herramienta ha revisado este activo" in body and ">nunca<" in body


def test_risk_column_follows_the_permission_of_the_register(client, make_user):
    from django.contrib.auth.models import Permission

    asset = AssetFactory(name="solo-inventario")
    _risk(asset, "CRITICAL", "k1")
    user = make_user()
    user.user_permissions.add(Permission.objects.get(codename="view_asset"))
    client.force_login(type(user).objects.get(pk=user.pk))
    response = client.get("/inventory/")
    body = response.content.decode()
    assert response.status_code == 200 and "solo-inventario" in body
    assert "data-posture" not in body and "Riesgo</a>" not in body
    assert "Último escaneo</a>" in body
    assert [c["key"] for c in response.context["columns"]].count("risk") == 0


def test_a_tag_shared_by_every_row_is_said_once(client, as_role):
    from tests.factories import TagFactory

    as_role(OPERATOR)
    shared = TagFactory(name="lab-aseguradora-norte")
    own = TagFactory(name="dmz")
    first, second = AssetFactory(name="uno"), AssetFactory(name="dos")
    first.tags.add(shared, own)
    second.tags.add(shared)
    response = client.get("/inventory/")
    body = response.content.decode()
    assert response.context["common_tags"] == ["lab-aseguradora-norte"]
    # (El filtro «Etiqueta» también las nombra: se cuentan solo las de la tabla.)
    shared_badge, own_badge = 'badge-neutral">lab-aseguradora-norte<', 'badge-neutral">dmz<'
    assert "data-common-tags" in body and body.count(shared_badge) == 1
    assert body.count(own_badge) == 1
    # Con un solo activo no hay nada «común»: la etiqueta va en su fila.
    one = client.get("/inventory/", {"q": "uno"})
    assert one.context["common_tags"] == [] and "data-common-tags" not in one.content.decode()
    # En cuanto un activo no la lleva, vuelve a mostrarse en cada fila.
    AssetFactory(name="tres")
    body = client.get("/inventory/").content.decode()
    assert "data-common-tags" not in body and body.count(shared_badge) == 2

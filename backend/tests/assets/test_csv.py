"""Importación/exportación CSV: dry-run sin escrituras, errores por fila, upsert y escape de fórmulas."""

import csv
import io
from datetime import timedelta

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.assets import csv_io
from apps.assets.enums import AssetOrigin, CriticalitySource, ExposureSource, IdentifierKind
from apps.assets.models import Asset, AssetConflict, CriticalitySuggestion, PendingUpload
from apps.assets.tasks import expire_import_previews
from tests.factories import AssetFactory, AssetIdentifierFactory

pytestmark = pytest.mark.django_db
HEADER = ",".join(csv_io.COLUMNS)


def make_csv(*rows, header=HEADER):
    return ("﻿" + header + "\n" + "\n".join(rows) + "\n").encode("utf-8")


def row(**values):
    return ",".join(values.get(c, "") for c in csv_io.COLUMNS)


@pytest.fixture
def operator_client(client, make_user):
    user = make_user(OPERATOR)
    client.force_login(user)
    client.user = user
    return client


@pytest.fixture(autouse=True)
def _llm_mock(settings, monkeypatch):
    settings.LLM_MOCK_MODE = True
    from django.db import transaction

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())


def upload(client, content, name="activos.csv", **extra):
    return client.post(
        "/inventory/import/", {"file": SimpleUploadedFile(name, content, "text/csv"), **extra}
    )


# --- Validación de archivo ---------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (make_csv(row(name="x"), header="name,ipv4"), "asset_type"),
        (make_csv("a,HOST", header="name,asset_type"), "identificador"),
        (
            make_csv(row(name="x", asset_type="HOST", ipv4="10.0.0.1"), header=HEADER + ",extra"),
            "desconocidas",
        ),
        (b"\xff\xfe\x00rota", "UTF-8"),
        (make_csv(), "no tiene filas"),
    ],
)
def test_read_rows_rejects_bad_files(content, message):
    with pytest.raises(Exception, match=message):
        csv_io.read_rows(content)


def test_row_limit(monkeypatch):
    monkeypatch.setattr(csv_io, "MAX_ROWS", 2)
    content = make_csv(
        *[row(name=f"a{i}", asset_type="HOST", ipv4=f"10.0.0.{i + 1}") for i in range(3)]
    )
    with pytest.raises(Exception, match="filas"):
        csv_io.read_rows(content)


# --- Dry-run ------------------------------------------------------------------------


def test_dry_run_plans_every_row_without_writing(operator_client):
    existing = AssetFactory(name="db01")
    AssetIdentifierFactory(asset=existing, kind=IdentifierKind.IPV4, value="10.1.0.5")
    a, b = AssetFactory(), AssetFactory()
    AssetIdentifierFactory(asset=a, kind=IdentifierKind.MAC, value="aa:bb:cc:dd:ee:01")
    AssetIdentifierFactory(asset=b, kind=IdentifierKind.FQDN, value="dup.atalaya.local")
    content = make_csv(
        row(name="nuevo", asset_type="HOST", ipv4="10.1.0.9"),
        row(name="db01", asset_type="DATABASE", ipv4="10.1.0.5", criticality="ALTO"),
        row(
            name="choque",
            asset_type="NETWORK_DEVICE",
            mac="aa:bb:cc:dd:ee:01",
            fqdn="dup.atalaya.local",
        ),
        row(name="mala", asset_type="HOST", ipv4="999.1.1.1"),
        row(name="enum", asset_type="SERVIDOR", ipv4="10.1.0.10"),
        row(name="otra-vez", asset_type="HOST", ipv4="10.1.0.9"),
    )
    before = Asset.objects.count()
    response = upload(operator_client, content)
    pending = PendingUpload.objects.get()
    assert response.url == f"/inventory/import/{pending.pk}/"
    actions = [e["action"] for e in pending.meta["plan"]]
    assert actions == ["create", "update", "conflict", "error", "error", "update"]
    assert pending.meta["plan"][5]["detail"] == "Actualiza el activo de la fila 2."
    assert "ipv4" in pending.meta["plan"][3]["detail"]
    assert Asset.objects.count() == before
    assert AssetConflict.objects.count() == 0  # el dry-run no persiste conflictos
    page = operator_client.get(response.url).content.decode()
    assert "Confirmar importación" in page


def test_confirm_applies_import(operator_client):
    existing = AssetFactory(name="db01", criticality=None, exposure=None)
    AssetIdentifierFactory(asset=existing, kind=IdentifierKind.IPV4, value="10.2.0.5")
    content = make_csv(
        row(
            name="portal",
            asset_type="WEB_APP",
            fqdn="Portal.Atalaya.Local",
            criticality="alto",
            data_categories="PII|FINANCIERO",
            tags="pagos|externo",
            environment="PROD",
        ),
        row(
            name="db01",
            asset_type="DATABASE",
            ipv4="10.2.0.5",
            mac="aa:bb:cc:00:00:07",
            exposure="DMZ",
            criticality="CRITICO",
        ),
        row(name="img", asset_type="CONTAINER_IMAGE", image_ref="nginx:1.27"),
        row(name="mala", asset_type="HOST"),
    )
    preview = upload(operator_client, content).url
    status = operator_client.post(preview).url
    pending = PendingUpload.objects.get()
    assert status == f"/inventory/import/{pending.pk}/status/"
    assert pending.result["counts"] == {"create": 2, "update": 1, "conflict": 0, "error": 1}
    portal = Asset.objects.get(name="portal")
    assert portal.origin == AssetOrigin.IMPORT
    assert (portal.criticality, portal.criticality_source) == ("ALTO", CriticalitySource.IMPORT)
    assert portal.data_categories == ["PII", "FINANCIERO"]
    assert set(portal.tags.values_list("name", flat=True)) == {"pagos", "externo"}
    existing.refresh_from_db()
    assert existing.asset_type == "DATABASE"
    assert (existing.exposure, existing.exposure_source) == ("DMZ", ExposureSource.MANUAL)
    assert (existing.criticality, existing.criticality_source) == (
        "CRITICO",
        CriticalitySource.IMPORT,
    )
    assert existing.identifiers.filter(kind="MAC").exists()
    assert (
        Asset.objects.get(asset_type="CONTAINER_IMAGE").container_image.repository
        == "docker.io/library/nginx"
    )
    assert "Creados" in operator_client.get(status).content.decode()


def test_import_schedules_suggestions_for_assets_without_criticality(operator_client):
    content = make_csv(
        row(
            name="sin",
            asset_type="HOST",
            ipv4="10.3.0.1",
            business_role="API",
            description="API interna de pagos.",
        ),
        row(
            name="con",
            asset_type="HOST",
            ipv4="10.3.0.2",
            criticality="BAJO",
            business_role="API",
            description="API interna.",
        ),
        row(name="sin-contexto", asset_type="HOST", ipv4="10.3.0.3"),
    )
    preview = upload(operator_client, content).url
    operator_client.post(preview)
    # Automática (sin casilla): solo el activo sin criticidad y con contexto mínimo.
    assert list(CriticalitySuggestion.objects.values_list("asset__name", flat=True)) == ["sin"]
    assert CriticalitySuggestion.objects.get().trigger == "IMPORT"


def test_large_import_runs_in_background(operator_client, monkeypatch):
    monkeypatch.setattr(csv_io, "ASYNC_THRESHOLD", 1)
    content = make_csv(
        row(name="a", asset_type="HOST", ipv4="10.4.0.1"),
        row(name="b", asset_type="HOST", ipv4="10.4.0.2"),
    )
    operator_client.post(upload(operator_client, content).url)
    pending = PendingUpload.objects.get()
    assert pending.status == "DONE" and pending.result["counts"]["create"] == 2  # tarea eager
    partial = operator_client.get(f"/inventory/import/{pending.pk}/status/", HTTP_HX_REQUEST="true")
    assert "hx-trigger" not in partial.content.decode()


def test_preview_is_private_and_expires(operator_client, client, make_user):
    preview = upload(
        operator_client, make_csv(row(name="a", asset_type="HOST", ipv4="10.5.0.1"))
    ).url
    other = make_user(OPERATOR)
    operator_client.force_login(other)
    assert operator_client.get(preview).status_code == 404
    operator_client.force_login(PendingUpload.objects.get().user)
    PendingUpload.objects.update(expires_at=timezone.now() - timedelta(minutes=1))
    assert operator_client.get(preview).status_code == 404
    assert not PendingUpload.objects.exists()


def test_expire_task_removes_old_uploads(operator_client):
    upload(operator_client, make_csv(row(name="a", asset_type="HOST", ipv4="10.6.0.1")))
    PendingUpload.objects.update(expires_at=timezone.now() - timedelta(hours=2))
    assert expire_import_previews.delay().get() == 1
    assert not PendingUpload.objects.exists()


def test_auditor_cannot_import(client, make_user):
    client.force_login(make_user(AUDITOR))
    assert (
        upload(client, make_csv(row(name="a", asset_type="HOST", ipv4="10.7.0.1"))).status_code
        == 403
    )
    assert client.get("/inventory/import/").status_code == 200  # puede exportar


def test_upload_rejects_non_csv_and_oversize(operator_client, monkeypatch):
    assert upload(operator_client, b"x", name="activos.xlsx").status_code == 400
    monkeypatch.setattr(csv_io, "MAX_BYTES", 10)
    assert (
        upload(
            operator_client, make_csv(row(name="a", asset_type="HOST", ipv4="10.8.0.1"))
        ).status_code
        == 400
    )


# --- Exportación ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "dangerous", ['=HYPERLINK("http://x")', "+1", "-2+3", "@SUM(A1)", "\tx", "\rx"]
)
def test_escape_cell(dangerous):
    assert csv_io.escape_cell(dangerous) == "'" + dangerous


def test_export_respects_filters_bom_and_escaping(client, make_user):
    client.force_login(make_user(AUDITOR))
    asset = AssetFactory(name="=cmd|' /C calc'!A0", environment="PROD", data_categories=["PII"])
    AssetIdentifierFactory(asset=asset, kind=IdentifierKind.IPV4, value="10.9.0.1")
    AssetFactory(name="dev-box", environment="DEV")
    response = client.get("/inventory/export.csv", {"environment": "PROD"})
    assert response["Content-Disposition"].startswith('attachment; filename="atalaya-activos-')
    raw = response.content
    assert raw.startswith("﻿".encode())
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    assert rows[0] == csv_io.COLUMNS
    assert len(rows) == 2
    assert rows[1][0] == "'=cmd|' /C calc'!A0" and rows[1][2] == "10.9.0.1"


def test_template_download(client, make_user):
    client.force_login(make_user(AUDITOR))
    response = client.get("/inventory/template.csv")
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert rows[0] == csv_io.COLUMNS and len(rows) == 2
    # La plantilla se puede importar tal cual.
    assert csv_io.plan_import(csv_io.read_rows(response.content))[0]["action"] == "create"


def test_import_enforces_catalog_and_required_identifiers():
    plan = csv_io.plan_import(
        csv_io.read_rows(
            make_csv(
                row(name="sin-ip", asset_type="HOST", fqdn="solo-fqdn.atalaya.local"),
                row(
                    name="rol-raro", asset_type="HOST", ipv4="10.12.0.1", business_role="NO_EXISTE"
                ),
                row(name="ok", asset_type="DATABASE", fqdn="db.atalaya.local", environment="prod"),
            )
        )
    )
    assert [e["action"] for e in plan] == ["error", "error", "create"]
    assert "IPv4" in plan[0]["detail"] and "business_role" in plan[1]["detail"]

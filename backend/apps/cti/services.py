"""Servicios del almacén CTI: sincronización, detección de cambios y consultas.

Toda escritura del espejo pasa por ``apply_cve`` / ``apply_epss`` / ``apply_kev``, que además
registran los ``CtiChange`` (CVE nuevo, CVE modificado, entró a KEV, EPSS subió). Las tres
funciones sirven igual para una descarga real, para la cobertura dirigida por producto y
para los datos de ejemplo del laboratorio (``import_fixture``).
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta

import httpx
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from .clients import epss as epss_client
from .clients import kev as kev_client
from .clients import nvd as nvd_client
from .clients.nvd import AffectedProduct, CveData
from .models import (
    ChangeKind,
    CtiChange,
    CtiSource,
    CtiSyncRun,
    CveProduct,
    CveRecord,
    ProductCoverage,
    SourceKind,
    SyncStatus,
    SyncTrigger,
)
from .products import product_key
from .signals import changes_detected
from .versions import Range

logger = logging.getLogger(__name__)

SOURCE_DEFAULTS = {
    SourceKind.NVD: ("NVD_API_BASE", 24),
    SourceKind.EPSS: ("EPSS_SNAPSHOT_URL", 24),
    SourceKind.KEV: ("KEV_CATALOG_URL", 6),
}
_LAST_SYNC_KEY = "cti:last-nvd-sync"


def _require(user, perm="cti.manage_sources"):
    if user is not None and not user.has_perm(perm):
        raise PermissionDenied("Solo un administrador configura las fuentes de inteligencia.")


# --------------------------------------------------------------------------
# Fuentes
# --------------------------------------------------------------------------


def ensure_sources():
    """Crea las tres filas de configuración con los valores de ``settings`` si no existen."""
    rows = []
    for kind, (setting, hours) in SOURCE_DEFAULTS.items():
        row, _ = CtiSource.objects.get_or_create(
            kind=kind,
            defaults={"url": getattr(settings, setting) or "", "interval_hours": hours},
        )
        rows.append(row)
    return rows


def get_source(kind):
    ensure_sources()
    return CtiSource.objects.get(kind=kind)


SOURCE_FIELDS = ("url", "enabled", "interval_hours")


def update_source(kind, *, user, fields):
    _require(user)
    source = get_source(kind)
    for name, value in fields.items():
        if name not in SOURCE_FIELDS:
            raise ValueError(f"Campo no editable: {name}")
        setattr(source, name, value)
    if source.enabled and not source.url:
        raise ValidationError("Una fuente habilitada necesita URL.")
    source.updated_by = user
    source.full_clean(exclude=["updated_by"])
    source.save()
    return source


def due_sources(now=None):
    now = now or timezone.now()
    due = []
    for source in ensure_sources():
        if not source.enabled or not source.url:
            continue
        last = source.last_success_at
        if last is None or last + timedelta(hours=source.interval_hours) <= now:
            due.append(source)
    return due


# --------------------------------------------------------------------------
# Aplicación de registros con detección de cambios
# --------------------------------------------------------------------------


def _cvss_signature(record):
    return {
        "cvss_score": record.cvss_score,
        "cvss_version": record.cvss_version,
        "severity": record.severity,
    }


def _products_signature(affected):
    return sorted(
        json.dumps(a if isinstance(a, dict) else a.as_dict(), sort_keys=True) for a in affected
    )


def _replace_products(record, affected: tuple[AffectedProduct, ...]):
    CveProduct.objects.filter(cve=record).delete()
    CveProduct.objects.bulk_create(
        [
            CveProduct(
                cve=record,
                product_key=a.product_key,
                vendor=a.vendor,
                product=a.product,
                cpe=a.cpe,
                version_start_including=a.range.start_including,
                version_start_excluding=a.range.start_excluding,
                version_end_including=a.range.end_including,
                version_end_excluding=a.range.end_excluding,
                exact_version=a.range.exact,
            )
            for a in affected
        ]
    )


def apply_cve(data: CveData, run: CtiSyncRun) -> CtiChange | None:
    """Crea o actualiza un CVE desde NVD. Devuelve el cambio detectado (o ``None``)."""
    record = CveRecord.objects.filter(pk=data.cve_id).first()
    created = record is None
    if created:
        record = CveRecord(cve_id=data.cve_id)
    before = {**_cvss_signature(record), "affected": _products_signature(record.affected)}
    record.description = data.description or record.description
    record.published_at = data.published_at or record.published_at
    record.modified_at = data.modified_at or record.modified_at
    if data.cvss_score is not None or created:
        record.cvss_score = data.cvss_score
        record.cvss_vector = data.cvss_vector
        record.cvss_version = data.cvss_version
        record.severity = data.severity
    record.cwe_ids = list(data.cwe_ids) or record.cwe_ids
    record.affected = [a.as_dict() for a in data.affected]
    record.references = list(data.references) or record.references
    record.save()
    _replace_products(record, data.affected)
    after = {**_cvss_signature(record), "affected": _products_signature(record.affected)}
    run.records_seen += 1
    if created:
        run.created += 1
        return _change(run, record, ChangeKind.NEW_CVE, {}, after)
    run.updated += 1
    if before != after:
        return _change(run, record, ChangeKind.CVE_MODIFIED, before, after)
    return None


def _change(run, record, kind, before, after):
    run.changes += 1
    return CtiChange.objects.create(run=run, cve=record, kind=kind, before=before, after=after)


def apply_epss(snapshot: epss_client.EpssSnapshot, run: CtiSyncRun) -> list[CtiChange]:
    """Actualiza EPSS solo de los CVE presentes en el espejo; registra las subidas."""
    delta = settings.CTI_EPSS_RISE_DELTA
    high = settings.CTI_EPSS_HIGH
    known = set(CveRecord.objects.values_list("cve_id", flat=True))
    changes = []
    for row in snapshot.rows:
        run.records_seen += 1
        if row.cve_id not in known:
            continue
        record = CveRecord.objects.get(pk=row.cve_id)
        previous = record.epss_score
        if (
            previous == row.score
            and record.epss_percentile == row.percentile
            and record.epss_date == snapshot.score_date
        ):
            continue
        record.epss_score = row.score
        record.epss_percentile = row.percentile
        record.epss_date = snapshot.score_date
        record.save(update_fields=["epss_score", "epss_percentile", "epss_date", "last_synced_at"])
        run.updated += 1
        rose = (previous is None and row.score >= high) or (
            previous is not None and row.score - previous >= delta
        )
        if rose:
            changes.append(
                _change(
                    run,
                    record,
                    ChangeKind.EPSS_RISE,
                    {"epss_score": previous},
                    {"epss_score": row.score, "epss_percentile": row.percentile},
                )
            )
    return changes


def apply_kev(catalog: kev_client.KevCatalog, run: CtiSyncRun) -> list[CtiChange]:
    """Refleja KEV completo; un CVE que no estaba en el espejo se crea con lo que KEV sabe."""
    changes = []
    for entry in catalog.entries:
        run.records_seen += 1
        record = CveRecord.objects.filter(pk=entry.cve_id).first()
        created = record is None
        if created:
            record = CveRecord(cve_id=entry.cve_id, description=entry.description)
            # KEV nombra vendor/producto en texto libre; sirve para emparejar a falta de CPE.
            key = product_key(entry.product, entry.vendor)
            record.affected = [
                AffectedProduct(
                    vendor=entry.vendor.lower()[:120],
                    product=entry.product.lower()[:120],
                    product_key=key,
                    cpe="",
                ).as_dict()
            ]
        was_in_kev = record.kev_added_at is not None
        record.kev_added_at = entry.added_at
        record.kev_due_at = entry.due_at
        record.kev_ransomware = entry.ransomware
        record.kev_name = entry.name
        record.kev_action = entry.action
        record.save()
        if created:
            run.created += 1
            _replace_products(
                record,
                tuple(
                    AffectedProduct(a["vendor"], a["product"], a["product_key"], a["cpe"], Range())
                    for a in record.affected
                ),
            )
        else:
            run.updated += 1
        if not was_in_kev:
            changes.append(
                _change(
                    run,
                    record,
                    ChangeKind.KEV_ADDED,
                    {},
                    {"kev_added_at": entry.added_at.isoformat() if entry.added_at else None},
                )
            )
    return changes


# --------------------------------------------------------------------------
# Sincronización
# --------------------------------------------------------------------------


def _finish(run, source, *, error=None, sha256="", detail=None):
    run.finished_at = timezone.now()
    run.sha256 = sha256
    run.detail = detail or {}
    if error:
        run.status = SyncStatus.FAILED
        run.error = str(error)[:2000]
    else:
        run.status = SyncStatus.SUCCEEDED
    run.save()
    if source is not None:
        source.last_run_at = run.finished_at
        source.last_status = run.status
        source.last_detail = (run.error or f"{run.changes} cambio(s)")[:255]
        if not error:
            source.last_success_at = run.finished_at
        source.save(update_fields=["last_run_at", "last_status", "last_detail", "last_success_at"])
    return run


def _emit(run, changes):
    changes = [c for c in changes if c is not None]
    if changes:
        changes_detected.send(sender=CtiSyncRun, run=run, changes=changes)
    return changes


def sync_source(kind, *, user=None, trigger=SyncTrigger.SCHEDULED, http=None, now=None):
    """Descarga y aplica una fuente. Nunca lanza por fallos de red: el run queda ``FAILED``."""
    if user is not None:
        _require(user)
    source = get_source(kind)
    run = CtiSyncRun.objects.create(source=kind, trigger=trigger, requested_by=user)
    now = now or timezone.now()
    try:
        if kind == SourceKind.NVD:
            since = source.last_success_at or (now - timedelta(days=settings.CTI_NVD_INITIAL_DAYS))
            client = nvd_client.NvdClient(http=http, base_url=source.url)
            items = client.fetch_modified(since, now)
            changes = [apply_cve(item, run) for item in items]
            sha = hashlib.sha256(
                json.dumps([i.cve_id for i in items], sort_keys=True).encode()
            ).hexdigest()
            _finish(run, source, sha256=sha, detail={"since": since.isoformat()})
        elif kind == SourceKind.EPSS:
            snapshot = epss_client.download(source.url, http=http)
            changes = apply_epss(snapshot, run)
            _finish(
                run,
                source,
                sha256=snapshot.sha256,
                detail={
                    "score_date": snapshot.score_date.isoformat() if snapshot.score_date else None
                },
            )
        elif kind == SourceKind.KEV:
            catalog = kev_client.download(source.url, http=http)
            changes = apply_kev(catalog, run)
            _finish(run, source, sha256=catalog.sha256, detail={"version": catalog.version})
        else:  # pragma: no cover
            raise ValidationError("Fuente desconocida.")
    except (httpx.HTTPError, ValueError, KeyError, json.JSONDecodeError) as exc:
        logger.warning("Sincronización %s fallida: %s", kind, exc)
        return _finish(run, source, error=f"{type(exc).__name__}: {exc}")
    _emit(run, changes)
    return run


def sync_due_sources(now=None, http=None):
    runs = []
    for source in due_sources(now):
        runs.append(sync_source(source.kind, http=http, now=now))
    return runs


# --------------------------------------------------------------------------
# Espejo dirigido por producto
# --------------------------------------------------------------------------


def ensure_product_coverage(key, vendor="", *, http=None, force=False, now=None):
    """Trae de NVD los CVE del producto si no se han traído en ``CTI_PRODUCT_REFRESH_DAYS``.

    Devuelve el ``CtiSyncRun`` creado, o ``None`` si la cobertura estaba vigente o NVD está
    deshabilitado.
    """
    if not key:
        return None
    source = get_source(SourceKind.NVD)
    if not source.enabled or not source.url:
        return None
    now = now or timezone.now()
    coverage, _ = ProductCoverage.objects.get_or_create(
        product_key=key[:120], vendor=(vendor or "")[:120]
    )
    fresh_until = (
        coverage.last_pulled_at + timedelta(days=settings.CTI_PRODUCT_REFRESH_DAYS)
        if coverage.last_pulled_at
        else None
    )
    if not force and fresh_until is not None and fresh_until > now:
        return None
    run = CtiSyncRun.objects.create(source=SourceKind.NVD, trigger=SyncTrigger.PRODUCT)
    try:
        client = nvd_client.NvdClient(http=http, base_url=source.url)
        items = client.fetch_by_product(vendor, key)
        changes = [apply_cve(item, run) for item in items]
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        coverage.last_error = f"{type(exc).__name__}: {exc}"[:255]
        coverage.save(update_fields=["last_error"])
        return _finish(run, None, error=coverage.last_error, detail={"product": key})
    coverage.last_pulled_at = now
    coverage.cve_count = len(items)
    coverage.last_error = ""
    coverage.save()
    _finish(run, None, detail={"product": key, "vendor": vendor})
    _emit(run, changes)
    return run


# --------------------------------------------------------------------------
# Datos de ejemplo (laboratorio, panel de pruebas, pruebas automatizadas)
# --------------------------------------------------------------------------


def _fixture_cve(item) -> CveData:
    cvss = item.get("cvss") or {}
    affected = tuple(
        AffectedProduct(
            vendor=str(a.get("vendor") or "").lower()[:120],
            product=str(a.get("product") or "").lower()[:120],
            product_key=product_key(a.get("product"), a.get("vendor")),
            cpe=str(a.get("cpe") or "")[:255],
            range=Range(
                start_including=str(a.get("version_start_including") or ""),
                start_excluding=str(a.get("version_start_excluding") or ""),
                end_including=str(a.get("version_end_including") or ""),
                end_excluding=str(a.get("version_end_excluding") or ""),
                exact=str(a.get("exact_version") or ""),
            ),
        )
        for a in item.get("affected") or []
    )
    score = cvss.get("score")
    severity = cvss.get("severity") or (
        nvd_client.severity_from_score(float(score)) if score is not None else "NONE"
    )
    return CveData(
        cve_id=str(item["cve_id"]).upper()[:20],
        description=str(item.get("description") or "")[:4000],
        published_at=nvd_client._parse_dt(item.get("published")),
        modified_at=nvd_client._parse_dt(item.get("modified")),
        cvss_score=float(score) if score is not None else None,
        cvss_vector=str(cvss.get("vector") or "")[:120],
        cvss_version=str(cvss.get("version") or "")[:4],
        severity=str(severity).upper(),
        cwe_ids=tuple(item.get("cwe_ids") or ()),
        affected=affected,
        references=tuple(item.get("references") or ()),
    )


@transaction.atomic
def import_fixture(data, *, user=None, trigger=SyncTrigger.FIXTURE):
    """Aplica un documento ``{"cves": [...]}`` con CVE, EPSS y KEV en el formato de Atalaya.

    Produce exactamente los mismos ``CtiChange`` que una descarga real, así que sirve para
    simular «llegó inteligencia nueva» sin internet.
    """
    if user is not None:
        _require(user)
    items = data.get("cves") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValidationError("El documento debe tener una lista «cves».")
    run = CtiSyncRun.objects.create(source=SourceKind.NVD, trigger=trigger, requested_by=user)
    changes = []
    epss_rows, kev_entries = [], []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("cve_id", "")).upper().startswith("CVE-"):
            raise ValidationError("Cada entrada necesita un «cve_id» con formato CVE-AAAA-NNNN.")
        changes.append(apply_cve(_fixture_cve(item), run))
        if item.get("epss"):
            e = item["epss"]
            epss_rows.append(
                epss_client.EpssRow(
                    str(item["cve_id"]).upper(),
                    float(e.get("score") or 0),
                    float(e.get("percentile") or 0),
                )
            )
        if item.get("kev"):
            k = item["kev"]
            kev_entries.append(
                kev_client.KevEntry(
                    cve_id=str(item["cve_id"]).upper(),
                    added_at=kev_client._date(k.get("added")),
                    due_at=kev_client._date(k.get("due")),
                    vendor=str(k.get("vendor") or "")[:120],
                    product=str(k.get("product") or "")[:120],
                    name=str(k.get("name") or "")[:255],
                    description=str(item.get("description") or "")[:4000],
                    action=str(k.get("action") or "")[:2000],
                    ransomware=str(k.get("ransomware") or "")[:10],
                )
            )
    if epss_rows:
        snapshot = epss_client.EpssSnapshot(
            score_date=timezone.now().date(), rows=tuple(epss_rows), sha256=""
        )
        changes.extend(apply_epss(snapshot, run))
    if kev_entries:
        catalog = kev_client.KevCatalog("fixture", tuple(kev_entries), "")
        changes.extend(apply_kev(catalog, run))
    sha = hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()
    _finish(run, None, sha256=sha, detail={"items": len(items)})
    transaction.on_commit(lambda: _emit(run, changes))
    return run


# --------------------------------------------------------------------------
# Consultas
# --------------------------------------------------------------------------


def get_cve(cve_id):
    return CveRecord.objects.filter(pk=str(cve_id).upper()).first()


def products_for(cve_ids):
    """``CveProduct`` de los CVE dados (con el CVE precargado)."""
    return list(CveProduct.objects.filter(cve_id__in=list(cve_ids)).select_related("cve"))


def products_for_keys(keys):
    """``CveProduct`` cuyo producto canónico está en ``keys``."""
    return list(CveProduct.objects.filter(product_key__in=list(keys)).select_related("cve"))


def summary():
    """Conteos para la pantalla de fuentes."""
    return {
        "cves": CveRecord.objects.count(),
        "in_kev": CveRecord.objects.filter(kev_added_at__isnull=False).count(),
        "with_epss": CveRecord.objects.filter(epss_score__isnull=False).count(),
        "products": ProductCoverage.objects.count(),
    }

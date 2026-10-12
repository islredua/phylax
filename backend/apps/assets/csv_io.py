"""Importación (dry-run + confirmación) y exportación CSV del inventario (sección 13)."""

import csv
import io
import logging

from django.core.exceptions import ValidationError
from django.db import transaction

from . import services
from .enums import (
    AssetOrigin,
    AssetType,
    BusinessRole,
    ConflictSource,
    Criticality,
    CriticalitySource,
    DataCategory,
    DataClassification,
    Environment,
    Exposure,
    IdentifierKind,
)
from .models import AssetConflict
from .normalization import normalize_identifier

logger = logging.getLogger(__name__)

COLUMNS = [
    "name",
    "asset_type",
    "ipv4",
    "ipv6",
    "fqdn",
    "mac",
    "image_ref",
    "description",
    "business_role",
    "environment",
    "criticality",
    "exposure",
    "data_classification",
    "data_categories",
    "tags",
    "business_owner",
]
IDENTIFIER_COLUMNS = {
    "ipv4": IdentifierKind.IPV4,
    "ipv6": IdentifierKind.IPV6,
    "fqdn": IdentifierKind.FQDN,
    "mac": IdentifierKind.MAC,
    "image_ref": IdentifierKind.IMAGE_REF,
}
ENUM_COLUMNS = {
    "asset_type": AssetType,
    "business_role": BusinessRole,
    "environment": Environment,
    "criticality": Criticality,
    "exposure": Exposure,
    "data_classification": DataClassification,
}
MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5000
ASYNC_THRESHOLD = 200
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

CREATE, UPDATE, CONFLICT, ERROR = "create", "update", "conflict", "error"


def read_rows(raw):
    """Decodifica (UTF-8 con o sin BOM) y valida encabezados. Devuelve ``list[dict]``."""
    if len(raw) > MAX_BYTES:
        raise ValidationError("El archivo excede 5 MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("El archivo debe estar en UTF-8.") from exc
    reader = csv.DictReader(io.StringIO(text))
    headers = {h.strip() for h in reader.fieldnames or []}
    missing = {"name", "asset_type"} - headers
    if missing:
        raise ValidationError(f"Faltan columnas obligatorias: {', '.join(sorted(missing))}.")
    if not headers & set(IDENTIFIER_COLUMNS):
        raise ValidationError(
            "Incluye al menos una columna de identificador: " + ", ".join(IDENTIFIER_COLUMNS) + "."
        )
    unknown = headers - set(COLUMNS)
    if unknown:
        raise ValidationError(f"Columnas desconocidas: {', '.join(sorted(unknown))}.")
    rows = []
    for row in reader:
        if len(rows) >= MAX_ROWS:
            raise ValidationError(f"El archivo excede {MAX_ROWS} filas.")
        rows.append({k.strip(): (v or "").strip() for k, v in row.items() if k})
    if not rows:
        raise ValidationError("El archivo no tiene filas.")
    return rows


def parse_row(row):
    """Valida y normaliza una fila. Devuelve ``(datos, identificadores)``."""
    data = {}
    for column, enum in ENUM_COLUMNS.items():
        value = row.get(column, "").upper()
        if value and value not in enum.values:
            raise ValidationError(
                f"{column}: «{row[column]}» no es válido ({', '.join(enum.values)})."
            )
        data[column] = value or None
    if not row.get("name"):
        raise ValidationError("name es obligatorio.")
    if not data["asset_type"]:
        raise ValidationError("asset_type es obligatorio.")
    categories = [c.strip().upper() for c in row.get("data_categories", "").split("|") if c.strip()]
    invalid = [c for c in categories if c not in DataCategory.values]
    if invalid:
        raise ValidationError(f"data_categories: valores no válidos ({', '.join(invalid)}).")
    identifiers = []
    for column, kind in IDENTIFIER_COLUMNS.items():
        if row.get(column):
            try:
                identifiers.append((kind, normalize_identifier(kind, row[column])))
            except ValidationError as exc:
                raise ValidationError(f"{column}: {' '.join(exc.messages)}") from exc
    if not identifiers:
        raise ValidationError("La fila no tiene ningún identificador.")
    data.update(
        name=row["name"][:200],
        description=row.get("description", ""),
        business_owner=row.get("business_owner", "")[:200],
        data_categories=categories,
        tags=row.get("tags", ""),
    )
    return data, identifiers


def plan_import(rows):
    """Dry-run sin escrituras: acción y motivo por fila."""
    plan, seen = [], {}
    for number, row in enumerate(rows, start=2):  # fila 1 = encabezados
        entry = {"line": number, "name": row.get("name", ""), "action": ERROR, "detail": ""}
        try:
            data, identifiers = parse_row(row)
        except ValidationError as exc:
            entry["detail"] = " ".join(exc.messages)
            plan.append(entry)
            continue
        earlier = next((seen[i] for i in identifiers if i in seen), None)
        if earlier is not None:
            entry.update(action=UPDATE, detail=f"Actualiza el activo de la fila {earlier}.")
        else:
            resolved = services.resolve_asset(
                identifiers, source=ConflictSource.IMPORT, persist=False
            )
            if isinstance(resolved, AssetConflict):
                names = ", ".join(a.name for a in resolved.preview_candidates)
                entry.update(
                    action=CONFLICT,
                    detail=f"Los identificadores pertenecen a activos distintos: {names}.",
                )
            elif resolved is not None:
                entry.update(action=UPDATE, detail=f"Actualiza «{resolved.name}».")
            else:
                entry.update(action=CREATE)
        for identifier in identifiers:
            seen.setdefault(identifier, number)
        plan.append(entry)
    return plan


def summarize(plan):
    counts = {CREATE: 0, UPDATE: 0, CONFLICT: 0, ERROR: 0}
    for entry in plan:
        counts[entry["action"]] += 1
    return counts


def _apply_row(data, identifiers, *, user):
    tags = services.get_or_create_tags(data["tags"])
    image_ref = next((v for k, v in identifiers if k == IdentifierKind.IMAGE_REF), None)
    resolved = services.resolve_asset(
        identifiers, source=ConflictSource.IMPORT, payload={"name": data["name"]}
    )
    if isinstance(resolved, AssetConflict):
        return CONFLICT, None
    context = {
        k: data[k]
        for k in (
            "name",
            "asset_type",
            "description",
            "business_role",
            "environment",
            "data_classification",
            "data_categories",
            "business_owner",
        )
    }
    if resolved is None:
        if image_ref and data["asset_type"] == AssetType.CONTAINER_IMAGE:
            result = services.register_container_image(
                image_ref,
                user=user,
                **{k: v for k, v in context.items() if k not in ("name", "asset_type")},
            )
            asset = result.asset
            if data["criticality"]:
                services.update_asset(asset, user=user, criticality=data["criticality"])
        else:
            asset = services.create_asset(
                user=user,
                fields=context,
                identifiers=identifiers,
                criticality=data["criticality"],
                exposure=data["exposure"],
                tags=tags,
                origin=AssetOrigin.IMPORT,
                criticality_source=CriticalitySource.IMPORT,
            )
        action = CREATE
    else:
        asset = resolved
        fields = {k: v for k, v in context.items() if v not in (None, "", [])}
        services.update_asset(asset, user=user, fields=fields)
        for kind, value in identifiers:
            if not asset.identifiers.filter(kind=kind, value=value).exists():
                services.add_identifier(asset, kind, value, user=user)
        action = UPDATE
    asset.refresh_from_db()
    changed = False
    if data["criticality"] and asset.criticality != data["criticality"]:
        services.set_criticality(asset, data["criticality"], source=CriticalitySource.IMPORT)
        changed = True
    if data["exposure"]:
        services.set_exposure(asset, data["exposure"])
        changed = True
    if changed:
        services._attribute(asset, user)
        asset.save()
    if tags:
        asset.tags.add(*tags)
    return action, asset


def execute_import(rows, *, user, request_llm=False):
    """Aplica la importación fila por fila (cada fila en su propia transacción)."""
    counts = {CREATE: 0, UPDATE: 0, CONFLICT: 0, ERROR: 0}
    errors, needs_suggestion = [], []
    for number, row in enumerate(rows, start=2):
        try:
            data, identifiers = parse_row(row)
            with transaction.atomic():
                action, asset = _apply_row(data, identifiers, user=user)
        except ValidationError as exc:
            counts[ERROR] += 1
            errors.append({"line": number, "detail": " ".join(exc.messages)})
            continue
        counts[action] += 1
        if asset is not None and asset.criticality is None:
            needs_suggestion.append(asset.pk)
    if request_llm:
        for asset_id in dict.fromkeys(needs_suggestion):
            services.request_criticality_suggestion(asset_id, user=None, requested_by=user)
    return {
        "counts": counts,
        "errors": errors[:200],
        "llm_requested": len(needs_suggestion) if request_llm else 0,
    }


# --- Exportación -------------------------------------------------------------------


def escape_cell(value):
    """Mitiga CSV/formula injection: prefija ``'`` a celdas que empiezan con = + - @ tab CR."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def export_rows(assets):
    yield COLUMNS
    for asset in assets:
        idents = {}
        for identifier in asset.identifiers.all():
            idents.setdefault(identifier.kind, identifier.value)
        yield [
            escape_cell(v)
            for v in (
                asset.name,
                asset.asset_type,
                idents.get("IPV4"),
                idents.get("IPV6"),
                idents.get("FQDN"),
                idents.get("MAC"),
                idents.get("IMAGE_REF"),
                asset.description,
                asset.business_role,
                asset.environment,
                asset.criticality,
                asset.exposure,
                asset.data_classification,
                "|".join(asset.data_categories or []),
                "|".join(t.name for t in asset.tags.all()),
                asset.business_owner,
            )
        ]


def to_csv_bytes(rows):
    """UTF-8 con BOM (Excel lo abre con acentos correctos)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in rows:
        writer.writerow(row)
    return ("﻿" + buffer.getvalue()).encode("utf-8")


TEMPLATE_EXAMPLE = [
    "portal-clientes",
    "WEB_APP",
    "10.10.1.20",
    "",
    "portal.empresa.local",
    "",
    "",
    "Portal de autoservicio para clientes",
    "WEB_PUBLICA",
    "PROD",
    "",
    "",
    "CONFIDENCIAL",
    "PII",
    "portal|clientes",
    "Gerencia Comercial",
]

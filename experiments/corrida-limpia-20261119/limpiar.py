# Limpieza para la corrida limpia: vacía todo lo que la plataforma produjo al operar y conserva
# cuentas, configuración, perfil de la organización, catálogos y el espejo de inteligencia.
# Una sola transacción: si algo falla no cambia nada. DRY = True deshace al final.
# Uso, con workers y beat detenidos y un respaldo comprobado:
#   (echo "DRY = True"; cat limpiar.py) | docker compose exec -T backend python manage.py shell
from django.apps import apps
from django.db import connection, transaction

DRY = globals().get("DRY", True)
WIPE = {
    "assets": ["Asset", "AssetConflict", "AssetIdentifier", "ContainerImage", "CriticalitySuggestion",
               "HistoricalAsset", "HistoricalAssetIdentifier", "HistoricalNetworkRange", "NetworkRange",
               "PendingUpload", "SbomDocument", "Service", "Tag"],
    "detection": ["AssetDetectionState", "AutomationLogEntry", "BusinessRiskDescription",
                  "BusinessRoleDescription", "DetectionEvent", "EventBatch", "Finding", "FindingEvent",
                  "FindingEvidence", "PlannedAction", "PlannerDecision", "Risk", "RiskEvent",
                  "RiskVerification", "SoftwareComponent", "SoftwareDescription", "Vulnerability",
                  "VulnerabilityEvent", "WatchItem"],
    "discovery": ["DiscoveryRun"],
    "presentation": ["HealthNarrative", "HealthSnapshot"],
    "scanners": ["ToolExecution"],
    "alerts": ["Notification"],
}
DELETE = [("llm", "InferenceLog")]  # la referencia del perfil impide TRUNCATE; se borra con DELETE

tables = []
for app, names in WIPE.items():
    for name in names:
        model = apps.get_model(app, name)
        tables.append(model._meta.db_table)
        for field in model._meta.local_many_to_many:
            through = field.remote_field.through
            if through._meta.auto_created:
                tables.append(through._meta.db_table)
tables = sorted(set(tables))
delete_tables = [apps.get_model(a, n)._meta.db_table for a, n in DELETE]


def counts(cursor):
    out = {}
    for name in connection.introspection.table_names(cursor):
        cursor.execute(f'SELECT count(*) FROM "{name}"')
        out[name] = cursor.fetchone()[0]
    return out


class Undo(Exception):
    pass


try:
    with transaction.atomic(), connection.cursor() as cursor:
        before = counts(cursor)
        cursor.execute("UPDATE detection_organizationprofile SET draft_inference_id = NULL")
        cursor.execute("TRUNCATE " + ", ".join(f'"{t}"' for t in tables) + " RESTART IDENTITY")
        for name in delete_tables:
            cursor.execute(f'DELETE FROM "{name}"')
        after = counts(cursor)
        wiped = set(tables) | set(delete_tables)
        left = {t: after[t] for t in wiped if after[t]}
        touched = {t: (before[t], after[t]) for t in before if t not in wiped and before[t] != after[t]}
        print("tablas vaciadas:", len(wiped), "· filas borradas:", sum(before[t] for t in wiped))
        print("vaciadas que conservan filas:", left or "ninguna")
        print("conservadas que cambiaron:", touched or "ninguna")
        print("conservadas con datos:", {t: n for t, n in sorted(after.items()) if n and t not in wiped and not t.startswith(("django_", "auth_"))})
        assert not left and not touched
        if DRY:
            raise Undo
    print("LIMPIEZA APLICADA")
except Undo:
    print("ensayo: deshecho, no cambió nada")

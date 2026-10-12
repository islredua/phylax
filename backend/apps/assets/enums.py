"""Enumeraciones del inventario (sección 3 de la especificación)."""

from django.db import models


class AssetType(models.TextChoices):
    HOST = "HOST", "Host"
    WEB_APP = "WEB_APP", "Aplicación web"
    DATABASE = "DATABASE", "Base de datos"
    CONTAINER_IMAGE = "CONTAINER_IMAGE", "Imagen de contenedor"
    NETWORK_DEVICE = "NETWORK_DEVICE", "Dispositivo de red"
    OTHER = "OTHER", "Otro"


class Criticality(models.TextChoices):
    # No cambiar: son las clases del dataset de evaluación de la tesis.
    CRITICO = "CRITICO", "Crítico"
    ALTO = "ALTO", "Alto"
    MEDIO = "MEDIO", "Medio"
    BAJO = "BAJO", "Bajo"
    INFORMATIVO = "INFORMATIVO", "Informativo"


class CriticalitySource(models.TextChoices):
    MANUAL = "MANUAL", "Manual"
    LLM_ACCEPTED = "LLM_ACCEPTED", "Sugerencia LLM aceptada"
    LLM_EDITED = "LLM_EDITED", "Sugerencia LLM editada"
    IMPORT = "IMPORT", "Importación"


class Exposure(models.TextChoices):
    INTERNET = "INTERNET", "Internet"
    DMZ = "DMZ", "DMZ"
    INTERNAL = "INTERNAL", "Red interna"
    ISOLATED = "ISOLATED", "Red aislada"


class ExposureSource(models.TextChoices):
    RANGE = "RANGE", "Heredada del rango"
    MANUAL = "MANUAL", "Manual"


class DataClassification(models.TextChoices):
    PUBLICA = "PUBLICA", "Pública"
    INTERNA = "INTERNA", "Interna"
    CONFIDENCIAL = "CONFIDENCIAL", "Confidencial"
    RESTRINGIDA = "RESTRINGIDA", "Restringida"


class DataCategory(models.TextChoices):
    PII = "PII", "Datos personales"
    FINANCIERO = "FINANCIERO", "Financieros"
    CLINICO = "CLINICO", "Clínicos"
    CREDENCIALES = "CREDENCIALES", "Credenciales"
    PROPIEDAD_INTELECTUAL = "PROPIEDAD_INTELECTUAL", "Propiedad intelectual"


class Environment(models.TextChoices):
    PROD = "PROD", "Producción"
    STAGING = "STAGING", "Staging"
    DEV = "DEV", "Desarrollo"
    TEST = "TEST", "Pruebas"
    LAB = "LAB", "Laboratorio"


class BusinessRole(models.TextChoices):
    WEB_PUBLICA = "WEB_PUBLICA", "Web pública"
    API = "API", "API"
    BASE_DATOS = "BASE_DATOS", "Base de datos"
    AUTENTICACION = "AUTENTICACION", "Autenticación"
    PAGOS = "PAGOS", "Pagos"
    CORREO = "CORREO", "Correo"
    ARCHIVOS = "ARCHIVOS", "Archivos"
    MONITOREO = "MONITOREO", "Monitoreo"
    CI_CD = "CI_CD", "CI/CD"
    INFRA_RED = "INFRA_RED", "Infraestructura de red"
    ENDPOINT = "ENDPOINT", "Endpoint"
    OTRO = "OTRO", "Otro"


class AssetStatus(models.TextChoices):
    UNCONFIRMED = "UNCONFIRMED", "Por confirmar"
    ACTIVE = "ACTIVE", "Activo"
    STALE = "STALE", "Sin ver"
    IGNORED = "IGNORED", "Ignorado"
    RETIRED = "RETIRED", "Retirado"


class AssetOrigin(models.TextChoices):
    MANUAL = "MANUAL", "Alta manual"
    IMPORT = "IMPORT", "Importación CSV"
    DISCOVERY = "DISCOVERY", "Descubrimiento"
    REGISTRY = "REGISTRY", "Registry"
    SBOM = "SBOM", "SBOM"


class IdentifierKind(models.TextChoices):
    IPV4 = "IPV4", "IPv4"
    IPV6 = "IPV6", "IPv6"
    MAC = "MAC", "MAC"
    FQDN = "FQDN", "FQDN"
    IMAGE_REF = "IMAGE_REF", "Referencia de imagen"
    IMAGE_DIGEST = "IMAGE_DIGEST", "Digest de imagen"
    URL = "URL", "URL"


class SuggestionState(models.TextChoices):
    PENDING = "PENDING", "Pendiente"
    ACCEPTED = "ACCEPTED", "Aceptada"
    EDITED = "EDITED", "Editada"
    REJECTED = "REJECTED", "Rechazada"
    SUPERSEDED = "SUPERSEDED", "Reemplazada"
    FAILED = "FAILED", "Fallida"
    # Revisión tras un cambio de contexto que confirma la decisión humana vigente.
    CONSISTENT = "CONSISTENT", "Coincide con la decisión vigente"


class SuggestionTrigger(models.TextChoices):
    MANUAL = "MANUAL", "Solicitud manual"
    CREATE = "CREATE", "Alta sin criticidad"
    IMPORT = "IMPORT", "Importación sin criticidad"
    CONFIRM = "CONFIRM", "Confirmación"
    CONTEXT_CHANGE = "CONTEXT_CHANGE", "Cambio de contexto"
    NIGHTLY = "NIGHTLY", "Barrido nocturno"


class ContextCompleteness(models.TextChoices):
    COMPLETE = "COMPLETE", "Completo"
    PARTIAL = "PARTIAL", "Parcial"


class DiscoverySchedule(models.TextChoices):
    NONE = "NONE", "Sin programar"
    DAILY = "DAILY", "Diaria"
    WEEKLY = "WEEKLY", "Semanal"


class SbomFormat(models.TextChoices):
    CYCLONEDX_JSON = "CYCLONEDX_JSON", "CycloneDX JSON"
    SPDX_JSON = "SPDX_JSON", "SPDX JSON"


class ServiceProtocol(models.TextChoices):
    TCP = "tcp", "TCP"
    UDP = "udp", "UDP"


class ServiceState(models.TextChoices):
    OPEN = "open", "Abierto"
    CLOSED = "closed", "Cerrado"
    FILTERED = "filtered", "Filtrado"


class ConflictSource(models.TextChoices):
    DISCOVERY = "discovery", "Descubrimiento"
    IMPORT = "import", "Importación"
    REGISTRY = "registry", "Registry"
    SBOM = "sbom", "SBOM"
    MANUAL = "manual", "Alta manual"


class ConflictResolution(models.TextChoices):
    MERGED = "MERGED", "Fusionados"
    DISTINCT = "DISTINCT", "Son distintos"
    DISMISSED = "DISMISSED", "Descartado"


# Precedencia de identidad (sección 7): primero el más confiable.
IDENTITY_PRECEDENCE = (
    IdentifierKind.IMAGE_DIGEST,
    IdentifierKind.MAC,
    IdentifierKind.FQDN,
    IdentifierKind.IPV4,
    IdentifierKind.IPV6,
    IdentifierKind.IMAGE_REF,
    IdentifierKind.URL,
)

"""Registro de cada inferencia LLM (evidencia y métricas para la tesis)."""

from django.conf import settings
from django.db import models
from simple_history.models import HistoricalRecords

from apps.core.models import UUIDModel


class InferenceTask(models.TextChoices):
    ASSET_CRITICALITY = "ASSET_CRITICALITY", "Criticidad de activo"
    CTI_EXTRACTION = "CTI_EXTRACTION", "Extracción CTI"
    EXEC_NARRATIVE = "EXEC_NARRATIVE", "Narrativa ejecutiva"
    DETECTION_PLANNER = "DETECTION_PLANNER", "Planificador de detección"
    ORG_PROFILE_DRAFT = "ORG_PROFILE_DRAFT", "Borrador del perfil de la organización"


class InferenceLog(UUIDModel):
    """Se escribe siempre, incluso en error. Métricas de Ollama convertidas de ns a ms."""

    task = models.CharField(max_length=20, choices=InferenceTask.choices)
    model = models.CharField(max_length=100)
    model_digest = models.CharField(max_length=100, blank=True)
    # Modelo que Ollama dice haber usado en la respuesta: si difiere de ``model`` hubo una
    # sustitución y la decisión debe marcarse (nunca una sustitución silenciosa).
    model_responded = models.CharField(max_length=100, blank=True)
    prompt_version = models.CharField(max_length=20)
    request_payload = models.JSONField(default=dict)
    response_raw = models.TextField(blank=True)
    parsed = models.JSONField(null=True, blank=True)
    parsed_ok = models.BooleanField(default=False)
    error = models.TextField(blank=True)
    options = models.JSONField(default=dict)
    accelerator = models.CharField(max_length=10, blank=True, help_text="gpu / cpu / mock")
    attempts = models.PositiveSmallIntegerField(default=1)

    total_duration_ms = models.FloatField(null=True, blank=True)
    load_duration_ms = models.FloatField(null=True, blank=True)
    prompt_eval_count = models.PositiveIntegerField(null=True, blank=True)
    prompt_eval_duration_ms = models.FloatField(null=True, blank=True)
    eval_count = models.PositiveIntegerField(null=True, blank=True)
    eval_duration_ms = models.FloatField(null=True, blank=True)
    tokens_per_second = models.FloatField(null=True, blank=True)

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    object_ref = models.CharField(max_length=100, blank=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "inferencia LLM"
        verbose_name_plural = "inferencias LLM"
        indexes = [models.Index(fields=["task", "model"])]

    def __str__(self):
        status = "ok" if self.parsed_ok else "error"
        return f"{self.get_task_display()} · {self.model} · {status}"

    @property
    def model_mismatch(self):
        return bool(self.model_responded) and self.model_responded != self.model


class LLMSettings(models.Model):
    """Configuración global del LLM (una sola fila). Solo administradores la cambian."""

    active_model = models.CharField(
        "modelo activo",
        max_length=100,
        blank=True,
        help_text="Vacío = LLM_DEFAULT_MODEL. Se usa en todas las inferencias del sistema.",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    updated_at = models.DateTimeField(auto_now=True)

    history = HistoricalRecords()

    class Meta:
        verbose_name = "configuración del LLM"
        verbose_name_plural = "configuración del LLM"
        permissions = [("manage_llm", "Elegir el modelo LLM del sistema")]

    def __str__(self):
        return self.active_model or "(predeterminado)"

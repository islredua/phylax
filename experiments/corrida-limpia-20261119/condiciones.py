# Solo lectura: las condiciones de la plataforma al empezar la corrida.
import json
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from apps.cti.models import CtiSource, CveRecord
from apps.detection.models import AutomationSettings, OrganizationProfile, TreatmentPolicy
from apps.llm import prompts
from apps.scanners.models import ScannerDataRun
from apps.scoring import services as scoring

auto = AutomationSettings.objects.first()
out = {
    "algoritmo_scoring": scoring.ALGORITHM_VERSION,
    "modelo": settings.LLM_DEFAULT_MODEL,
    "zona_horaria": settings.TIME_ZONE,
    "automatizacion": {
        "modo": auto.mode,
        "pausada": auto.paused,
        "difiere_acciones_pesadas": auto.defer_heavy_actions,
        "ventana": f"{auto.off_hours_start:%H:%M}-{auto.off_hours_end:%H:%M}",
        "escala_criticas_a_una_persona": auto.escalate_critical,
        "max_escaneos_por_hora": auto.max_scans_per_hour,
        "max_ejecuciones_simultaneas": auto.max_concurrent_executions,
        "max_llamadas_planificador_por_hora": auto.max_planner_calls_per_hour,
    },
    "organizacion": OrganizationProfile.objects.first().name,
    "politica_tratamiento_dias": {
        k: getattr(TreatmentPolicy.objects.first(), k)
        for k in ("critical_days", "very_high_days", "high_days", "moderate_days", "low_days")
    },
    "inteligencia": {
        "cve_en_espejo": CveRecord.objects.count(),
        "cve_en_kev": CveRecord.objects.exclude(kev_added_at=None).count(),
        "fuentes": {
            s.kind: timezone.localtime(s.last_success_at).isoformat(timespec="seconds")
            for s in CtiSource.objects.all()
            if s.last_success_at
        },
    },
    "datos_escaneres": [
        {
            k: (v.isoformat(timespec="seconds") if hasattr(v, "isoformat") else v)
            for k, v in r.__dict__.items()
            if k in ("dataset", "trigger", "status", "finished_at", "data_date_before", "data_date_after")
        }
        for r in ScannerDataRun.objects.order_by("-created_at")[:4]
    ],
    "ajustes": {
        k: getattr(settings, k)
        for k in (
            "DETECTION_CONSOLIDATE_DELAY_S",
            "DETECTION_CONSOLIDATE_CHUNK",
            "DETECTION_DESCRIBE_BATCH",
            "DETECTION_DESCRIBE_BURST",
            "DETECTION_EPSS_HIGH",
            "SCANNER_TIMEOUT_S",
        )
        if hasattr(settings, k)
    },
}
root = Path(settings.BASE_DIR) / "apps" / "llm" / "prompts"
out["prompts"] = {
    d.name: sorted((p.stem for p in d.glob("v*.md")), key=lambda v: int(v[1:]))[-1]
    for d in sorted(root.iterdir())
    if d.is_dir() and list(d.glob("v*.md"))
}
print("COND" + json.dumps(out, ensure_ascii=False, default=str))

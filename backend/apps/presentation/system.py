"""Estado del sistema para Administración: servicios, colas, datos y almacenamiento.

Administración solo hablaba de cuentas. Aquí se reúne lo que antes exigía la consola: si la base
de datos, Redis, Ollama, los tres trabajadores y el programador están en marcha; qué espera en
cada cola y qué corre ahora; de cuándo son las fuentes de inteligencia y los datos de los
escáneres; y cuánto espacio queda.

Cómo se sabe cada cosa, sin bloquear la petición web:

- **Trabajadores y programador**: ``refresh_system_status`` (beat, cada minuto) pregunta a los
  trabajadores quién vive, qué colas atiende y qué ejecuta, y lo deja en la caché. Ese registro es
  a la vez el latido del programador: si es reciente, beat y el trabajador general funcionan. Si
  se queda viejo, la pantalla pregunta en vivo (unos segundos) para decir cuál de los dos falta.
- **Base de datos y Redis**: una consulta directa, con espera corta.
- **Ollama**: el último sondeo de ``apps.llm.status`` (beat, cada minuto).
- **Colas**: longitud de cada lista en Redis; el contenido de la cola del modelo se lee completo
  para decir cuántas tareas de cada tipo esperan y cuánto tardarán.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import statistics
import time
from collections import Counter, defaultdict

from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.utils import timezone

from apps.core.text import cuantos

OK, WARN, DOWN, UNKNOWN = "ok", "warn", "down", "unknown"
SNAPSHOT_KEY = "system:workers"
SNAPSHOT_TTL = 24 * 3600
STALE_AFTER_S = 180  # tres latidos perdidos

QUEUES = (
    {
        "name": "default",
        "label": "General",
        "service": "worker",
        "what": "Inventario, sincronizaciones de inteligencia, avisos y tareas programadas",
        "without": "no corren las sincronizaciones, los avisos ni las tareas programadas",
    },
    {
        "name": "llm",
        "label": "Modelo",
        "service": "worker-llm",
        "what": "Todo lo que decide o redacta el modelo local, de una en una",
        "without": "nada de lo que decide o redacta el modelo avanza",
    },
    {
        "name": "discovery",
        "label": "Descubrimiento y escaneo",
        "service": "worker-discovery",
        "what": "nmap, nuclei y Grype: el único con acceso a las redes escaneadas",
        "without": "no hay descubrimiento ni escaneos",
    },
)
QUEUE_NAMES = tuple(q["name"] for q in QUEUES)

# Cada tarea del proyecto con un nombre que se entiende (una prueba vigila que no falte ninguna).
TASK_LABELS = {
    "apps.accounts.tasks.purge_expired_sessions": "Depurar sesiones caducadas",
    "apps.alerts.tasks.dispatch_alerts": "Enviar avisos",
    "apps.assets.tasks.auto_suggest_criticality": "Sugerir la criticidad de un activo nuevo",
    "apps.assets.tasks.expire_import_previews": "Depurar importaciones sin confirmar",
    "apps.assets.tasks.import_assets_csv": "Importar activos desde un archivo",
    "apps.assets.tasks.mark_stale_assets": "Marcar los activos que ya no se ven",
    "apps.assets.tasks.suggest_criticality": "Sugerir la criticidad de un activo",
    "apps.assets.tasks.sweep_unclassified_criticality": "Barrido de activos sin criticidad",
    "apps.cti.tasks.pull_product_coverage": "Traer los CVE de un producto del inventario",
    "apps.cti.tasks.sync_cti_source": "Sincronizar una fuente de inteligencia",
    "apps.cti.tasks.sync_cti_sources": "Sincronizar las fuentes de inteligencia",
    "apps.detection.tasks.consolidate_asset": "Consolidar los reportes de un activo",
    "apps.detection.tasks.describe_pending_vulnerabilities": "Encolar explicaciones pendientes",
    "apps.detection.tasks.describe_software": "Explicar qué es un software",
    "apps.detection.tasks.describe_business_role": "Explicar una función de negocio",
    "apps.detection.tasks.describe_business_risk": "Explicar qué puede pasar en un riesgo",
    "apps.detection.tasks.describe_vulnerability": "Redactar la explicación de una vulnerabilidad",
    "apps.detection.tasks.dispatch_actions": "Enviar acciones aprobadas a las herramientas",
    "apps.detection.tasks.draft_org_profile": "Redactar el perfil de la organización",
    "apps.detection.tasks.emit_time_reviews": "Señalar lo que lleva mucho sin revisarse",
    "apps.detection.tasks.plan_event": "Decidir qué hacer con una señal",
    "apps.detection.tasks.plan_stragglers": "Retomar señales sin decisión",
    "apps.detection.tasks.process_event_batch": "Procesar un lote de señales",
    "apps.detection.tasks.process_pending_events": "Agrupar las señales nuevas",
    "apps.detection.tasks.refresh_asset_components": "Actualizar el software de un activo",
    "apps.discovery.tasks.probe_asset": "Sondeo de un activo",
    "apps.discovery.tasks.probe_host": "Sondeo de un equipo",
    "apps.discovery.tasks.run_discovery": "Descubrimiento de un rango",
    "apps.discovery.tasks.run_scheduled_discoveries": "Lanzar los descubrimientos programados",
    "apps.llm.tasks.refresh_llm_status": "Consultar el estado del modelo",
    "apps.presentation.tasks.apply_retention": "Aplicar la retención de datos",
    "apps.presentation.tasks.generate_health_narrative": "Redactar la lectura de Inicio",
    "apps.presentation.tasks.recover_lost_work": "Retomar el trabajo que se quedó sin cola",
    "apps.presentation.tasks.refresh_health_narrative": "Revisar si toca redactar la lectura",
    "apps.presentation.tasks.refresh_system_status": "Latido del sistema",
    "apps.presentation.tasks.snapshot_health": "Guardar la instantánea de Inicio",
    "apps.scanners.tasks.recover_orphaned_executions": "Cerrar escaneos interrumpidos",
    "apps.scanners.tasks.run_tool": "Escaneo con nuclei o Grype",
    "apps.scanners.tasks.update_scanner_data": "Actualizar los datos de un escáner",
    "apps.scanners.tasks.update_scanner_data_scheduled": "Pedir la actualización de los escáneres",
}
# La tarea que pregunta no cuenta como trabajo en curso.
HEARTBEAT_TASK = "apps.presentation.tasks.refresh_system_status"
# Qué inferencias hace cada tarea de la cola del modelo: de ahí sale cuánto tarda.
TASK_INFERENCES = {
    "apps.detection.tasks.describe_vulnerability": ("VULN_DESCRIBE",),
    "apps.detection.tasks.describe_software": ("SOFTWARE_DESCRIBE",),
    "apps.detection.tasks.describe_business_role": ("ROLE_DESCRIBE",),
    "apps.detection.tasks.describe_business_risk": ("ORG_RISK_DESCRIBE",),
    "apps.detection.tasks.consolidate_asset": (
        "VULN_ASSESSMENT",
        "RISK_ASSESSMENT",
        "RISK_NARRATIVE",
    ),
    "apps.detection.tasks.plan_event": ("DETECTION_PLANNER",),
    "apps.detection.tasks.draft_org_profile": ("ORG_PROFILE_DRAFT",),
    "apps.assets.tasks.suggest_criticality": ("ASSET_CRITICALITY",),
    "apps.presentation.tasks.generate_health_narrative": ("EXEC_NARRATIVE",),
}
DEFAULT_TASK_SECONDS = 10.0
# Inferencias del mismo objeto separadas por más de esto son ejecuciones distintas de la tarea.
BURST_GAP_S = 600


def task_label(name) -> str:
    name = str(name or "")
    return TASK_LABELS.get(name) or name.rsplit(".", 1)[-1].replace("_", " ")


def _eager() -> bool:
    """Sin broker (pruebas, modo síncrono): no hay colas ni trabajadores que consultar."""
    return bool(getattr(settings, "CELERY_TASK_ALWAYS_EAGER", False))


def lapse(seconds) -> str:
    """«40 s», «9 min», «3 h», «2 días»: cuánto hace o cuánto falta, sin precisión falsa."""
    seconds = max(float(seconds or 0), 0)
    if seconds < 90:
        return f"{round(seconds)} s"
    minutes = seconds / 60
    if minutes < 90:
        return f"{round(minutes)} min"
    hours = minutes / 60
    if hours < 36:
        return f"{round(hours)} h"
    return cuantos(round(hours / 24), "día")


def megabytes(size) -> str:
    size = float(size or 0)
    if size >= 1024**3:
        return f"{size / 1024**3:.1f} GB"
    return f"{size / 1024**2:,.0f} MB"


# --- Trabajadores: registro que deja el programador -----------------------------------------


def _inspect(timeout):
    from atalaya.celery import app

    return app.control.inspect(timeout=timeout)


def take_snapshot(timeout=1.5, *, store=True) -> dict:
    """Pregunta a los trabajadores quién vive, qué colas atiende y qué ejecuta. Tarda hasta tres
    veces ``timeout``: se llama desde la tarea periódica, no desde una petición normal."""
    inspector = _inspect(timeout)
    stats = inspector.stats() or {}
    active = inspector.active() or {}
    queues = inspector.active_queues() or {}
    moment = time.time()

    def running_s(task):
        started = task.get("time_start")
        # Época (no reloj monótono): solo entonces se puede decir cuánto lleva.
        if isinstance(started, int | float) and started > 1_000_000_000:
            return max(round(moment - started), 0)
        return None

    workers = {}
    for name, info in stats.items():
        workers[name] = {
            "queues": sorted(q.get("name", "") for q in queues.get(name) or []),
            "uptime": info.get("uptime"),
            "concurrency": (info.get("pool") or {}).get("max-concurrency"),
            "active": [
                {"name": t.get("name", ""), "id": t.get("id", ""), "running_s": running_s(t)}
                for t in active.get(name) or []
                if t.get("name") != HEARTBEAT_TASK
            ],
        }
    snap = {"checked_at": timezone.now().isoformat(), "workers": workers}
    if store:
        cache.set(SNAPSHOT_KEY, snap, SNAPSHOT_TTL)
    return snap


def _cached_snapshot():
    try:
        return cache.get(SNAPSHOT_KEY)
    except Exception:  # Redis caído: se informa en su propia fila
        return None


def _age_s(iso, now):
    try:
        return (now - datetime.datetime.fromisoformat(iso)).total_seconds()
    except (TypeError, ValueError):
        return None


def worker_view(now=None, *, live=True) -> dict:
    """Lo que se sabe de los trabajadores: ``{"workers", "age_s", "fresh", "live"}``.

    Con el registro al día se usa tal cual. Si está viejo (o no existe) y ``live`` lo permite, se
    pregunta ahora mismo: así se distingue «el programador no corre» de «no hay trabajadores».
    """
    now = now or timezone.now()
    if _eager():
        return {"workers": {}, "age_s": None, "fresh": False, "live": False, "eager": True}
    snap = _cached_snapshot() or {}
    age = _age_s(snap.get("checked_at"), now)
    fresh = age is not None and age <= STALE_AFTER_S
    view = {"workers": snap.get("workers") or {}, "age_s": age, "fresh": fresh, "live": False}
    if not fresh and live:
        try:
            probe = take_snapshot(timeout=1.0, store=False)
        except Exception:  # sin broker: no hay a quién preguntar
            return {**view, "workers": {}, "live_failed": True}
        view.update(workers=probe["workers"], live=True)
    return view


def _serving(workers, queue):
    return [info for info in workers.values() if queue in (info.get("queues") or [])]


def _doing(info) -> str:
    active = info.get("active") or []
    if not active:
        return "sin tareas ahora"
    first = active[0]
    text = task_label(first.get("name"))
    if first.get("running_s") is not None:
        text += f" (lleva {lapse(first['running_s'])})"
    if len(active) > 1:
        text += f" y {len(active) - 1} más"
    return f"ahora: {text}"


# --- Servicios ------------------------------------------------------------------------------


def _row(key, name, role, state, detail, fix="", label=""):
    # ``label``: palabras propias para la píldora cuando «sin datos» no describe el estado.
    return {
        "key": key,
        "name": name,
        "role": role,
        "state": state,
        "detail": detail,
        "fix": fix,
        "label": label,
    }


def _database():
    name, role = "Base de datos", "PostgreSQL: todo lo que la plataforma guarda"
    try:
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute(
                    "SELECT current_setting('server_version'), "
                    "pg_database_size(current_database())"
                )
                version, size = cursor.fetchone()
                detail = f"PostgreSQL {str(version).split()[0]} · {megabytes(size)}"
            else:  # pragma: no cover - el proyecto corre sobre PostgreSQL
                cursor.execute("SELECT 1")
                size, detail = None, connection.vendor
    except Exception as error:  # pragma: no cover - sin base no hay página que mostrar
        return _row("db", name, role, DOWN, f"No responde ({type(error).__name__})"), None
    return _row("db", name, role, OK, detail), size


def broker_facts() -> dict | None:
    """Redis: versión, memoria y cuánto espera en cada cola. ``None`` si no responde."""
    if _eager():
        return None
    try:
        import redis

        client = redis.Redis.from_url(
            settings.CELERY_BROKER_URL, socket_connect_timeout=2, socket_timeout=2
        )
        info = client.info()
        try:
            snapshots = bool((client.config_get("save") or {}).get("save"))
        except Exception:  # CONFIG deshabilitado en algunos despliegues
            snapshots = False
        return {
            "version": info.get("redis_version", ""),
            "memory": info.get("used_memory", 0),
            "uptime": info.get("uptime_in_seconds", 0),
            # Sin AOF ni instantáneas, un reinicio de Redis pierde lo encolado.
            "persistent": bool(info.get("aof_enabled")) or snapshots,
            "queues": {name: int(client.llen(name)) for name in QUEUE_NAMES},
        }
    except Exception:
        return None


def _broker(facts):
    name, role = "Redis", "Colas de trabajo y caché"
    if _eager():
        return _row("redis", name, role, UNKNOWN, "Modo síncrono: las tareas corren sin cola")
    if facts is None:
        return _row(
            "redis",
            name,
            role,
            DOWN,
            "No responde: nada se encola y la caché no está disponible",
            "Revisa el contenedor redis.",
        )
    detail = f"Redis {facts['version']} · {megabytes(facts['memory'])} en memoria"
    detail += f" · en marcha desde hace {lapse(facts['uptime'])}"
    if facts["persistent"]:
        detail += " · guarda lo encolado en disco"
    else:
        detail += " · no guarda en disco: un reinicio de Redis pierde lo encolado"
    return _row("redis", name, role, OK, detail)


MAIL_CHECK_KEY = "system:mail"
MAIL_CHECK_TTL = 60
SMTP_BACKEND = "apps.core.mail.EmailBackend"
CONSOLE_BACKEND = "django.core.mail.backends.console.EmailBackend"


def _sends_by_smtp(backend) -> bool:
    from django.core.mail.backends import smtp
    from django.utils.module_loading import import_string

    try:
        return issubclass(import_string(backend), smtp.EmailBackend)
    except ImportError:
        return False


def _mail_answers(host, port) -> bool:
    """¿Abre conexión el servidor de correo? Dos segundos de espera y un minuto de memoria: la
    página de Sistema no puede depender de un servidor ajeno."""
    import socket

    key = f"{MAIL_CHECK_KEY}:{host}:{port}"
    known = cache.get(key)
    if known is None:
        try:
            with socket.create_connection((host, port), timeout=2):
                known = True
        except OSError:
            known = False
        cache.set(key, known, MAIL_CHECK_TTL)
    return known


def _mail(*, live=True):
    """Por dónde sale el correo. Restablecer la contraseña y los avisos dependen de él, y un
    despliegue que lo deja en la consola no avisa a nadie de que no llega."""
    name, role = "Correo", "Restablecer la contraseña y avisos por correo"
    backend = settings.EMAIL_BACKEND
    sender = settings.DEFAULT_FROM_EMAIL
    if _sends_by_smtp(backend):
        host, port = settings.EMAIL_HOST or "localhost", settings.EMAIL_PORT
        ca_file = getattr(settings, "EMAIL_CA_FILE", "")
        if ca_file and not os.path.isfile(ca_file):
            return _row(
                "mail",
                name,
                role,
                DOWN,
                f"No existe el archivo de la CA del correo ({ca_file}): el envío cifrado falla",
                "Deja el certificado de la CA en deploy/ca/ y revisa DJANGO_EMAIL_CA_FILE en .env.",
            )
        cipher = (
            "TLS desde la conexión"
            if settings.EMAIL_USE_SSL
            else "STARTTLS"
            if settings.EMAIL_USE_TLS
            else "sin cifrar"
        )
        account = "con usuario" if settings.EMAIL_HOST_USER else "sin usuario"
        trust = ", con la CA de la organización" if ca_file else ""
        detail = f"Sale por {host}:{port} ({cipher}, {account}{trust}) como {sender}"
        if live and not _mail_answers(host, port):
            return _row(
                "mail",
                name,
                role,
                DOWN,
                f"{host}:{port} no responde: el correo no está saliendo",
                "Revisa DJANGO_EMAIL_HOST y DJANGO_EMAIL_PORT en .env y que el servidor acepte "
                "conexiones desde este equipo.",
            )
        return _row("mail", name, role, OK, detail)
    if backend == CONSOLE_BACKEND:
        if settings.EMAIL_HOST:
            # Las dos líneas se contradicen, también en desarrollo: quien puso el servidor espera
            # que el correo salga, y la línea DJANGO_EMAIL_BACKEND (venía en el .env de ejemplo
            # anterior) lo deja en la consola sin decir nada.
            return _row(
                "mail",
                name,
                role,
                WARN,
                f"Hay un servidor configurado ({settings.EMAIL_HOST}), pero el correo se imprime "
                "en la consola: nadie lo recibe",
                "DJANGO_EMAIL_BACKEND lo manda a la consola: quita esa línea de .env.",
            )
        if settings.DEBUG:
            return _row(
                "mail",
                name,
                role,
                UNKNOWN,
                "Se imprime en la consola del backend (desarrollo): nadie lo recibe",
                label="solo consola",
            )
        return _row(
            "mail",
            name,
            role,
            WARN,
            "Se imprime en la consola del servidor: nadie recibe el enlace para restablecer "
            "la contraseña ni los avisos por correo",
            "Define DJANGO_EMAIL_HOST en .env (y puerto, usuario y cifrado si hacen falta).",
        )
    return _row(
        "mail", name, role, UNKNOWN, f"Lo entrega {backend.rsplit('.', 2)[-2]}", label="a medida"
    )


def _model():
    from apps.llm import status

    name, role = "Ollama", "Servidor del modelo local"
    state = status.get_status()
    active = status.active_model()
    if state.get("available") is False:
        return _row(
            "ollama",
            name,
            role,
            DOWN,
            "No responde: lo que depende del modelo espera en su cola hasta que vuelva",
            "Revisa el contenedor ollama.",
        )
    if state.get("available") is None:
        return _row("ollama", name, role, UNKNOWN, "Aún no se ha consultado")
    accelerator = str(state.get("accelerator") or "").lower()
    parts = [f"modelo activo {active}"]
    if accelerator in ("gpu", "cpu"):
        parts.append(accelerator.upper())
    if state.get("version"):
        parts.append(f"Ollama {state['version']}")
    detail = " · ".join(parts)
    if not status.active_model_ready():
        return _row(
            "ollama",
            name,
            role,
            WARN,
            f"El modelo activo ({active}) no está descargado",
            "Descárgalo o elige otro en Administración › LLM.",
        )
    if accelerator == "cpu" and str(settings.LLM_ACCELERATOR).lower() == "gpu":
        return _row(
            "ollama",
            name,
            role,
            WARN,
            detail + " · se esperaba GPU y corre en CPU: cada inferencia tarda varias veces más",
            "Revisa que el contenedor vea la tarjeta gráfica.",
        )
    return _row("ollama", name, role, OK, detail)


def _workers(view):
    rows = []
    for queue in QUEUES:
        name = f"Trabajador · {queue['label'].lower()}"
        key = f"worker-{queue['name']}"
        if view.get("eager"):
            rows.append(
                _row(key, name, queue["what"], UNKNOWN, "Modo síncrono: no hay trabajadores")
            )
            continue
        serving = _serving(view["workers"], queue["name"])
        if serving:
            info = serving[0]
            parts = []
            if info.get("uptime") is not None:
                parts.append(f"en marcha desde hace {lapse(info['uptime'])}")
            if info.get("concurrency"):
                parts.append(cuantos(info["concurrency"], "proceso"))
            parts.append(_doing(info))
            if len(serving) > 1:
                parts.append(cuantos(len(serving), "trabajador", "trabajadores"))
            rows.append(_row(key, name, queue["what"], OK, " · ".join(parts)))
        elif view["fresh"] or view["live"]:
            rows.append(
                _row(
                    key,
                    name,
                    queue["what"],
                    DOWN,
                    f"No responde: {queue['without']}",
                    f"Revisa el contenedor {queue['service']}.",
                )
            )
        else:
            rows.append(_row(key, name, queue["what"], UNKNOWN, "No se pudo consultar"))
    return rows


def _scheduler(view):
    name, role = "Programador", "Lanza las tareas periódicas (beat)"
    if view.get("eager"):
        return _row("beat", name, role, UNKNOWN, "Modo síncrono: no hay tareas periódicas")
    if view["fresh"]:
        return _row("beat", name, role, OK, f"último latido hace {lapse(view['age_s'])}")
    if view["age_s"] is None:
        # Recién arrancado (o Redis reiniciado): el primer latido tarda hasta un minuto.
        return _row(
            "beat", name, role, UNKNOWN, "Aún no llega el primer latido; se espera uno por minuto"
        )
    since = f"hace {lapse(view['age_s'])}"
    if view["live"] and _serving(view["workers"], "default"):
        return _row(
            "beat",
            name,
            role,
            DOWN,
            f"Sin latido desde {since} aunque el trabajador general responde: las tareas "
            "periódicas no se están lanzando",
            "Revisa el contenedor beat.",
        )
    return _row(
        "beat",
        name,
        role,
        UNKNOWN,
        f"Sin latido desde {since}; no hay trabajador general que lo confirme",
    )


# --- Colas ----------------------------------------------------------------------------------


def queues(facts, view, now) -> list[dict]:
    rows = []
    for queue in QUEUES:
        serving = _serving(view["workers"], queue["name"])
        active = [task for info in serving for task in info.get("active") or []]
        rows.append(
            {
                **queue,
                "waiting": (facts or {}).get("queues", {}).get(queue["name"]),
                "active": [task_label(task.get("name")) for task in active],
                "served": bool(serving),
            }
        )
    return rows


def _seconds_per_task(kinds) -> float | None:
    """Segundos de inferencia que suele costar una tarea: la mediana de sus ejecuciones recientes.

    Una consolidación hace varias inferencias para el mismo activo: se suman las que van seguidas.
    """
    from apps.llm.models import InferenceLog

    logs = (
        InferenceLog.objects.filter(task__in=kinds, parsed_ok=True, total_duration_ms__isnull=False)
        .order_by("-created_at")
        .values_list("object_ref", "created_at", "total_duration_ms")[:400]
    )
    by_ref = defaultdict(list)
    for ref, at, ms in logs:
        by_ref[ref].append((at, ms))
    bursts = []
    for items in by_ref.values():
        items.sort()
        total, last = 0.0, None
        for at, ms in items:
            if last is not None and (at - last).total_seconds() > BURST_GAP_S:
                bursts.append(total)
                total = 0.0
            total += ms
            last = at
        bursts.append(total)
    return statistics.median(bursts) / 1000 if bursts else None


def _queued_tasks(name) -> list[str] | None:
    """Nombres de las tareas que esperan en una cola (cabecera de cada mensaje de Celery)."""
    if _eager():
        return []
    try:
        import redis

        client = redis.Redis.from_url(
            settings.CELERY_BROKER_URL, socket_connect_timeout=2, socket_timeout=2
        )
        raw = client.lrange(name, 0, 4999)
    except Exception:
        return None
    names = []
    for message in raw:
        try:
            names.append(json.loads(message)["headers"]["task"])
        except (ValueError, KeyError, TypeError):
            names.append("")
    return names


def model_queue(now=None, *, live=False) -> dict:
    """Lo que espera el modelo: qué hay en cola, qué corre, qué falta por encolar y cuánto tardará."""
    from apps.detection.descriptions import SUSTAINED
    from apps.detection.models import StatusSource, Vulnerability

    now = now or timezone.now()
    names = _queued_tasks("llm")
    view = worker_view(now, live=live)
    serving = _serving(view["workers"], "llm")
    running = [task for info in serving for task in info.get("active") or []]

    rows, total = [], 0.0
    for name, count in Counter(names or []).most_common():
        each = _seconds_per_task(TASK_INFERENCES.get(name, ())) if name in TASK_INFERENCES else None
        seconds = (each or DEFAULT_TASK_SECONDS) * count
        total += seconds
        rows.append(
            {
                "label": task_label(name) if name else "Tarea sin identificar",
                "count": count,
                "each": each,
                "seconds": seconds,
                # Sin precisión falsa: «12 min», no «12 min 8 s».
                "total": lapse(seconds),
            }
        )
    # Las explicaciones se encolan por lotes: lo que aún no entra a la cola también es trabajo.
    undescribed = (
        Vulnerability.objects.filter(status__in=SUSTAINED, summary="")
        .exclude(description_source=StatusSource.HUMAN)
        .count()
    )
    queued_describe = Counter(names or []).get("apps.detection.tasks.describe_vulnerability", 0)
    backlog = max(undescribed - queued_describe, 0)
    backlog_each = _seconds_per_task(("VULN_DESCRIBE",)) if backlog else None
    backlog_seconds = backlog * (backlog_each or DEFAULT_TASK_SECONDS)
    waiting = len(names) if names is not None else None
    busy = bool(waiting) or bool(running)
    return {
        "known": names is not None and not view.get("eager"),
        "eager": bool(view.get("eager")),
        "waiting": waiting,
        "rows": rows,
        "running": [
            {
                "label": task_label(task.get("name")),
                "lapse": lapse(task["running_s"]) if task.get("running_s") is not None else "",
            }
            for task in running
        ],
        "served": bool(serving),
        "workers_known": view["fresh"] or view["live"],
        "seconds": total,
        "eta": lapse(total) if total else "",
        "backlog": backlog,
        "backlog_eta": lapse(backlog_seconds) if backlog else "",
        "idle": not busy and not backlog,
        "safe_to_restart": names is not None and not busy,
    }


# --- Datos y almacenamiento -----------------------------------------------------------------


def intelligence(now=None) -> list[dict]:
    """Fuentes de inteligencia: cuándo se sincronizó cada una y si va atrasada."""
    from apps.cti.models import CtiSource

    now = now or timezone.now()
    rows = []
    for source in CtiSource.objects.all():
        age = (now - source.last_success_at).total_seconds() if source.last_success_at else None
        interval = source.interval_hours * 3600
        if not source.enabled:
            state, note = UNKNOWN, "Deshabilitada"
        elif age is None:
            state, note = WARN, "Nunca se ha sincronizado"
        elif age > 2 * interval + 3600:
            state, note = WARN, f"Atrasada: se sincroniza cada {lapse(interval)}"
        else:
            state, note = OK, f"Cada {lapse(interval)}"
        if source.enabled and source.last_status == "FAILED":
            state, note = WARN, "La última sincronización falló"
        rows.append(
            {
                "name": str(source),
                "state": state,
                "note": note,
                "last_success_at": source.last_success_at,
                "age": lapse(age) if age is not None else "",
            }
        )
    return rows


def storage(db_size=None) -> list[dict]:
    """Espacio libre donde viven los datos. Varias carpetas suelen compartir el mismo disco."""
    places = (
        ("Archivos subidos", settings.MEDIA_ROOT),
        ("Resultados de escaneo", getattr(settings, "SCAN_RESULTS_DIR", "")),
        ("Datos de inteligencia y escáneres", _cti_cache_dir()),
    )
    rows, seen = [], {}
    for label, path in places:
        if not path:
            continue
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        key = (usage.total, usage.free)
        if key in seen:
            seen[key]["labels"].append(label)
            continue
        free = usage.free / usage.total if usage.total else 0
        row = {
            "labels": [label],
            "free": megabytes(usage.free),
            "total": megabytes(usage.total),
            "used_pct": round((1 - free) * 100),
            "state": DOWN if free < 0.05 else WARN if free < 0.15 else OK,
        }
        seen[key] = row
        rows.append(row)
    return rows


def _cti_cache_dir() -> str:
    from apps.scanners import data

    return str(data.templates_dir().parent)


# --- Todo junto -----------------------------------------------------------------------------


def report(now=None, *, live=True) -> dict:
    """Todo lo que muestra Administración › Sistema."""
    from apps.scanners import data as scanner_data

    now = now or timezone.now()
    view = worker_view(now, live=live)
    facts = broker_facts()
    database, db_size = _database()
    services = [
        database,
        _broker(facts),
        _model(),
        *_workers(view),
        _scheduler(view),
        _mail(live=live),
    ]
    scanner = scanner_data.datasets(now)
    sources = intelligence(now)
    disks = storage(db_size)
    problems = [
        {"name": row["name"], "state": row["state"], "detail": row["detail"]}
        for row in services
        if row["state"] in (DOWN, WARN)
    ]
    problems += [
        {
            "name": item["name"],
            "state": WARN if item["state"] == WARN else DOWN,
            "detail": item["note"],
        }
        for item in scanner
        if item["state"] != OK
    ]
    problems += [
        {"name": f"Fuente {row['name']}", "state": WARN, "detail": row["note"]}
        for row in sources
        if row["state"] == WARN
    ]
    problems += [
        {
            "name": "Espacio en disco",
            "state": row["state"],
            "detail": f"Queda {row['free']} libre de {row['total']}",
        }
        for row in disks
        if row["state"] != OK
    ]
    return {
        "now": now,
        "services": services,
        "queues": queues(facts, view, now),
        "queues_known": facts is not None,
        "scanner_data": scanner,
        "sources": sources,
        "storage": disks,
        "db_size": megabytes(db_size) if db_size else "",
        "problems": problems,
        "state": DOWN if any(p["state"] == DOWN for p in problems) else WARN if problems else OK,
        "heartbeat_age": lapse(view["age_s"]) if view.get("age_s") is not None else "",
        "eager": bool(view.get("eager")),
    }


def headline(now=None) -> dict:
    """Resumen barato para otras pantallas (sin preguntar en vivo): estado y cuántos problemas."""
    data = report(now, live=False)
    return {"state": data["state"], "problems": data["problems"], "eager": data["eager"]}

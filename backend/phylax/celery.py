"""Aplicación Celery de Phylax (D7).

Colas: ``default`` (inventario, importaciones), ``llm`` (inferencia, concurrencia 1
para proteger la GPU/CPU) y ``discovery`` (nmap, concurrencia 1, worker con
capabilities de red). Configuración en settings con prefijo ``CELERY_``.
"""

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phylax.settings")

app = Celery("phylax")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

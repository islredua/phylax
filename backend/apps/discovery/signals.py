"""Señal de dominio del descubrimiento: una ejecución terminó (en cualquier estado)."""

from django.dispatch import Signal

# kwargs: run_id (UUID), status (RunStatus), asset_id (UUID | None)
run_finished = Signal()

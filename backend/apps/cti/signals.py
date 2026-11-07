"""Señales de dominio del almacén CTI.

``changes_detected`` se emite al terminar una sincronización que produjo cambios
(``CtiChange``). El módulo de detección se suscribe para convertirlos en eventos; ``cti``
no conoce a sus consumidores.
"""

from django.dispatch import Signal

# kwargs: run (CtiSyncRun), changes (list[CtiChange])
changes_detected = Signal()

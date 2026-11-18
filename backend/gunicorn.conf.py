"""Servidor web del perfil de producción (``docker-compose.prod.yml``).

gunicorn lee este archivo solo, por estar en el directorio desde el que arranca. Las opciones no
viajan en la línea de órdenes: ahí un salto de línea las dejó fuera sin avisar y el servidor
corría con un solo proceso, atendiendo las páginas de una en una.
"""

import os

bind = "0.0.0.0:8000"  # noqa: S104 - dentro del contenedor; desde fuera solo llega el proxy
# Cada proceso ejecuta Python para una petición a la vez (los hilos cubren las esperas de base
# de datos y de red): son los procesos los que reparten el trabajo entre núcleos.
workers = int(os.environ.get("ATALAYA_WEB_WORKERS") or 3)
threads = 4
timeout = 60
accesslog = "-"
errorlog = "-"

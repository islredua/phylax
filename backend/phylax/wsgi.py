"""WSGI config para Phylax."""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "phylax.settings")
application = get_wsgi_application()

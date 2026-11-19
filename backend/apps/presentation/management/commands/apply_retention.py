"""Aplica la política de retención ahora (lo mismo que hace la tarea diaria).

python manage.py apply_retention --dry-run    # solo dice cuánto quitaría
python manage.py apply_retention
"""

from django.core.management.base import BaseCommand

from apps.presentation import retention


class Command(BaseCommand):
    help = "Depura señales descartadas, cambios de inteligencia e inferencias según la política."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="No borra: solo cuenta.")

    def handle(self, *args, dry_run=False, **options):
        policy = retention.current()
        result = retention.apply(dry_run=dry_run)
        verb = "Se quitarían" if dry_run else "Se quitaron"
        for kind in retention._kinds():
            days = retention.effective_days(kind, policy)
            kept = f"se conservan {days} días" if days else "se conserva siempre"
            self.stdout.write(f"{kind['label']}: {verb.lower()} {result[kind['key']]} ({kept})")
        if result.get("capped"):
            self.stdout.write("Se alcanzó el tope de la pasada; la siguiente continúa.")

from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand

from apps.accounts.roles import ROLES, sync_roles


class Command(BaseCommand):
    help = "Crea o actualiza los grupos de rol (admin, operador, auditor) y sus permisos."

    def handle(self, *args, **options):
        sync_roles()
        for group in Group.objects.filter(name__in=ROLES).order_by("name"):
            self.stdout.write(f"{group.name}: {group.permissions.count()} permisos")
        self.stdout.write(self.style.SUCCESS("Roles sincronizados."))

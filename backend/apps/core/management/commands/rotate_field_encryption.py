from django.apps import apps
from django.core.management.base import BaseCommand
from django.db import connection

from apps.core import crypto
from apps.core.fields import EncryptedTextField


class Command(BaseCommand):
    help = (
        "Re-cifra todos los campos cifrados con la llave primaria de PHYLAX_FIELD_ENCRYPTION_KEYS."
    )

    def handle(self, *args, **options):
        total = 0
        for model in apps.get_models():
            fields = [f for f in model._meta.concrete_fields if isinstance(f, EncryptedTextField)]
            if not fields:
                continue
            table = connection.ops.quote_name(model._meta.db_table)
            pk = connection.ops.quote_name(model._meta.pk.column)
            for field in fields:
                column = connection.ops.quote_name(field.column)
                with connection.cursor() as cursor:
                    # Se lee el token crudo (sin from_db_value) para rotarlo sin pasar por texto claro en Python.
                    cursor.execute(
                        f"SELECT {pk}, {column} FROM {table} WHERE {column} <> ''"  # noqa: S608
                    )
                    rows = cursor.fetchall()
                    for row_pk, token in rows:
                        cursor.execute(
                            f"UPDATE {table} SET {column} = %s WHERE {pk} = %s",  # noqa: S608
                            [crypto.rotate(token), row_pk],
                        )
                total += len(rows)
                self.stdout.write(f"{model._meta.label}.{field.name}: {len(rows)} valor(es)")
        self.stdout.write(
            self.style.SUCCESS(f"Re-cifrados {total} valor(es) con la llave primaria.")
        )

#!/usr/bin/env bash
# Respaldo de Atalaya con el sistema en marcha: base de datos, archivos subidos y resultados
# de escaneo. Guía completa: docs/operacion.md.
#
#   scripts/backup.sh                  # deja el respaldo en backups/<fecha>-<hora>/
#   scripts/backup.sh /mnt/respaldos   # en otra carpeta (crea <fecha>-<hora>/ dentro)
#
# Qué NO incluye, a propósito:
#   - .env: lleva la llave de cifrado y las contraseñas. Guárdalo aparte y en otro lugar que el
#     respaldo: sin ATALAYA_FIELD_ENCRYPTION_KEYS no se pueden leer los tokens de registries.
#   - Plantillas de nuclei, base de Grype (cti_cache) y modelos de Ollama: se vuelven a descargar.
#   - La cola de Redis: al restaurar se vacía y el sistema retoma solo lo que quedó a medias.
#
# Comprobar que un respaldo sirve (no toca nada): scripts/restore.sh --verify <carpeta>
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dest_root="${1:-backups}"
stamp="$(date +%Y%m%d-%H%M%S)"
dest="$dest_root/$stamp"

say() { printf 'atalaya: %s\n' "$*" >&2; }
die() { say "ERROR: $*"; exit 1; }

in_db() { docker compose exec -T db sh -c "$1"; }

# Filas de cada tabla, una por línea: «tabla cuenta».
counts() {
  in_db 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F " "' <<'SQL'
SELECT table_name,
       (xpath('/row/c/text()',
              query_to_xml(format('SELECT count(*) AS c FROM %I', table_name), false, true, '')))[1]
       FROM information_schema.tables
 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
 ORDER BY table_name;
SQL
}

docker compose ps --status running --services 2>/dev/null | grep -qx db \
  || die "la base de datos no está en marcha (levanta el sistema antes de respaldar)"
docker compose ps --status running --services 2>/dev/null | grep -qx backend \
  || die "el servicio backend no está en marcha (hace falta para leer los archivos)"

mkdir -p "$dest"
chmod 700 "$dest"
trap 'say "el respaldo no terminó; carpeta incompleta: $dest"' ERR

say "respaldando en $dest"
# Las cuentas se toman antes y después del volcado: lo restaurado debe quedar entre ambas.
counts > "$dest/.counts-before"
say "base de datos…"
in_db 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=6' \
  > "$dest/atalaya.dump"
counts > "$dest/.counts-after"
join "$dest/.counts-before" "$dest/.counts-after" > "$dest/counts.txt"
rm -f "$dest/.counts-before" "$dest/.counts-after"

say "archivos subidos…"
docker compose exec -T backend tar -C /data -czf - media > "$dest/media.tar.gz"
say "resultados de escaneo…"
docker compose exec -T backend tar -C /data -czf - scan-results > "$dest/scan-results.tar.gz"

(cd "$dest" && sha256sum atalaya.dump media.tar.gz scan-results.tar.gz counts.txt > SHA256SUMS)

{
  echo "fecha: $(date -Iseconds)"
  echo "codigo: $(git rev-parse --short HEAD 2>/dev/null || echo desconocido)"
  echo "postgres: $(in_db 'pg_dump --version')"
  echo "migraciones: $(in_db 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT count(*) FROM django_migrations"')"
  echo "tablas: $(wc -l < "$dest/counts.txt")"
  echo "tamano_base: $(du -h "$dest/atalaya.dump" | cut -f1)"
  echo "tamano_archivos: $(du -h "$dest/media.tar.gz" | cut -f1)"
  echo "tamano_escaneos: $(du -h "$dest/scan-results.tar.gz" | cut -f1)"
} > "$dest/manifest.txt"

trap - ERR
say "listo: $dest ($(du -sh "$dest" | cut -f1))"
say "recuerda: el archivo .env NO va aquí. Sin su llave de cifrado el respaldo no descifra los tokens de registries."
say "comprueba que sirve: scripts/restore.sh --verify $dest"
echo "$dest"

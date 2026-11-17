#!/usr/bin/env bash
# Restaura un respaldo hecho con scripts/backup.sh. Guía completa: docs/operacion.md.
#
#   scripts/restore.sh --verify backups/20261117-164500   # comprueba que sirve; no toca nada
#   scripts/restore.sh backups/20261117-164500            # restaura (pide confirmación)
#   scripts/restore.sh --yes backups/20261117-164500      # sin preguntar
#
# Restaurar hace esto, en orden, y se detiene sin cambiar nada si un paso previo al cambio falla:
#   1. Comprueba las sumas del respaldo.
#   2. Respalda lo que hay ahora en backups/antes-de-restaurar/ (--no-safety-backup lo omite).
#   3. Detiene la aplicación y los trabajadores (la base y Redis siguen en marcha).
#   4. Carga el respaldo en una base nueva y compara las filas de cada tabla con las del respaldo.
#   5. Cambia la base en uso por la nueva; la anterior queda como <base>_antes_<fecha>.
#   6. Reemplaza los archivos subidos y los resultados de escaneo.
#   7. Vacía Redis (la cola hablaba de la base anterior) y vuelve a arrancar todo.
#
# Hace falta el mismo .env con el que se hizo el respaldo (ATALAYA_FIELD_ENCRYPTION_KEYS).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

APP_SERVICES=(backend worker worker-llm worker-discovery beat)

say() { printf 'atalaya: %s\n' "$*" >&2; }
die() { say "ERROR: $*"; exit 1; }

in_db() { docker compose exec -T db sh -c "$1"; }

# sql <base> : ejecuta en esa base lo que llega por la entrada estándar.
sql() {
  docker compose exec -T -e TARGET_DB="$1" -e PGOPTIONS="-c client_min_messages=warning" db sh -c \
    'psql -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$TARGET_DB" -At -F " "'
}

live_database() { in_db 'printf %s "$POSTGRES_DB"'; }

check_files() {
  local dir="$1"
  for f in atalaya.dump media.tar.gz scan-results.tar.gz counts.txt SHA256SUMS; do
    [[ -f "$dir/$f" ]] || die "falta $f en $dir (¿es una carpeta de scripts/backup.sh?)"
  done
  (cd "$dir" && sha256sum --quiet -c SHA256SUMS) || die "las sumas no coinciden: el respaldo está dañado"
  gzip -t "$dir/media.tar.gz" "$dir/scan-results.tar.gz" || die "un archivo comprimido está dañado"
}

drop_database() {
  sql postgres <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$1' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "$1";
SQL
}

# load_into <base> <carpeta> : crea la base y carga el volcado. Falla ante cualquier error.
load_into() {
  drop_database "$1" > /dev/null
  echo "CREATE DATABASE \"$1\";" | sql postgres > /dev/null
  docker compose exec -T -e TARGET_DB="$1" db sh -c \
    'pg_restore --no-owner --exit-on-error -U "$POSTGRES_USER" -d "$TARGET_DB"' < "$2/atalaya.dump"
}

# compare_counts <base> <carpeta> : cada tabla debe tener las filas que tenía al respaldar
# (entre la cuenta de antes y la de después del volcado, que se hizo con el sistema en marcha).
compare_counts() {
  local db="$1" dir="$2" bad=0 table low high got
  local restored
  restored="$(sql "$db" <<'SQL'
SELECT table_name,
       (xpath('/row/c/text()',
              query_to_xml(format('SELECT count(*) AS c FROM %I', table_name), false, true, '')))[1]
       FROM information_schema.tables
 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
 ORDER BY table_name;
SQL
)" || return 1
  # Sin tablas que comparar no hay nada comprobado: eso también es un fallo.
  [[ -n "$restored" && -s "$dir/counts.txt" ]] || { say "  no hay tablas que comparar"; return 1; }
  while read -r table low high; do
    got="$(awk -v t="$table" '$1 == t { print $2 }' <<< "$restored")"
    if [[ -z "$got" ]]; then
      say "  falta la tabla $table"; bad=1
    elif (( got < (low < high ? low : high) || got > (low > high ? low : high) )); then
      say "  $table: $got filas; el respaldo tenía $low"; bad=1
    fi
  done < "$dir/counts.txt"
  (( bad == 0 )) || return 1
  say "  $(wc -l < "$dir/counts.txt") tablas, $(awk '{ s += $2 } END { print s }' <<< "$restored") filas: coinciden con el respaldo"
}

# swap_database <en uso> <nueva> <nombre para la anterior>
swap_database() {
  sql postgres <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
 WHERE datname IN ('$1', '$2') AND pid <> pg_backend_pid();
ALTER DATABASE "$1" RENAME TO "$3";
ALTER DATABASE "$2" RENAME TO "$1";
SQL
}

# restore_files <carpeta> [raíz] : deja los volúmenes exactamente como estaban en el respaldo.
# Usa los volúmenes y la imagen del contenedor backend (que ya está detenido), sin reconstruir
# nada. La raíz es /data; los ensayos pasan otra para no tocar los archivos reales.
restore_files() {
  local name root="${2:-/data}" container image
  container="$(docker compose ps -a -q backend | head -1)"
  [[ -n "$container" ]] || die "no existe el contenedor backend (levanta el sistema una vez antes de restaurar)"
  image="$(docker inspect --format '{{.Config.Image}}' "$container")"
  for name in media scan-results; do
    docker run --rm -i --volumes-from "$container" -e NAME="$name" -e ROOT="$root" "$image" sh -c \
      'mkdir -p "$ROOT/$NAME" && find "$ROOT/$NAME" -mindepth 1 -delete && tar -C "$ROOT" -xzf -' \
      < "$1/$name.tar.gz"
  done
}

verify() {
  local dir="$1" live scratch
  check_files "$dir"
  say "sumas correctas; cargando el respaldo en una base aparte (no se toca la que está en uso)…"
  live="$(live_database)"
  scratch="${live}_verificacion"
  trap 'drop_database "$scratch" > /dev/null 2>&1 || true' EXIT
  load_into "$scratch" "$dir"
  compare_counts "$scratch" "$dir" || die "el respaldo se carga, pero no tiene las filas que debería"
  say "archivos: $(tar -tzf "$dir/media.tar.gz" | wc -l) entradas subidas, $(tar -tzf "$dir/scan-results.tar.gz" | wc -l) de escaneos"
  drop_database "$scratch" > /dev/null
  trap - EXIT
  say "el respaldo sirve: $dir ($(grep '^fecha:' "$dir/manifest.txt" 2>/dev/null || echo 'sin manifiesto'))"
}

restore() {
  local dir="$1" assume_yes="$2" safety="$3" live fresh stamp previous answer
  check_files "$dir"
  live="$(live_database)"
  stamp="$(date +%Y%m%d_%H%M%S)"
  fresh="${live}_restaurada"
  previous="${live}_antes_${stamp}"
  say "se va a reemplazar la base «$live», los archivos subidos y los resultados de escaneo"
  say "por el respaldo $dir ($(grep '^fecha:' "$dir/manifest.txt" 2>/dev/null || echo 'sin manifiesto'))."
  if [[ "$assume_yes" != 1 ]]; then
    read -r -p "Escribe RESTAURAR para continuar: " answer
    [[ "$answer" == "RESTAURAR" ]] || die "cancelado; no se cambió nada"
  fi
  if [[ "$safety" == 1 ]]; then
    say "respaldo de lo que hay ahora…"
    scripts/backup.sh "backups/antes-de-restaurar" > /dev/null
  fi
  say "deteniendo la aplicación y los trabajadores…"
  docker compose stop "${APP_SERVICES[@]}" > /dev/null
  say "cargando el respaldo en una base nueva…"
  if ! load_into "$fresh" "$dir" || ! compare_counts "$fresh" "$dir"; then
    drop_database "$fresh" > /dev/null 2>&1 || true
    docker compose start "${APP_SERVICES[@]}" > /dev/null
    die "el respaldo no se pudo cargar completo; no se cambió nada y el sistema volvió a arrancar"
  fi
  say "cambiando la base en uso…"
  swap_database "$live" "$fresh" "$previous"
  say "reemplazando archivos…"
  restore_files "$dir"
  say "vaciando la cola y la caché…"
  docker compose exec -T redis redis-cli FLUSHALL > /dev/null
  say "arrancando…"
  docker compose start "${APP_SERVICES[@]}" > /dev/null
  say "restaurado. La base anterior quedó como «$previous»; cuando confirmes que todo está bien:"
  say "  docker compose exec db sh -c 'dropdb -U \"\$POSTGRES_USER\" $previous'"
  say "Lo que estaba en cola al respaldar se retoma solo en unos minutos (Administración › Sistema)."
}

main() {
  local mode=restore assume_yes=0 safety=1 dir=""
  while (( $# )); do
    case "$1" in
      --verify) mode=verify ;;
      --yes) assume_yes=1 ;;
      --no-safety-backup) safety=0 ;;
      -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
      -*) die "opción desconocida: $1" ;;
      *) dir="$1" ;;
    esac
    shift
  done
  [[ -n "$dir" && -d "$dir" ]] || die "indica la carpeta del respaldo (scripts/restore.sh --help)"
  docker compose ps --status running --services 2>/dev/null | grep -qx db \
    || die "la base de datos no está en marcha (levanta el sistema antes de restaurar)"
  if [[ "$mode" == verify ]]; then verify "$dir"; else restore "$dir" "$assume_yes" "$safety"; fi
}

# Permite cargar las funciones sin ejecutar nada (pruebas): ATALAYA_RESTORE_LIB=1 source …
[[ "${ATALAYA_RESTORE_LIB:-0}" == 1 ]] || main "$@"

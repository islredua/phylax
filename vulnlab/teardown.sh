#!/usr/bin/env bash
# Baja vulnlab y purga sus volúmenes nombrados (wp_db_data, pg_old_data).
# Pide confirmación: esto borra físicamente los datos de las bases de datos
# del laboratorio (no hay nada que "retirar" aquí, es un laboratorio).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "Esto va a:"
echo "  - detener y eliminar todos los contenedores de vulnlab"
echo "  - eliminar los volúmenes nombrados (wp_db_data, pg_old_data)"
echo
read -r -p "¿Continuar? [s/N] " answer
case "$answer" in
  [sS]|[sS][iI]) ;;
  *) echo "Cancelado."; exit 0 ;;
esac

docker compose down --volumes --remove-orphans
echo "vulnlab eliminado (contenedores y volúmenes)."

#!/usr/bin/env bash
# Verifica, desde dentro de Host B, que cada puerto publicado de vulnlab responde.
# No usa Phylax ni nmap: solo nc -zv contra localhost, para confirmar que el
# stack local está arriba antes de escanearlo desde Host A.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

declare -A PORTS=(
  [dvwa]=8080
  [juice-shop]=3000
  [wp-old]=8081
  [ssh-old]=2222
  [ftp-old]=2121
  [samba-old-139]=1139
  [samba-old-445]=1445
  [pg-old]=5433
  [mongo-noauth]=27018
)

failures=0
for name in "${!PORTS[@]}"; do
  port="${PORTS[$name]}"
  if nc -z -w 3 127.0.0.1 "$port" 2>/dev/null; then
    echo "OK   ${name} (puerto ${port})"
  else
    echo "FAIL ${name} (puerto ${port}) no responde"
    failures=$((failures + 1))
  fi
done

if [[ "$failures" -gt 0 ]]; then
  echo
  echo "${failures} servicio(s) no responden. Revisa 'docker compose ps' y" >&2
  echo "'docker compose logs <servicio>'." >&2
  exit 1
fi

echo
echo "Todos los servicios con puerto publicado responden."

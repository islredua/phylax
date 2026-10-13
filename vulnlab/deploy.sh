#!/usr/bin/env bash
# Despliega vulnlab en Host B. NO ejecutar en el host de Phylax.
#
# No se corre nunca automáticamente (CI, un agente, etc.): es responsabilidad
# del operador humano en Host B, bajo su propio criterio de seguridad. Ver
# "Despliegue manual requerido" en README.md.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

MIN_DOCKER_MAJOR=24

echo "== vulnlab: verificaciones previas =="

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker no está instalado en este host." >&2
  exit 1
fi

docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
if [[ -z "$docker_version" ]]; then
  echo "ERROR: no se pudo contactar al daemon de Docker. ¿Está corriendo?" >&2
  exit 1
fi
docker_major="${docker_version%%.*}"
if [[ "$docker_major" -lt "$MIN_DOCKER_MAJOR" ]]; then
  echo "ERROR: Docker $docker_version detectado; se requiere >= ${MIN_DOCKER_MAJOR}.x" >&2
  exit 1
fi
echo "Docker $docker_version: OK"

if [[ ! -f .env ]]; then
  echo "ERROR: falta .env (copia .env.example a .env y ajústalo)." >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
source .env
set +a

echo "== vulnlab: verificando que los puertos no estén ya en uso en este host =="
declare -a PORTS=(8080 3000 8081 2222 2121 1139 1445 5433 27018)
any_in_use=0
for port in "${PORTS[@]}"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
    echo "AVISO: el puerto ${port} ya está en uso en este host." >&2
    exec 3>&- 3<&- 2>/dev/null || true
    any_in_use=1
  fi
done
if [[ "$any_in_use" -eq 1 ]]; then
  echo "ERROR: al menos un puerto del laboratorio ya está ocupado. Libéralo o" >&2
  echo "       edita docker-compose.yml antes de continuar." >&2
  exit 1
fi
echo "Puertos libres: OK"

lan_ip="$(ip -4 route get 1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')"
echo "== vulnlab: IP de Host B en la LAN del laboratorio =="
echo "    ${lan_ip:-<no detectada automáticamente; revisa `ip addr`>}"
echo "    Anota esta IP: es la que debes usar como VULNLAB_HOST en Phylax (Host A)."

echo "== vulnlab: levantando el stack =="
if ! docker compose up -d; then
  echo "ERROR: 'docker compose up' falló. Si Host B no tiene salida a internet" >&2
  echo "       (despliegue air-gapped), precarga las imágenes de docker-compose.yml" >&2
  echo "       con 'docker load' desde un host con acceso y vuelve a intentar." >&2
  exit 1
fi

echo "== vulnlab: verificando que los servicios respondan =="
./verify.sh

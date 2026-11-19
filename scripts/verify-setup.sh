#!/usr/bin/env bash
# Comprueba que el entorno está en pie: Docker, servicios, salud de la aplicación y modelo.
# Sirve para los dos perfiles (desarrollo y producción). Guía: docs/operacion.md.
#
#   scripts/verify-setup.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail=0
ok()   { printf '  OK     %s\n' "$*"; }
warn() { printf '  AVISO  %s\n' "$*"; }
bad()  { printf '  FALLA  %s\n' "$*"; fail=1; }

echo "=== Verificación del entorno de Atalaya ==="

echo "[1/5] Docker"
if docker --version > /dev/null 2>&1; then ok "$(docker --version)"; else bad "docker no está instalado o no es accesible"; fi
if docker compose version > /dev/null 2>&1; then ok "$(docker compose version)"; else bad "falta el plugin docker compose"; fi

echo "[2/5] Servicios"
running="$(docker compose ps --status running --services 2>/dev/null)"
for service in db redis ollama backend worker worker-llm worker-discovery beat; do
  if grep -qx "$service" <<< "$running"; then ok "$service"; else bad "$service no está en marcha (scripts/compose.sh up -d)"; fi
done
profile=desarrollo
if grep -qx proxy <<< "$running"; then profile=producción; ok "proxy (perfil de producción)"; fi

echo "[3/5] Salud de la aplicación (perfil de $profile)"
if docker compose exec -T backend curl -fsS http://localhost:8000/health/ > /dev/null 2>&1; then
  ok "$(docker compose exec -T backend curl -fsS http://localhost:8000/health/)"
else
  bad "/health/ no responde dentro del contenedor backend (docker compose logs --tail 50 backend)"
fi

echo "[4/5] Colas"
for queue in default llm discovery; do
  waiting="$(docker compose exec -T redis redis-cli llen "$queue" 2>/dev/null | tr -d '\r')"
  if [[ "$waiting" =~ ^[0-9]+$ ]]; then ok "$queue: $waiting en espera"; else bad "Redis no responde"; break; fi
done
if docker compose exec -T redis redis-cli config get appendonly 2>/dev/null | grep -qx yes; then
  ok "Redis guarda la cola en disco"
else
  warn "Redis no guarda la cola en disco: un reinicio pierde lo encolado"
fi

echo "[5/5] Modelo local (Ollama)"
models="$(docker compose exec -T ollama ollama list 2>/dev/null | tail -n +2 | awk '{print $1}')"
if [[ -n "$models" ]]; then
  while read -r model; do ok "$model"; done <<< "$models"
else
  warn "no hay modelos descargados: scripts/compose.sh exec ollama ollama pull <modelo> (o LLM_MOCK_MODE=1)"
fi

echo
if (( fail )); then echo "=== Hay fallas: revisa las líneas marcadas ==="; exit 1; fi
echo "=== Todo en pie. Detalle en Administración › Sistema ==="

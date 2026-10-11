#!/usr/bin/env bash
# Script de verificación del entorno. Correr desde la raíz del repo tras levantar
# docker compose, idealmente desde WSL2.

set -euo pipefail

echo "=== Verificación del entorno RBVM ==="
echo

# 1. Docker
echo "[1/5] Docker..."
if ! docker --version > /dev/null; then
    echo "  ERROR: docker no está instalado o no accesible"; exit 1
fi
docker --version
echo "  OK"
echo

# 2. Docker Compose
echo "[2/5] Docker Compose..."
if ! docker compose version > /dev/null; then
    echo "  ERROR: docker compose plugin no está instalado"; exit 1
fi
docker compose version
echo "  OK"
echo

# 3. Servicios levantados
echo "[3/5] Servicios RBVM..."
if ! docker compose ps --format json | grep -q rbvm-backend; then
    echo "  AVISO: backend no está corriendo. Ejecuta: docker compose up -d"
else
    echo "  Backend: UP"
fi
if ! docker compose ps --format json | grep -q rbvm-db; then
    echo "  AVISO: db no está corriendo"
else
    echo "  DB: UP"
fi
echo

# 4. Backend health
echo "[4/5] Backend health..."
if curl -s -f http://localhost:8000/health/ > /dev/null; then
    echo "  OK: $(curl -s http://localhost:8000/health/)"
else
    echo "  ERROR: /health/ no responde"
fi
echo

# 5. Ollama (en host)
echo "[5/5] Ollama (host)..."
# Desde WSL2 el host es accesible como localhost si Ollama escucha en todas las ifaces,
# o vía la IP del host. En Windows nativo es solo localhost.
OLLAMA_URL="${OLLAMA_BASE_URL:-http://host.docker.internal:11434}"
# Para probar desde WSL2 shell usa localhost:
if curl -s -f http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "  OK: Ollama responde en localhost:11434"
    echo "  Modelos descargados:"
    curl -s http://localhost:11434/api/tags | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'    - {m[\"name\"]}') for m in d.get('models',[])]"
else
    echo "  AVISO: Ollama no responde en localhost. Verifica que esté corriendo en Windows."
fi
echo
echo "=== Verificación completa ==="

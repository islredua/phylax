#!/usr/bin/env bash
# Envoltura de `docker compose` que se adapta al hardware:
# si hay GPU NVIDIA utilizable por Docker añade docker-compose.gpu.yml; si no, Ollama usa CPU.
#
#   scripts/compose.sh up -d
#   scripts/compose.sh exec ollama ollama pull qwen2.5:7b-instruct-q4_K_M
#   PHYLAX_GPU=0 scripts/compose.sh up -d   # forzar CPU
#   PHYLAX_GPU=1 scripts/compose.sh up -d   # forzar GPU
set -euo pipefail
cd "$(dirname "$0")/.."

files=(-f docker-compose.yml)
gpu="${PHYLAX_GPU:-auto}"
if [[ "$gpu" == "auto" ]]; then
  if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
    gpu=1
  elif docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
    gpu=1
  else
    gpu=0
  fi
fi
if [[ "$gpu" == "1" ]]; then
  files+=(-f docker-compose.gpu.yml)
  echo "phylax: GPU NVIDIA detectada → Ollama con GPU" >&2
else
  echo "phylax: sin GPU → Ollama en CPU (inferencias más lentas, se ejecutan en segundo plano)" >&2
fi
exec docker compose "${files[@]}" "$@"

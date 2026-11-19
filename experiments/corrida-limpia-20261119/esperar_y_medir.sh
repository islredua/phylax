#!/bin/bash
# Deja la corrida programada: espera a las 21:28, comprueba que el modelo responde en GPU
# (si va lento reinicia solo el contenedor de Ollama y vuelve a medir) y arranca medir.sh,
# que da de alta el laboratorio a las 22:00:30. Corre suelto (nohup setsid), sin sesión.
cd /home/emaceda/projects/phylax || exit 1
D=experiments/corrida-limpia-20261119
LOG=$D/previo.log
say() { echo "$(date '+%F %T') $*" >> $LOG; }
say "en espera hasta las 21:28"
while [ "$(date +%H%M)" \< "2128" ]; do sleep 30; done
speed() {
  docker compose exec -T backend python - <<'PY' 2>/dev/null
import json, time, urllib.request
body = json.dumps({"model": "qwen2.5:7b-instruct-q4_K_M", "prompt": "Explica en un párrafo qué es una vulnerabilidad de software.", "stream": False, "options": {"num_predict": 160, "temperature": 0}}).encode()
try:
    r = json.load(urllib.request.urlopen(urllib.request.Request("http://ollama:11434/api/generate", body, {"Content-Type": "application/json"}), timeout=240))
    print(round(r["eval_count"] / (r["eval_duration"] / 1e9), 1))
except Exception:
    print(0)
PY
}
tps=$(speed | tail -1); say "modelo: ${tps:-0} tokens/s"
if [ "$(printf '%.0f' "${tps:-0}")" -lt 25 ]; then
  say "va lento: se reinicia el contenedor de Ollama"
  docker compose --progress quiet restart ollama >> $LOG 2>&1; sleep 40
  tps=$(speed | tail -1); say "modelo tras reiniciar: ${tps:-0} tokens/s"
fi
echo "${tps:-0}" > $D/tokens_por_s_previo.txt
for q in llm default discovery; do say "cola $q: $(docker exec atalaya-redis redis-cli llen $q 2>/dev/null | tr -d '\r')"; done
say "contenedores en marcha: $(docker ps --format '{{.Names}}' | grep -c .)"
exec bash $D/medir.sh 220030

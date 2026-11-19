"""Arma condiciones.json: lo que dice la plataforma (condiciones.py, por manage.py shell) más el
equipo, Ollama y el código. Solo lee.
Uso: python3 armar_condiciones.py <respaldo> <tablas> <filas> [<cómo y cuándo arranca>]
"""
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

here = Path(__file__).resolve().parent
repo = here.parents[1]


def sh(cmd):
    return subprocess.run(cmd, shell=True, cwd=repo, capture_output=True, text=True).stdout.strip()


shell = "docker compose exec -T backend python manage.py shell"
app = json.loads(sh(f"{shell} < {here / 'condiciones.py'} | grep '^COND' | cut -c5-"))
gpu = sh("nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader")
out = {
    "corrida": "segunda corrida limpia del laboratorio Aseguradora Norte",
    "preparada": datetime.now().astimezone().isoformat(timespec="seconds"),
    "codigo": {
        "commit": sh("git rev-parse --short HEAD"),
        "rama": sh("git rev-parse --abbrev-ref HEAD"),
        "arbol_limpio": not sh("git status --porcelain -- backend frontend"),
    },
    "respaldo_previo": sys.argv[1],
    "limpieza": {
        "tablas_vaciadas": int(sys.argv[2]),
        "filas_borradas": int(sys.argv[3]),
        "se_conservo": [
            "cuentas y sesiones",
            "configuración (automatización, tratamiento, Inicio, retención)",
            "perfil de la organización",
            "catálogos",
            "espejo de inteligencia (NVD, EPSS, KEV) y su historial",
            "historial de actualizaciones de los escáneres",
        ],
    },
    "equipo": {
        "cpu": sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"),
        "hilos": int(sh("nproc")),
        "ram_visible_mib": int(sh("awk '/MemTotal/{print int($2/1024)}' /proc/meminfo")),
        "gpu": gpu,
        "sistema": sh("uname -r"),
        "docker": sh("docker version --format '{{.Server.Version}}'"),
    },
    "ollama": {
        "version": sh("docker exec atalaya-ollama ollama --version"),
        "modelos": sh("docker exec atalaya-ollama ollama list | tail -n +2 | awk '{print $1, $2}'").splitlines(),
        "num_parallel": sh("docker exec atalaya-ollama printenv OLLAMA_NUM_PARALLEL"),
        "keep_alive": sh("docker exec atalaya-ollama printenv OLLAMA_KEEP_ALIVE"),
    },
    "nuclei": {
        "motor": sh("docker exec atalaya-worker-discovery /usr/local/bin/nuclei -version 2>&1 | grep -o 'v[0-9.]*' | head -1"),
        "plantillas": sh("docker exec atalaya-worker-discovery cat /data/cti-cache/nuclei-templates/.atalaya-version"),
    },
    "workers": {"default": 2, "llm": 1, "discovery": 1},
    "laboratorio": {
        "contenedores": int(sh("docker ps --format '{{.Names}}' | grep -vc '^atalaya-'")),
        "inventario": "datasets/lab-inventario-hosts.csv",
        "esperado": "datasets/lab-expected-results.csv",
    },
    "plataforma": app,
    "arranque_previsto": sys.argv[4] if len(sys.argv) > 4 else "",
}
(here / "condiciones.json").write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
print("condiciones.json escrito:", len(out["plataforma"]), "claves de plataforma")

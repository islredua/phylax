"""Resume las muestras de recursos de la corrida: reposo (antes de T0) frente a la corrida.
Uso: python3 recursos.py <T0 iso> <fin iso>  → imprime JSON."""
import csv
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

here = Path(__file__).parent
t0 = datetime.fromisoformat(sys.argv[1]).replace(tzinfo=None)
end = datetime.fromisoformat(sys.argv[2]).replace(tzinfo=None)


def when(text):
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")


def mib(text):
    value = text.split("/")[0].strip()
    for unit, factor in (("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024), ("B", 1 / 1048576)):
        if value.endswith(unit):
            return float(value[: -len(unit)]) * factor
    return 0.0


def num(text):
    try:
        return float(text)
    except ValueError:
        return None


def stats(values, digits=1):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return {"media": round(statistics.mean(values), digits), "max": round(max(values), digits)}


phases = {"reposo": lambda t: t < t0, "corrida": lambda t: t0 <= t <= end}
gpu = defaultdict(lambda: defaultdict(list))
with open(here / "gpu_equipo.csv") as handle:
    for row in csv.DictReader(handle):
        t = when(row["ts"])
        for name, inside in phases.items():
            if inside(t):
                for key in ("gpu_util_pct", "vram_mib", "gpu_temp_c", "gpu_w", "carga_1min", "ram_disponible_mib"):
                    gpu[name][key].append(num(row[key]))
containers = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
lab = defaultdict(lambda: defaultdict(lambda: [0.0, 0.0]))
with open(here / "contenedores.csv") as handle:
    for row in csv.DictReader(handle):
        t = when(row["ts"])
        cpu, mem = num(row["cpu_pct"].rstrip("%")), mib(row["memoria"])
        for name, inside in phases.items():
            if not inside(t):
                continue
            if row["contenedor"].startswith("atalaya-"):
                containers[name][row["contenedor"]]["cpu_pct"].append(cpu)
                containers[name][row["contenedor"]]["memoria_mib"].append(mem)
            else:
                lab[name][row["ts"]][0] += cpu or 0
                lab[name][row["ts"]][1] += mem
out = {}
for name in phases:
    g = gpu[name]
    out[name] = {
        "muestras": len(g["vram_mib"]),
        "gpu_uso_pct": stats(g["gpu_util_pct"]),
        "vram_mib": stats(g["vram_mib"], 0),
        "gpu_temperatura_c": stats(g["gpu_temp_c"], 0),
        "gpu_potencia_w": stats(g["gpu_w"]),
        "carga_del_equipo_1min": stats(g["carga_1min"], 2),
        "ram_disponible_mib_min": min((v for v in g["ram_disponible_mib"] if v is not None), default=None),
        "contenedores": {
            c: {"cpu_pct": stats(v["cpu_pct"]), "memoria_mib": stats(v["memoria_mib"], 0)}
            for c, v in sorted(containers[name].items())
        },
        "laboratorio_en_conjunto": {
            "cpu_pct": stats([v[0] for v in lab[name].values()]),
            "memoria_mib": stats([v[1] for v in lab[name].values()], 0),
        },
    }
print(json.dumps(out, ensure_ascii=False, indent=2))

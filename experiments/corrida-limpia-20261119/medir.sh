#!/bin/bash
# Corrida limpia del laboratorio: mide recursos cada 20 s y avance cada 60 s, da de alta el
# laboratorio a la hora indicada y termina cuando la plataforma se asienta.
#   medir.sh <HHMMSS de arranque>
# Se asienta = colas vacías, nada en curso ni pendiente, todos los activos con criticidad y
# 15 minutos seguidos sin inferencias nuevas (sin contar el resumen ejecutivo de Inicio).
# Al asentarse deja también, solo leyendo la base: lab-eval.json, resultado.json y recursos.json.
cd /home/emaceda/projects/phylax || exit 1
D=experiments/corrida-limpia-20261119
START=${1:-220030}
QUIET_MIN=15; MIN_AFTER_T0=1500; MAX_SECONDS=27000
GPU=$D/gpu_equipo.csv; CONT=$D/contenedores.csv; PROG=$D/progreso.csv; LOG=$D/medicion.log
echo "ts,gpu_util_pct,vram_mib,gpu_temp_c,gpu_w,carga_1min,ram_disponible_mib" > $GPU
echo "ts,contenedor,cpu_pct,memoria" > $CONT
echo "ts,cola_llm,cola_default,cola_discovery,activos,activos_con_criticidad,descubrimientos_en_curso,descubrimientos_listos,escaneos_en_curso,escaneos_listos,escaneos_fallidos,senales_pendientes,decisiones,acciones_abiertas,acciones_por_revisar,observaciones,vulnerabilidades,vulnerabilidades_descritas,riesgos_abiertos,riesgos,inferencias,inferencias_sin_resumen" > $PROG
say() { echo "$(date '+%F %T') $*" >> $LOG; }
say "medición iniciada; el laboratorio se da de alta a las $START"
began=$(date +%s); launched=0; t0=0; i=0; quiet=0; last_inf=-1
while :; do
  loop=$(date +%s); ts=$(date '+%F %T')
  g=$(nvidia-smi --query-gpu=utilization.gpu,memory.used,temperature.gpu,power.draw --format=csv,noheader,nounits 2>/dev/null | head -1 | tr -d ' ')
  echo "$ts,${g:-,,,},$(cut -d' ' -f1 /proc/loadavg),$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)" >> $GPU
  docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}}' 2>/dev/null | sed "s/^/$ts,/" >> $CONT
  if [ $launched = 0 ] && [ "$(date +%H%M%S)" \> "$START" ]; then
    launched=1; t0=$(date +%s); date -Iseconds > $D/t0.txt
    say "T0: alta del laboratorio (lab_import --user emaceda)"
    ( docker compose exec -T backend python manage.py lab_import --user emaceda > $D/lanzamiento.log 2>&1; echo "salida=$? fin=$(date -Iseconds)" >> $D/lanzamiento.log ) &
  fi
  if [ $((i % 3)) = 0 ]; then
    ql=$(docker exec atalaya-redis redis-cli llen llm 2>/dev/null | tr -d '\r'); qd=$(docker exec atalaya-redis redis-cli llen default 2>/dev/null | tr -d '\r'); qx=$(docker exec atalaya-redis redis-cli llen discovery 2>/dev/null | tr -d '\r')
    row=$(docker exec -i atalaya-db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -F,' < $D/progreso.sql 2>/dev/null | head -1)
    echo "$ts,$ql,$qd,$qx,$row" >> $PROG
    if [ $launched = 1 ] && [ -n "$row" ]; then
      IFS=, read -r assets crit drun ddone trun tdone tfail evp dec aopen areview obs vul vdesc ropen rtot inf infc <<< "$row"
      if [ "$infc" = "$last_inf" ]; then quiet=$((quiet + 1)); else quiet=0; last_inf=$infc; fi
      now=$(date +%s)
      if [ $((now - t0)) -ge $MIN_AFTER_T0 ] && [ "$ql$qd$qx" = "000" ] && [ "$drun$trun$evp$aopen" = "0000" ] \
         && [ "$assets" -gt 0 ] && [ "$assets" = "$crit" ] && [ "$vul" -gt 0 ] && [ $quiet -ge $QUIET_MIN ]; then
        say "asentada: $quiet min sin inferencias nuevas; activos=$assets vulnerabilidades=$vul riesgos=$rtot inferencias=$inf"
        echo "asentada $(date -Iseconds) minutos_en_calma=$quiet" > $D/fin.txt; break
      fi
    fi
  fi
  if [ $(( $(date +%s) - began )) -ge $MAX_SECONDS ]; then
    say "tiempo máximo alcanzado sin asentarse"; echo "tiempo_maximo $(date -Iseconds)" > $D/fin.txt; break
  fi
  i=$((i + 1)); rest=$((20 - ($(date +%s) - loop))); [ $rest -gt 0 ] && sleep $rest
done
say "medición terminada"
if [ $launched = 1 ]; then
  docker compose exec -T backend python manage.py evaluate_lab --out /experiments/$(basename $D)/lab-eval.json > $D/evaluacion.log 2>&1
  say "evaluate_lab: salida $?"
  (echo "T0 = \"$(cat $D/t0.txt)\""; cat $D/resultado.py) | docker compose exec -T backend python manage.py shell 2> $D/resultado.err | grep "^RES" | cut -c4- | python3 -m json.tool --no-ensure-ascii > $D/resultado.json
  say "resultado.json: $(wc -c < $D/resultado.json) bytes"
  fin=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fin_de_actividad"])' $D/resultado.json 2>/dev/null)
  [ -n "$fin" ] && python3 $D/recursos.py "$(cat $D/t0.txt)" "$fin" > $D/recursos.json 2>> $D/resultado.err
  say "recursos.json: $(wc -c < $D/recursos.json 2>/dev/null) bytes (fin de actividad $fin)"
  echo "listo $(date -Iseconds)" >> $D/fin.txt
fi

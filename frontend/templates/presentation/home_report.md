{% autoescape off %}# Estado de la organización · {{ profile.name|default:"Organización" }} · {{ generated_at|fecha_larga }}

**Estado:** {{ health_label }} · **Ventana:** {{ data.window_days }} días · Generado por Atalaya el {{ generated_at|fecha }} para {{ generated_by.get_full_name|default:generated_by.get_username }}

## Qué hay que decidir
{% for item in today %}
- **{{ item.count|miles }}** {{ item.text }} — {{ item.action|default:item.view|lower }}{% empty %}
Nada espera una decisión humana: sin riesgos críticos, plazos vencidos ni aprobaciones pendientes.{% endfor %}

## Resumen

**{{ headline|default:narrative.headline|plain }}**

{{ narrative.summary|plain }}

- **Qué cambió:** {{ narrative.changes|default:"—"|plain }}
- **Qué urge:** {{ narrative.urgent|default:"—"|plain }}
{% if narrative.next_steps %}
Siguientes pasos:
{% for s in narrative.next_steps %}
{{ forloop.counter }}. {{ s|plain }}{% endfor %}
{% endif %}
*{% if narrative.by_rule %}Resumen por regla (sin IA){% else %}Resumen por IA ({{ narrative.model }}){% endif %}, {{ narrative.created_at|fecha }}.*{% if narrative_changes %} Desde entonces cambió: {% for c in narrative_changes %}{{ c.label }} {{ c.before }} → {{ c.now }}{% if not forloop.last %}; {% endif %}{% endfor %}; el titular y los indicadores llevan las cifras de ahora.{% endif %}

## Indicadores

| Indicador | Valor | Detalle |
|---|---|---|
| Riesgos abiertos | {{ data.risks.open }} | {{ data.risks.critical }} críticos · {{ data.risks.very_high }} muy altos · {{ data.risks.high }} altos · {{ data.risks.untreated }} sin tratamiento |
| Vulnerabilidades sostenidas | {{ data.vulnerabilities.sustained }} | {{ data.vulnerabilities.confirmed }} confirmadas · {{ data.vulnerabilities.needs_verification }} por verificar |
| Explotación activa (KEV) | {{ data.vulnerabilities.in_kev }} | {{ data.vulnerabilities.kev_overdue }} con plazo CISA vencido |
| Activos | {{ data.assets.total }} | {{ data.assets.with_criticality }} con criticidad · {{ data.assets.scanned_window }} escaneados en la ventana |
| Acciones por aprobar | {{ data.actions.pending_approval }} | {{ data.actions.done_window }} ejecutadas en la ventana |
| Reportes de evidencia | {{ data.observations.total }} | {{ data.observations.multi_source }} con más de una fuente |
{% if deltas.available %}
Frente al {{ deltas.since|fecha_corta }}: {% if deltas.risks_comparable %}riesgos abiertos {{ deltas.risks_open|stringformat:"+d" }}, críticos {{ deltas.risks_critical|stringformat:"+d" }}, {% endif %}vulnerabilidades sostenidas {{ deltas.vulns_sustained|stringformat:"+d" }}, en KEV {{ deltas.vulns_kev|stringformat:"+d" }}.{% if not deltas.risks_comparable %} Los riesgos no se comparan con los de esa fecha: entonces se contaba el riesgo de cada activo y ahora el de la organización.{% endif %}
{% endif %}
## Riesgos principales

Un riesgo es una consecuencia sobre una función de negocio; reúne un escenario por activo y toma el nivel del peor.

| Riesgo | Activos | Peor escenario | P × I | Nivel | Tratamiento |
|---|---|---|---|---|---|
{% for r in top_business %}| {{ r.title }} | {{ r.assets|length }} | {{ r.worst.asset.name }} | {{ r.likelihood }} × {{ r.impact }} | {{ r.level_label }} | {{ r.treatments }} |
{% endfor %}
## Escenarios que más pesan

| Escenario | Activo | P × I | Nivel | Inteligencia | Tratamiento |
|---|---|---|---|---|---|
{% for r in top_risks %}| {{ r.title }} | {{ r.asset.name }} | {{ r.likelihood }} × {{ r.impact }} | {{ r.get_level_display }} | {{ r.intelligence_summary|default:"—"|plain }} | {% if r.treatment %}{{ r.get_treatment_display }}{% else %}sin decidir{% endif %} |
{% endfor %}
## Cómo trabajó la detección

Las etapas no van en fila: las señales y el inventario entran por separado, y un escaneo lo pide el planificador, una persona o el calendario. El periodo dice si la cifra cuenta los últimos {{ data.window_days }} días o lo vigente hoy.

| Etapa | Cifra | Quién actúa | Detalle | Le llega de | Periodo |
|---|---:|---|---|---|---|
{% for st in hero.flow %}| {{ st.label }} | {{ st.value }} | {{ st.actor }} | {{ st.sub }}{% if st.ai %}. IA: {{ st.ai }}{% endif %} | {{ st.origin|default:"—" }} | {{ st.scope }} |
{% endfor %}
- De {{ data.pipeline.signals.total }} señales, {{ data.pipeline.match.filtered }} ({{ data.pipeline.match.filtered_pct|floatformat:1 }} %) se descartaron por regla al no tocar el inventario; {{ data.pipeline.match.reconciled }} se resolvieron sin escanear.
- {{ data.pipeline.observations.intel_only_pct|floatformat:0 }} % de los reportes se encontró cruzando inteligencia con inventario, sin tocar el activo; {{ data.pipeline.observations.multi_source }} las confirmaron dos fuentes a la vez.
- IA local ({{ data.pipeline.ai.model }}{% if data.pipeline.ai.local %}, en este equipo{% endif %}): {{ data.pipeline.ai.calls }} inferencias de decisión, valoración y redacción de riesgos (sin contar la redacción de explicaciones ni la lectura del estado), {{ data.pipeline.ai.ok_pct|floatformat:0 }} % aceptadas por el validador, {{ data.pipeline.ai.hours }} h de cómputo.
- {{ data.automation.vulns_consolidated_window }} vulnerabilidades valoradas, {{ data.automation.vulns_described_window }} descripciones redactadas y {{ data.automation.risks_assessed_window }} riesgos valorados conforme a ISO/IEC 27005; {{ data.automation.cti_syncs_window }} sincronizaciones de inteligencia.

## Avisos vigentes
{% for a in alerts %}
- **{% if a.level == 'critical' %}Crítico{% elif a.level == 'high' %}Alto{% elif a.level == 'medium' %}Medio{% else %}Info{% endif %}** · {{ a.text }}{% empty %}
Sin avisos.{% endfor %}

---
Las valoraciones «por IA» las produjo un modelo local y pueden corregirse en la plataforma; el tratamiento lo decide siempre una persona.
{% endautoescape %}

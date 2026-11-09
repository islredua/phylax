{% autoescape off %}# Estado de la organización · {{ profile.name|default:"Organización" }} · {{ generated_at|fecha_larga }}

**Estado:** {{ narrative.get_status_display }} · **Ventana:** {{ data.window_days }} días · Generado por Atalaya el {{ generated_at|fecha }} para {{ generated_by.get_full_name|default:generated_by.get_username }}

## Qué hay que decidir
{% for item in today %}
- **{{ item.count|miles }}** {{ item.text }} — {{ item.action|lower }}{% empty %}
Nada espera una decisión humana: sin riesgos críticos, plazos vencidos ni aprobaciones pendientes.{% endfor %}

## Resumen

**{{ narrative.headline|plain }}**

{{ narrative.summary|plain }}

- **Qué cambió:** {{ narrative.changes|default:"—"|plain }}
- **Qué urge:** {{ narrative.urgent|default:"—"|plain }}
- **Qué hizo el sistema:** {{ narrative.achievements|default:"—"|plain }}
{% if narrative.next_steps %}
Siguientes pasos:
{% for s in narrative.next_steps %}
{{ forloop.counter }}. {{ s|plain }}{% endfor %}
{% endif %}
*{% if narrative.by_rule %}Resumen por regla (sin IA){% else %}Resumen por IA ({{ narrative.model }}){% endif %}, {{ narrative.created_at|fecha }}.*

## Indicadores

| Indicador | Valor | Detalle |
|---|---|---|
| Riesgos abiertos | {{ data.risks.open }} | {{ data.risks.critical }} críticos · {{ data.risks.very_high }} muy altos · {{ data.risks.high }} altos · {{ data.risks.untreated }} sin tratamiento |
| Vulnerabilidades sostenidas | {{ data.vulnerabilities.sustained }} | {{ data.vulnerabilities.confirmed }} confirmadas · {{ data.vulnerabilities.needs_verification }} por verificar |
| Explotación activa (KEV) | {{ data.vulnerabilities.in_kev }} | {{ data.vulnerabilities.kev_overdue }} con plazo CISA vencido |
| Activos | {{ data.assets.total }} | {{ data.assets.with_criticality }} con criticidad · {{ data.assets.scanned_window }} escaneados en la ventana |
| Acciones por aprobar | {{ data.actions.pending_approval }} | {{ data.actions.done_window }} ejecutadas en la ventana |
| Observaciones | {{ data.observations.total }} | {{ data.observations.multi_source }} con más de una fuente |
{% if deltas.available %}
Frente al {{ deltas.since|fecha_corta }}: riesgos abiertos {{ deltas.risks_open|stringformat:"+d" }}, críticos {{ deltas.risks_critical|stringformat:"+d" }}, vulnerabilidades sostenidas {{ deltas.vulns_sustained|stringformat:"+d" }}, en KEV {{ deltas.vulns_kev|stringformat:"+d" }}.
{% endif %}
## Riesgos principales

| Riesgo | Activo | P × I | Nivel | Inteligencia | Tratamiento |
|---|---|---|---|---|---|
{% for r in top_risks %}| {{ r.title }} | {{ r.asset.name }} | {{ r.likelihood }} × {{ r.impact }} | {{ r.get_level_display }} | {{ r.intelligence_summary|default:"—"|plain }} | {% if r.treatment %}{{ r.get_treatment_display }}{% else %}sin decidir{% endif %} |
{% endfor %}
## Lo que el sistema hizo por sí solo ({{ data.window_days }} días)

- {{ data.automation.decisions_window }} decisiones del planificador ({{ data.automation.auto_approved_window }} aprobadas automáticamente) y {{ data.automation.scans_window }} escaneos ejecutados.
- {{ data.automation.vulns_consolidated_window }} vulnerabilidades consolidadas, {{ data.automation.vulns_described_window }} descripciones redactadas y {{ data.automation.risks_assessed_window }} riesgos valorados conforme a ISO/IEC 27005.
- {{ data.automation.cti_syncs_window }} sincronizaciones de inteligencia; {{ data.llm.hours_window }} horas de modelo local con {{ data.llm.ok_window }} de {{ data.llm.calls_window }} respuestas válidas.

## Avisos vigentes
{% for a in alerts %}
- **{% if a.level == 'critical' %}Crítico{% elif a.level == 'high' %}Alto{% elif a.level == 'medium' %}Medio{% else %}Info{% endif %}** · {{ a.text }}{% empty %}
Sin avisos.{% endfor %}

---
Las valoraciones «por IA» las produjo un modelo local y pueden corregirse en la plataforma; el tratamiento lo decide siempre una persona.
{% endautoescape %}

{% autoescape off %}{% load detection_tags inventory %}# {{ risk.headline }}
{% if risk.cause %}
*por {{ risk.cause }}*
{% endif %}
**Nivel:** {{ risk.get_level_display }} ({{ risk.likelihood }} × {{ risk.impact }} = {{ risk.score }}) · **Estado:** {{ risk.get_status_display }}{% if risk.consequence %} · **Consecuencia:** {{ risk.get_consequence_display }}{% endif %} · **Fuente de amenaza:** {{ risk.get_threat_source_display }}
**Valorado por** {% if risk.assessment_source == 'AI' %}IA ({{ risk.model }}){% else %}regla{% endif %} el {{ risk.assessed_at|fecha }} · Atalaya · ISO/IEC 27005:2022

## Resumen ejecutivo

**{{ asset.name }}** ({{ asset.business_role|catalog:"BUSINESS_ROLE" }}, {{ asset.environment|catalog:"ENVIRONMENT" }}, exposición {{ asset.exposure|choice_label:"Exposure"|lower }}) tiene un riesgo de nivel **{{ risk.get_level_display|lower }}** de **{{ risk.get_consequence_display|default:"compromiso"|lower }}**, sustentado en {{ evidence|length|pl:"vulnerabilidad,vulnerabilidades" }}{% if intel.kev_count %}, {{ intel.kev_count }} de ellas con explotación activa conocida (KEV){% if intel.kev_overdue %} y plazo de remediación de CISA vencido{% endif %}{% endif %}.

- **Qué podría pasar:** {{ risk.impact_description|default:risk.scenario }}
- **Qué hacer primero:** {% if risk.recommendations %}{{ risk.recommendations.0 }}{% else %}ver las acciones de cada vulnerabilidad ligada{% endif %}
- **Decisión:** {% if closure %}riesgo cerrado el {{ closure.at|fecha }} ({{ closure.message }}){% elif risk.treatment %}{{ risk.get_treatment_display }}{% if risk.owner %}, responsable {{ risk.owner }}{% endif %}, decidido por {{ risk.decided_by.get_username|default:"—" }} el {{ risk.decided_at|fecha }}{% else %}pendiente: nadie ha decidido el tratamiento{% endif %}

## Activo

- **Nombre:** {{ asset.name }}
- **Función de negocio:** {{ asset.business_role|catalog:"BUSINESS_ROLE" }} · **Entorno:** {{ asset.environment|catalog:"ENVIRONMENT" }}
- **Criticidad:** {{ asset.criticality|choice_label:"Criticality" }} · **Exposición:** {{ asset.exposure|choice_label:"Exposure" }} · **Datos:** {{ asset.data_classification|choice_label:"DataClassification" }}
- **Identificadores:** {% for i in asset.identifiers.all %}{{ i.value }}{% if not forloop.last %}, {% endif %}{% endfor %}

## Descripción

{{ risk.description|default:risk.scenario }}

**Qué perdería la organización.** {% if risk.impact_description %}{{ risk.impact_description }}{% else %}No descrito; la valoración estima el impacto en {{ risk.impact }} / 5.{% endif %}

## Detalles

{{ risk.details|default:risk.scenario }}

## Inteligencia de amenazas

{{ intel.plain }}

*Detalle técnico:* {{ intel.text }}
{% if risk.intelligence_summary and risk.assessment_source == 'AI' and risk.intelligence_summary != intel.text %}
*Lectura de la IA:* {{ risk.intelligence_summary }}
{% endif %}
- **En el catálogo de explotación activa (KEV, CISA):** {{ intel.kev_count }} de {{ intel.total }}{% if intel.kev_since %} · desde el {{ intel.kev_since|fecha }}{% endif %}{% if intel.ransomware_count %} · {{ intel.ransomware_count }} en ransomware{% endif %}
- **Plazo de remediación que fijó CISA:** {% if intel.kev_due %}{{ intel.kev_due|fecha }}{% if intel.kev_overdue %} (vencido){% endif %}{% else %}—{% endif %}
- **Probabilidad de intento de explotación en 30 días (EPSS):** {% if intel.epss_max is not None %}{{ intel.epss_max|epss_pct }}{% if intel.epss_percentile is not None %} (percentil {{ intel.epss_percentile|percentil }}){% endif %} · {{ intel.epss_key }}{% else %}—{% endif %}
- **Confirmadas por más de una fuente:** {{ intel.multi_source_count }} de {{ intel.total }}{% if intel.cti_only_count %} · {{ intel.cti_only_count }} solo por inteligencia{% endif %}

Fuentes: espejo local de NVD, catálogo KEV de CISA y EPSS (FIRST).

## Valoración

| Probabilidad | Impacto | Nivel |
|---|---|---|
| {{ risk.likelihood }} / 5 | {{ risk.impact }} / 5 | {{ risk.get_level_display }} ({{ risk.score }}) |
{% if risk.rationale %}
{{ risk.rationale }}
{% endif %}
## Recomendaciones
{% for r in risk.recommendations %}
{{ forloop.counter }}. {{ r }}{% empty %}
Ver las acciones de cada vulnerabilidad.{% endfor %}

## Tratamiento

{% if risk.treatment %}{{ risk.get_treatment_display }}{% if risk.owner %} · responsable: {{ risk.owner }}{% endif %} · decidido por {{ risk.decided_by.get_username|default:"—" }} el {{ risk.decided_at|fecha }}.{% if risk.treatment_note %} «{{ risk.treatment_note }}»{% endif %}{% if risk.residual_level %} Riesgo residual: {{ risk.get_residual_level_display }} ({{ risk.residual_likelihood }} × {{ risk.residual_impact }}).{% endif %}{% else %}Sin tratamiento decidido todavía.{% endif %}

## Evidencia técnica

{{ evidence|length|pl:"vulnerabilidad,vulnerabilidades" }} en {{ evidence_groups|length|pl:"componente de software,componentes de software" }}. Un asterisco marca las que están en el catálogo de explotación activa de CISA (KEV).

| Software afectado | Vulnerabilidades | Mayor puntaje contextual | Fuentes | Identificadores |
|---|---|---|---|---|
{% for g in evidence_groups %}| {{ g.component }} | {{ g.count }}{% if g.kev %} ({{ g.kev }} en KEV){% endif %} | {{ g.max_score|default_if_none:"—" }} | {% for s in g.sources %}{{ s|source_label }}{% if not forloop.last %}, {% endif %}{% endfor %} | {% for row in g.rows %}`{{ row.vuln.key }}`{% if row.vuln.in_kev %}\*{% endif %}{% if not forloop.last %}, {% endif %}{% endfor %} |
{% endfor %}
{% if described %}
## Las vulnerabilidades principales, explicadas
{% for row in described %}
### {{ row.vuln.title }} (`{{ row.vuln.key }}`)

{{ row.vuln.get_status_display }}, puntaje contextual {{ row.vuln.contextual_score|default_if_none:"—" }}.

{{ row.vuln.summary }}
{% if row.vuln.actions %}
Acciones: {{ row.vuln.actions|join:" · " }}
{% endif %}{% endfor %}{% endif %}
## Historia
{% for ev in timeline %}
- {{ ev.occurred_at|fecha }} · {{ ev.get_kind_display }} · {{ ev.message }} ({{ ev.actor.get_username|default:"sistema" }}){% endfor %}

---
Generado por Atalaya el {{ generated_at|fecha }} para {{ generated_by.get_username }}. Las valoraciones «por IA» las produjo un modelo local y pueden corregirse en la plataforma; el tratamiento lo decide siempre una persona.
{% endautoescape %}

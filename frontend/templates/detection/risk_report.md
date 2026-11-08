{% autoescape off %}{% load detection_tags inventory %}# {{ risk.title }}

**Nivel:** {{ risk.get_level_display }} ({{ risk.likelihood }} × {{ risk.impact }} = {{ risk.score }}) · **Estado:** {{ risk.get_status_display }}{% if risk.consequence %} · **Consecuencia:** {{ risk.get_consequence_display }}{% endif %} · **Fuente de amenaza:** {{ risk.get_threat_source_display }}
**Valorado por** {% if risk.assessment_source == 'AI' %}IA ({{ risk.model }}){% else %}regla{% endif %} el {{ risk.assessed_at|date:"Y-m-d H:i" }} · Atalaya · ISO/IEC 27005:2022

## Activo

- **Nombre:** {{ asset.name }}
- **Función de negocio:** {{ asset.business_role|catalog:"BUSINESS_ROLE" }} · **Entorno:** {{ asset.environment|catalog:"ENVIRONMENT" }}
- **Criticidad:** {{ asset.criticality|default:"—" }} · **Exposición:** {{ asset.exposure|default:"—" }} · **Datos:** {{ asset.data_classification|choice_label:"DataClassification" }}
- **Identificadores:** {% for i in asset.identifiers.all %}{{ i.value }}{% if not forloop.last %}, {% endif %}{% endfor %}

## Descripción

{{ risk.description|default:risk.scenario }}
{% if risk.description %}
*Escenario:* {{ risk.scenario }}
{% endif %}
## Posible impacto

{% if risk.impact_description %}{{ risk.impact_description }}{% else %}No descrito; la valoración estima el impacto en {{ risk.impact }} / 5.{% endif %}

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

{% if risk.treatment %}{{ risk.get_treatment_display }}{% if risk.owner %} · responsable: {{ risk.owner }}{% endif %} · decidido por {{ risk.decided_by.get_username|default:"—" }} el {{ risk.decided_at|date:"Y-m-d H:i" }}.{% if risk.treatment_note %} «{{ risk.treatment_note }}»{% endif %}{% if risk.residual_level %} Riesgo residual: {{ risk.get_residual_level_display }} ({{ risk.residual_likelihood }} × {{ risk.residual_impact }}).{% endif %}{% else %}Sin tratamiento decidido todavía.{% endif %}

## Evidencia técnica

| Vulnerabilidad | Contextual | Técnico | CVSS | EPSS | Estado | Sustento |
|---|---|---|---|---|---|---|
{% for row in evidence %}| {{ row.vuln.title }} (`{{ row.vuln.key }}`{% if row.vuln.component %}, {{ row.vuln.component.label }}{% endif %}){% if row.vuln.in_kev %} **KEV**{% endif %} | {{ row.vuln.contextual_score|default_if_none:"—" }} | {{ row.vuln.technical_score|default_if_none:"—" }} | {{ row.vuln.cvss_score|default_if_none:"—" }} | {{ row.vuln.epss_score|epss_pct }} | {{ row.vuln.get_status_display }} ({{ row.vuln.plausibility|pct }}) | {{ row.observations }} obs.: {{ row.sources|join:", "|lower }}{% if row.templates %}; {{ row.templates|join:", " }}{% endif %} |
{% endfor %}
{% for row in evidence %}{% if row.vuln.summary or row.vuln.technical_description %}
### {{ row.vuln.title }}
{% if row.vuln.summary %}
{{ row.vuln.summary }}
{% endif %}{% if row.vuln.actions %}
Acciones: {{ row.vuln.actions|join:" · " }}
{% endif %}{% if row.vuln.technical_description %}
> {{ row.vuln.technical_description|truncatechars:500 }}
{% endif %}{% endif %}{% endfor %}
## Historia
{% for ev in timeline %}
- {{ ev.occurred_at|date:"Y-m-d H:i" }} · {{ ev.get_kind_display }} · {{ ev.message }} ({{ ev.actor.get_username|default:"sistema" }}){% endfor %}

---
Generado por Atalaya el {{ generated_at|date:"Y-m-d H:i" }} para {{ generated_by.get_username }}. Las valoraciones «por IA» las produjo un modelo local y pueden corregirse en la plataforma; el tratamiento lo decide siempre una persona.
{% endautoescape %}

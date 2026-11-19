"""Números y plurales de los textos que se muestran (revisión del 2026-11-16, P5)."""

import pytest
from django.template import Context, Template

from apps.core.text import cuantos, forma, legible, miles


def test_cuantos_writes_the_number_with_thousands_and_the_right_form():
    assert cuantos(1, "hallazgo") == "1 hallazgo"
    assert cuantos(0, "cambio") == "0 cambios"
    assert cuantos(33753, "resultado") == "33,753 resultados"
    assert cuantos(2, "decisión", "decisiones") == "2 decisiones"
    assert cuantos(1, "hallazgo nuevo", "hallazgos nuevos") == "1 hallazgo nuevo"
    assert forma(1, "encontró", "encontraron") == "encontró"
    assert forma(None, "riesgo") == "riesgos" and miles("n/d") == "n/d"


@pytest.mark.parametrize(
    ("stored", "shown"),
    [
        (
            "nuclei cves-web: 9 hallazgo(s) distintos de 33753 resultado(s) · 2 consulta(s) a terceros",
            "nuclei cves-web: 9 hallazgos distintos de 33,753 resultados · 2 consultas a terceros",
        ),
        (
            "1 hallazgo(s) distintos · 1 resultado(s) crudos",
            "1 hallazgo distinto · 1 resultado crudo",
        ),
        ("Se encontraron 3 hallazgo(s), 1 nuevo(s).", "Se encontraron 3 hallazgos, 1 nuevo."),
        ("4582 cambio(s)", "4,582 cambios"),
        ("3 decisión(es) esta hora", "3 decisiones esta hora"),
        ("Consolidada a partir de 1 observación(es)", "Consolidada a partir de 1 observación"),
        ("1 acción(es) abiertas", "1 acción abierta"),
        ("5 activo(s) nuevo(s), 2 SBOM adjunto(s)", "5 activos nuevos, 2 SBOM adjuntos"),
        # Lo que no lleva la marca no se toca: puertos, años, direcciones.
        ("puerto 8080 abierto en 2026", "puerto 8080 abierto en 2026"),
        ("«x» no es una URL http(s) válida.", "«x» no es una URL http(s) válida."),
        ("", ""),
    ],
)
def test_legible_repairs_stored_texts_when_shown(stored, shown):
    assert legible(stored) == shown


def test_template_filters_for_stored_text_and_durations():
    render = lambda source, **ctx: Template(source).render(Context(ctx))  # noqa: E731
    assert render("{{ t|legible }}", t="2 cambio(s)") == "2 cambios"
    assert render(
        "{{ a|duracion }} · {{ b|duracion }} · {{ c|duracion }} · {{ d|duracion }}",
        a=850,
        b=5671,
        c=48437,
        d=125000,
    ) == ("850 ms · 5.7 s · 48 s · 2 min 5 s")
    assert render("{{ x|duracion }}", x=None) == "—"

"""Riesgos de la organización: una consecuencia sobre una función de negocio, con un escenario
por activo. No tienen tabla: se arman con los escenarios abiertos."""

import datetime

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.detection import business_risks
from apps.detection.models import Risk, RiskConsequence, RiskLevel, RiskStatus, risk_level_for
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db
LEAK, CHANGE, DOWN = (
    RiskConsequence.CONFIDENTIALITY,
    RiskConsequence.INTEGRITY,
    RiskConsequence.AVAILABILITY,
)


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


def _scenario(asset, consequence, likelihood, impact, **extra):
    return Risk.objects.create(
        asset=asset,
        key=consequence,
        consequence=consequence,
        title=f"{RiskConsequence(consequence).label} en {asset.name} por nginx 1.27.3",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=likelihood,
        impact=impact,
        level=risk_level_for(likelihood, impact),
        **{"first_identified_at": timezone.now(), **extra},
    )


def _organization():
    """Dos activos de pagos, una API y un equipo sin función: cinco escenarios, cuatro riesgos."""
    pagos = AssetFactory(name="pagos-01", business_role="PAGOS")
    pagos_2 = AssetFactory(name="pagos-02", business_role="PAGOS")
    api = AssetFactory(name="api-01", business_role="API")
    suelto = AssetFactory(name="suelto-01", business_role="")
    return {
        "pagos_leak": _scenario(pagos, LEAK, 2, 3),
        "pagos_2_leak": _scenario(pagos_2, LEAK, 5, 5),
        "pagos_down": _scenario(pagos, DOWN, 3, 4),
        "api_leak": _scenario(api, LEAK, 4, 4),
        "suelto": _scenario(suelto, CHANGE, 1, 2),
    }


def test_a_risk_is_a_consequence_on_a_business_function_and_takes_its_worst_scenario():
    rows = _organization()
    found = business_risks.register()
    assert [r.title for r in found] == [
        "Fuga de información en Pagos",
        "Fuga de información en API",
        "Interrupción del servicio en Pagos",
        "Alteración de datos o sistemas en activos sin función de negocio",
    ]
    leak = found[0]
    # El nivel no se promedia: manda el peor escenario, y va primero.
    assert leak.level == RiskLevel.CRITICAL and (leak.likelihood, leak.impact, leak.score) == (
        5,
        5,
        25,
    )
    assert [s.pk for s in leak.scenarios] == [rows["pagos_2_leak"].pk, rows["pagos_leak"].pk]
    assert [a.name for a in leak.assets] == ["pagos-02", "pagos-01"]
    assert leak.undecided == 2 and leak.treatments == "sin decidir"
    assert business_risks.counts() == {
        "open": 4,
        "by_level": {"LOW": 1, "MODERATE": 0, "HIGH": 1, "VERY_HIGH": 1, "CRITICAL": 1},
        "undecided": 4,
    }
    summary = business_risks.summary(found)
    assert (summary["open"], summary["scenarios"], summary["assets"]) == (4, 5, 4)
    assert summary["critical"] == 1 and summary["undecided"] == 4


def test_closed_scenarios_leave_the_risk_and_an_empty_risk_disappears():
    rows = _organization()
    worst = rows["pagos_2_leak"]
    worst.status, worst.closed_at = RiskStatus.CLOSED, timezone.now()
    worst.save()
    leak = business_risks.get(LEAK, "PAGOS")
    # Sin su peor escenario, el riesgo baja al nivel del que queda.
    assert leak.level == RiskLevel.MODERATE and len(leak.scenarios) == 1
    Risk.objects.filter(pk=rows["api_leak"].pk).update(status=RiskStatus.CLOSED)
    assert business_risks.get(LEAK, "API") is None
    assert len(business_risks.register()) == 3
    # El escenario cerrado sigue sabiendo de qué riesgo era, aunque ya no cuente en él.
    assert business_risks.of(worst).title == "Fuga de información en Pagos"
    assert business_risks.of(rows["api_leak"]).scenarios == []


def test_an_asset_that_changes_function_moves_its_scenarios_with_it():
    rows = _organization()
    asset = rows["pagos_down"].asset
    asset.business_role = "API"
    asset.save()
    titles = {r.title: len(r.scenarios) for r in business_risks.register()}
    assert titles["Fuga de información en API"] == 2
    assert titles["Fuga de información en Pagos"] == 1
    assert "Interrupción del servicio en Pagos" not in titles
    assert titles["Interrupción del servicio en API"] == 1


def test_the_map_has_a_row_per_function_and_a_column_per_consequence():
    _organization()
    grid = business_risks.grid(business_risks.register())
    assert [label for _, label in grid["columns"]] == [
        "Fuga de información",
        "Alteración de datos o sistemas",
        "Interrupción del servicio",
    ]
    rows = {row["label"]: row["cells"] for row in grid["rows"]}
    # Las funciones, por su riesgo más grave; cada casilla es un riesgo o nada.
    assert list(rows) == ["Pagos", "API", "activos sin función de negocio"]
    assert [cell.level if cell else None for cell in rows["Pagos"]] == [
        RiskLevel.CRITICAL,
        None,
        RiskLevel.HIGH,
    ]
    assert [bool(cell) for cell in rows["API"]] == [True, False, False]


def test_the_register_opens_by_risk_and_keeps_the_scenario_list(client, as_role):
    rows = _organization()
    as_role(AUDITOR)
    body = client.get(reverse("detection:risks")).content.decode()
    assert "data-business-risks" in body and "data-risk-map" in body
    assert "Fuga de información en Pagos" in body and "2 escenarios" in body
    assert reverse("detection:business_risk", args=[LEAK, "PAGOS"]) in body
    # Un filtro propio de los escenarios (o pedirlo) abre la lista de escenarios de siempre.
    for query in ("?view=escenario", "?mine=1", f"?asset={rows['api_leak'].asset_id}"):
        listed = client.get(reverse("detection:risks") + query).content.decode()
        assert "data-business-risks" not in listed, query
    flat = client.get(reverse("detection:risks") + "?view=escenario").content.decode()
    assert reverse("detection:risk", args=[rows["api_leak"].pk]) in flat
    # El nivel filtra por el del riesgo (su peor escenario), no por el de cada escenario.
    moderate = client.get(reverse("detection:risks") + "?level=MODERATE").content.decode()
    assert "Fuga de información en Pagos" not in moderate.split("data-business-risks")[1]
    critical = client.get(reverse("detection:risks") + "?level=CRITICAL").content.decode()
    assert "Fuga de información en Pagos" in critical.split("data-business-risks")[1]
    assert "Fuga de información en API" not in critical.split("data-business-risks")[1]


def test_the_register_by_risk_keeps_the_five_by_five_matrix(client, as_role):
    """La matriz probabilidad × impacto sigue en la vista por riesgo: cada riesgo en la casilla de
    su peor escenario, y la casilla filtra la lista de riesgos (no la de escenarios)."""
    _organization()
    as_role(AUDITOR)
    url = reverse("detection:risks")
    response = client.get(url)
    body = response.content.decode()
    cells = {
        (c["likelihood"], c["impact"]): len(c["risks"])
        for row in response.context["risk_matrix"]
        for c in row
    }
    # Pagos (fuga) vale por su peor escenario, 5 × 5; el 2 × 3 de pagos-01 no ocupa casilla.
    assert cells[(5, 5)] == 1 and cells[(3, 4)] == 1 and cells[(4, 4)] == 1 and cells[(1, 2)] == 1
    assert cells[(2, 3)] == 0 and sum(cells.values()) == 4
    assert "data-risk-matrix" in body and "Matriz de riesgos" in body
    assert "?likelihood=5&amp;impact=5&amp;view=riesgo" in body

    picked = client.get(url + "?likelihood=5&impact=5&view=riesgo")
    assert picked.context["by_risk"]
    assert [r.title for r in picked.context["business"]] == ["Fuga de información en Pagos"]
    assert "con su peor escenario en la casilla" in picked.content.decode()
    # La matriz y el mapa siguen mostrando todo: el filtro es de la lista.
    assert sum(len(c["risks"]) for row in picked.context["risk_matrix"] for c in row) == 4
    # Sin «view=riesgo» la casilla es la de la matriz de escenarios (Inicio, la ficha del activo).
    assert not client.get(url + "?likelihood=5&impact=5").context["by_risk"]


def test_the_name_of_a_function_opens_what_it_is_and_which_assets_have_it(client, as_role):
    """«API»: ¿qué es? El nombre de la función abre un cuadro con su descripción (la del
    catálogo), lo que se puede perder en ella y sus activos, tengan riesgos o no."""
    from apps.assets import catalogs
    from apps.assets.models import CatalogEntry

    _organization()
    AssetFactory(name="pagos-sin-riesgo", business_role="PAGOS")
    AssetFactory(name="pagos-retirado", business_role="PAGOS", status="RETIRED")
    # La descripción viene sembrada para las funciones del catálogo inicial.
    assert "interfaz de programación" in catalogs.get(catalogs.BUSINESS_ROLE, "API")["description"]

    cards = {c["role"]: c for c in business_risks.role_cards(business_risks.register())}
    pagos = cards["PAGOS"]
    assert pagos["label"] == "Pagos" and "dinero" in pagos["description"]
    assert [r.consequence for r in pagos["risks"]] == [LEAK, DOWN]
    assert [(row["asset"].name, row["level"]) for row in pagos["assets"]] == [
        ("pagos-02", RiskLevel.CRITICAL),
        ("pagos-01", RiskLevel.HIGH),
        ("pagos-sin-riesgo", ""),
    ]
    assert pagos["with_risk"] == 2
    assert cards[""]["label"] == "Activos sin función de negocio" and cards[""]["description"]

    as_role(AUDITOR)
    body = client.get(reverse("detection:risks")).content.decode()
    assert (
        'data-dialog-open="funcion-pagos"' in body
        and '<dialog class="modal" id="funcion-pagos"' in body
    )
    dialog = body.split('id="funcion-pagos"')[1].split("</dialog>")[0]
    assert (
        "mueven dinero" in dialog
        and "pagos-sin-riesgo" in dialog
        and "sin riesgos abiertos" in dialog
    )
    assert "pagos-retirado" not in dialog
    assert reverse("detection:business_risk", args=[DOWN, "PAGOS"]) in dialog
    assert "Administración › Catálogos" not in dialog  # el auditor no administra catálogos

    # Una función sin descripción lo dice, y a quien puede escribirla le dice dónde.
    CatalogEntry.objects.filter(kind="BUSINESS_ROLE", code="PAGOS").update(description="")
    catalogs.invalidate()
    as_role(ADMIN)
    dialog = client.get(reverse("detection:risks")).content.decode()
    dialog = dialog.split('id="funcion-pagos"')[1].split("</dialog>")[0]
    assert "todavía no tiene descripción" in dialog and "Administración › Catálogos" in dialog

    # La página de un riesgo lleva el mismo cuadro, con todos los riesgos de su función.
    page = client.get(reverse("detection:business_risk", args=[LEAK, "PAGOS"])).content.decode()
    assert 'data-dialog-open="funcion-pagos"' in page
    assert "Interrupción del servicio" in page.split('id="funcion-pagos"')[1].split("</dialog>")[0]


def test_assets_without_a_function_are_one_group_whether_empty_or_null(client, as_role):
    """«Sin función» se guarda vacío o nulo según por dónde entró el activo: es el mismo grupo."""
    vacio = AssetFactory(name="suelto-vacio", business_role="")
    nulo = AssetFactory(name="suelto-nulo", business_role=None)
    _scenario(vacio, LEAK, 2, 2)
    worst = _scenario(nulo, LEAK, 4, 4)
    (risk,) = business_risks.register()
    assert risk.role == "" and len(risk.scenarios) == 2
    assert business_risks.get(LEAK, business_risks.NO_ROLE).worst == worst
    assert len(business_risks.of(worst).scenarios) == 2
    card = business_risks.role_card(business_risks.NO_ROLE)
    assert {row["asset"].name for row in card["assets"]} == {"suelto-vacio", "suelto-nulo"}
    as_role(AUDITOR)
    page = client.get(risk.url)
    assert page.status_code == 200 and "suelto-nulo" in page.content.decode()


def test_the_risk_page_lists_its_scenarios_and_decides_them_together(client, as_role):
    rows = _organization()
    user = as_role(OPERATOR)
    url = reverse("detection:business_risk", args=[LEAK, "PAGOS"])
    body = client.get(url).content.decode()
    assert "Fuga de información en Pagos" in body and "pagos-01" in body and "pagos-02" in body
    assert "api-01" not in body
    # Al entrar, todos sus escenarios están marcados: decidir aquí es decidir el riesgo.
    assert body.count('name="ids"') == 2 and body.count('class="checkbox" checked') == 2
    target = timezone.localdate() + datetime.timedelta(days=20)
    response = client.post(
        reverse("detection:risk_bulk"),
        {
            "ids": [rows["pagos_leak"].pk, rows["pagos_2_leak"].pk],
            "treatment": "MITIGATE",
            "target_date": target.isoformat(),
            "note": "Se parchan los dos en la ventana del sábado.",
            "next": url,
        },
    )
    assert response.status_code == 302 and response["Location"] == url
    leak = business_risks.get(LEAK, "PAGOS")
    assert leak.undecided == 0 and leak.treatments == "mitigar"
    assert all(s.decided_by_id == user.pk and s.target_date == target for s in leak.scenarios)
    # La decisión es de los escenarios que había: la interrupción de pagos sigue sin decidir.
    assert business_risks.get(DOWN, "PAGOS").undecided == 1
    # Un activo que entra después llega sin decidir.
    _scenario(AssetFactory(name="pagos-03", business_role="PAGOS"), LEAK, 3, 3)
    leak = business_risks.get(LEAK, "PAGOS")
    assert leak.undecided == 1 and leak.treatments == "2 mitigar · 1 sin decidir"


def test_a_risk_without_open_scenarios_sends_back_to_the_register(client, as_role):
    _organization()
    as_role(AUDITOR)
    response = client.get(reverse("detection:business_risk", args=[DOWN, "API"]), follow=True)
    assert response.redirect_chain[-1][0] == reverse("detection:risks")
    assert "ya no tiene escenarios abiertos" in response.content.decode()
    assert client.get(reverse("detection:business_risk", args=["NADA", "API"])).status_code == 404
    # Una función que el catálogo no conoce tampoco es «un riesgo que se resolvió».
    unknown = reverse("detection:business_risk", args=["CONFIDENTIALITY", "NO_EXISTE"])
    assert client.get(unknown).status_code == 404


def test_the_scenario_page_names_its_risk(client, as_role):
    rows = _organization()
    as_role(AUDITOR)
    body = client.get(reverse("detection:risk", args=[rows["pagos_leak"].pk])).content.decode()
    assert reverse("detection:business_risk", args=[LEAK, "PAGOS"]) in body
    assert "Fuga de información en Pagos" in body and "2 activos" in body

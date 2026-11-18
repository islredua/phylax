"""Qué es una función de negocio **en esta organización** (2026-11-18).

El cuadro de una función decía solo la definición del catálogo, igual para cualquier organización
(«Pagos: sistemas que cobran, pagan o mueven dinero»). Ahora dice qué es aquí: un párrafo que la
IA arma con el perfil de la organización y la descripción de los activos de la función, y lo que
el inventario sabe de ellos (criticidad, exposición, datos), que pone el código.

Sin red, sin LLM real (modo simulado) y sin herramientas.
"""

import json

import pytest
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from pydantic import ValidationError

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.detection import business_risks, business_roles, profile, tasks
from apps.detection.models import (
    BusinessRoleDescription,
    OrganizationProfile,
    Risk,
    RiskConsequence,
    risk_level_for,
)
from apps.llm.models import InferenceLog
from apps.llm.schemas import business_role_validator
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db
GENERAL = "Sistemas que cobran, pagan o mueven dinero"


@pytest.fixture(autouse=True)
def _setup(settings):
    cache.clear()
    settings.LLM_MOCK_MODE = True


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


def _organization(**fields):
    OrganizationProfile.objects.update_or_create(
        pk=1,
        defaults={
            "name": "Aseguradora Norte",
            "sector": "Aseguradora regional de **seguros de vida**",
            "description": "Vende pólizas por un portal público y cobra las primas con tarjeta.",
            **fields,
        },
    )
    profile.invalidate()


def _scenario(asset, consequence=RiskConsequence.CONFIDENTIALITY, likelihood=4, impact=5):
    return Risk.objects.create(
        asset=asset,
        key=consequence,
        consequence=consequence,
        title=f"{RiskConsequence(consequence).label} en {asset.name}",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=likelihood,
        impact=impact,
        level=risk_level_for(likelihood, impact),
        first_identified_at=timezone.now(),
    )


def _payments():
    """Dos activos de pagos descritos (uno con riesgo), uno retirado y uno de otra función."""
    _organization()
    api = AssetFactory(
        name="api-pagos",
        business_role="PAGOS",
        description="Servicio que procesa el cobro de primas con tarjeta desde el portal público.",
        criticality="CRITICO",
        exposure="DMZ",
        environment="PROD",
        data_classification="RESTRINGIDA",
        data_categories=["FINANCIERO", "PII"],
        business_owner="Tesorería",
    )
    ledger = AssetFactory(
        name="conciliador",
        business_role="PAGOS",
        description="Concilia cada noche los cobros con el banco.",
        criticality="ALTO",
        exposure="INTERNAL",
        data_classification="CONFIDENCIAL",
        data_categories=["FINANCIERO"],
    )
    AssetFactory(name="pagos-viejo", business_role="PAGOS", status="RETIRED", description="x" * 40)
    AssetFactory(name="crm-legacy", business_role="API", description="CRM de los agentes.")
    _scenario(api)
    return api, ledger


def _dialog(body, role="pagos"):
    return " ".join(body.split(f'id="funcion-{role}"')[1].split("</dialog>")[0].split())


# --------------------------------------------------------------------------
# El cuadro de la función
# --------------------------------------------------------------------------


def test_the_function_card_says_what_the_function_is_in_this_organization(client, as_role):
    as_role(AUDITOR)
    _payments()
    dialog = _dialog(client.get(reverse("detection:risks")).content.decode())

    # Primero, qué es aquí: el párrafo de la IA (queda pedido y escrito al abrir el registro).
    found = BusinessRoleDescription.objects.get()
    assert (found.role, found.source) == ("PAGOS", "AI")
    assert found.prompt_version == business_roles.PROMPT_VERSION
    assert "api-pagos" in found.summary and "conciliador" in found.summary
    assert "En Aseguradora Norte</h4>" in dialog and found.summary in dialog
    assert "por IA" in dialog and "Puede equivocarse" in dialog
    # Después, la definición general del catálogo, que antes era todo lo que había.
    assert dialog.index("En Aseguradora Norte") < dialog.index("En general") < dialog.index(GENERAL)
    # Lo que el inventario sabe de sus activos lo pone el código.
    assert business_roles.facts(business_roles.assets_of("PAGOS")) == [
        ("Criticidad", "1 crítico · 1 de criticidad alta"),
        ("Dónde están", "1 en la DMZ · 1 en la red interna"),
        (
            "Datos que manejan",
            "Datos personales, financieros · clasificación más alta: restringida",
        ),
        ("Responsables de negocio", "Tesorería"),
    ]
    for text in ("1 crítico · 1 de criticidad alta", "1 en la DMZ", "clasificación más alta"):
        assert text in dialog, text
    # Cada activo dice qué es, tenga riesgos o no; el retirado y el de otra función no están.
    assert "Servicio que procesa el cobro de primas con tarjeta" in dialog
    assert "Concilia cada noche los cobros con el banco." in dialog
    assert "pagos-viejo" not in dialog and "crm-legacy" not in dialog
    # Quien solo lee no ve el formulario para corregir.
    assert "Corregir la explicación" not in dialog

    # La otra función tiene su propio párrafo, y volver a abrir la página no pregunta de nuevo.
    assert InferenceLog.objects.filter(task="ROLE_DESCRIBE").count() == 1  # API no tiene riesgos
    client.get(reverse("detection:risks"))
    assert InferenceLog.objects.filter(task="ROLE_DESCRIBE").count() == 1


def test_the_model_is_asked_again_only_when_what_it_was_told_changes(client, as_role):
    as_role(AUDITOR)
    api, _ledger = _payments()
    payload = business_roles.build_payload("PAGOS")
    sent = json.dumps(payload, ensure_ascii=False)
    # El modelo recibe quién es la organización, la definición general y qué es cada activo, del
    # más crítico al menos; sin marcas de Markdown ni activos fuera del inventario.
    assert payload["organization"] == {
        "name": "Aseguradora Norte",
        "sector": "Aseguradora regional de seguros de vida",
        "what_it_does": "Vende pólizas por un portal público y cobra las primas con tarjeta.",
    }
    assert payload["business_function"]["name"] == "Pagos"
    assert GENERAL in payload["business_function"]["general_meaning"]
    assert [a["name"] for a in payload["assets_with_this_function"]] == ["api-pagos", "conciliador"]
    assert payload["assets_with_this_function"][0] == {
        "name": "api-pagos",
        "what_it_is": "Servicio que procesa el cobro de primas con tarjeta desde el portal público.",
        "criticality": "crítico",
        "where": "en la DMZ (la zona que da la cara a Internet)",
        "environment": "Producción",
        "data": "información restringida, la más sensible: datos personales, financieros",
    }
    assert payload["how_many_assets"] == 2 and "pagos-viejo" not in sent and "**" not in sent

    assert business_roles.queue_missing() == 2  # Pagos y API
    assert business_roles.queue_missing() == 0
    first = BusinessRoleDescription.objects.get(role="PAGOS")
    assert first.fingerprint == business_roles.fingerprint(payload)
    # Cambia lo que hace un activo: la huella cambia y se vuelve a preguntar, solo por su función.
    api.description = "Servicio que cobra las primas y guarda los comprobantes."
    api.save(update_fields=["description"])
    assert business_roles.needs(first, business_roles.build_payload("PAGOS"))
    assert tasks.describe_pending_vulnerabilities()["functions"] == 1
    assert InferenceLog.objects.filter(task="ROLE_DESCRIBE").count() == 3
    # Cambia el perfil de la organización: se revisan todas.
    _organization(description="Ahora también vende seguros de auto.")
    assert business_roles.queue_missing() == 2


def test_without_anything_to_go_on_the_model_is_not_asked(client, as_role):
    as_role(ADMIN)
    OrganizationProfile.objects.update_or_create(pk=1, defaults={"name": "", "description": ""})
    profile.invalidate()
    bare = AssetFactory(name="caja-01", business_role="PAGOS", description="", criticality="ALTO")
    _scenario(bare)
    loose = AssetFactory(name="suelto-01", business_role="", description="Equipo de pruebas.")
    _scenario(loose, RiskConsequence.AVAILABILITY)
    body = client.get(reverse("detection:risks")).content.decode()
    dialog = _dialog(body)
    assert not business_roles.has_context(business_roles.build_payload("PAGOS"))
    assert not BusinessRoleDescription.objects.exists() and not InferenceLog.objects.exists()
    assert business_roles.queue_missing() == 0
    # El cuadro dice qué falta escribir y sigue dando la definición general y los datos.
    assert "En esta organización</h4>" in dialog and "Todavía no hay con qué decirlo" in dialog
    assert GENERAL in dialog and "1 de criticidad alta" in dialog
    assert "Sin descripción en el inventario." in dialog
    # Los activos sin función no tienen párrafo: no hay función que explicar.
    no_role = _dialog(body, "sin-funcion")
    assert "En esta organización" not in no_role and "Equipo de pruebas." in no_role
    # En cuanto alguien describe el activo, hay con qué.
    bare.description = "Terminal de cobro de la sucursal centro."
    bare.save(update_fields=["description"])
    assert business_roles.queue_missing() == 1
    assert "caja-01" in BusinessRoleDescription.objects.get().summary


# --------------------------------------------------------------------------
# La respuesta del modelo va atada a los datos
# --------------------------------------------------------------------------


def test_the_answer_must_come_from_what_the_model_was_told():
    _payments()
    payload = business_roles.build_payload("PAGOS")
    validator = business_roles._validator(payload)
    good = (
        "En Aseguradora Norte, Pagos es el cobro de las primas con tarjeta: **api-pagos** procesa "
        "cada cobro que llega del portal público y conciliador lo cuadra con el banco cada noche."
    )
    parsed = validator.model_validate({"summary": good})
    assert "**" not in parsed.summary and parsed.summary.startswith("En Aseguradora Norte")
    # Nombrar un activo con sus palabras («el portal público» por «portal-publico») también vale.
    spoken = business_role_validator(
        assets=["portal-publico"], known_text="portal-publico", general=""
    )
    spoken.model_validate(
        {
            "summary": "En Aseguradora Norte, el Portal Público es donde los clientes cotizan y pagan."
        }
    )
    for bad, why in (
        (
            "Es la función que cobra las primas de los clientes con tarjeta de crédito.",
            "faltan: api-pagos",
        ),
        # Con cinco activos o menos se nombran todos: aquí falta el segundo.
        (
            "En Aseguradora Norte, api-pagos procesa cada cobro de primas que llega del portal.",
            "faltan: conciliador",
        ),
        (good + " También usa srv-tesoreria para los reportes del mes.", "srv-tesoreria"),
        (good + " Procesa 4500 cobros al día para los clientes.", "4500"),
        (good + " Tiene una vulnerabilidad que permite un ataque.", "sin vulnerabilidades"),
        (good + " " + payload["business_function"]["general_meaning"], "no repite"),
        # Tampoco un tramo de la definición general, aunque cambie la puntuación.
        # Nombrar los sistemas no basta: dice qué hace cada uno, con lo que cuenta su descripción.
        (
            "En Aseguradora Norte, esta función mueve el dinero de los clientes mediante "
            "api-pagos y conciliador. Por ellos pasan datos personales y financieros.",
            "falta decirlo de: api-pagos, conciliador",
        ),
        # Describe, no valora: lo que importa cada cosa lo dicen la criticidad y los riesgos.
        (good + " Ambos sistemas son fundamentales.", "no valora: quita fundamentales"),
        # Y el aviso le dice al modelo qué tramo copió, para que no lo repita al reintentar.
        (
            good + " Son sistemas que cobran pagan o mueven dinero de la empresa.",
            "quita «sistemas que cobran pagan o mueven dinero»",
        ),
        (
            "api-pagos processes the card payments that come from the public portal each day.",
            "español",
        ),
        ("api-pagos cobra.", "dos o tres frases"),
    ):
        with pytest.raises(ValidationError) as error:
            validator.model_validate({"summary": bad})
        assert why in str(error.value), (bad, str(error.value))


def test_every_problem_of_an_answer_is_told_at_once():
    """Avisando solo del primero, el modelo arreglaba una cosa y deshacía otra en cada reintento."""
    _payments()
    validator = business_roles._validator(business_roles.build_payload("PAGOS"))
    with pytest.raises(ValidationError) as error:
        validator.model_validate(
            {
                "summary": "En Aseguradora Norte, api-pagos procesa cada cobro de primas con "
                "tarjeta para 300 clientes, y es fundamental."
            }
        )
    message = str(error.value)
    for part in (
        "faltan: conciliador",
        "quita fundamental",
        "cifras que no están en los datos: 300",
    ):
        assert part in message, (part, message)


# --------------------------------------------------------------------------
# Una persona puede corregirlo
# --------------------------------------------------------------------------


def test_a_person_can_correct_it_and_is_told_when_the_assets_changed_afterwards(client, as_role):
    operator = as_role(OPERATOR)
    api, _ledger = _payments()
    page = reverse("detection:risks")
    assert "Corregir la explicación" in _dialog(client.get(page).content.decode())
    write = reverse("detection:business_role_context", args=["PAGOS"])
    text = "Pagos es el cobro de primas con tarjeta: lo hace api-pagos y lo revisa Tesorería."
    response = client.post(write, {"summary": text, "next": page}, follow=True)
    assert response.redirect_chain[-1][0] == page
    assert "Explicación de «Pagos» guardada a tu nombre" in response.content.decode()
    found = BusinessRoleDescription.objects.get()
    assert (found.source, found.summary, found.edited_by) == ("HUMAN", text, operator)
    dialog = _dialog(response.content.decode())
    assert text in dialog and "por una persona" in dialog and "Desde entonces" not in dialog
    # Lo que escribió una persona la IA no lo toca, cambie lo que cambie…
    api.description = "Servicio de cobro, ahora también con transferencias."
    api.save(update_fields=["description"])
    assert business_roles.describe("PAGOS") is None and not business_roles.request("PAGOS")
    assert BusinessRoleDescription.objects.get().summary == text
    # …pero el cuadro avisa de que conviene revisarlo.
    assert "Desde entonces cambiaron" in _dialog(client.get(page).content.decode())
    # El bloque que se consulta mientras la IA escribe.
    fragment = client.get(write).content.decode()
    assert 'id="funcion-pagos-contexto"' in fragment and text in fragment
    # Con el texto vacío vuelve a escribirlo la IA.
    client.post(write, {"summary": " ", "next": page})
    assert BusinessRoleDescription.objects.get().source == "AI"
    assert (
        client.get(reverse("detection:business_role_context", args=["NO_EXISTE"])).status_code
        == 404
    )
    as_role(AUDITOR)
    assert client.post(write, {"summary": "otra cosa"}).status_code == 403
    assert BusinessRoleDescription.objects.get().source == "AI"


def test_while_the_model_writes_the_open_card_checks_by_itself(client, as_role, monkeypatch):
    as_role(AUDITOR)
    _payments()
    # La pregunta queda en la cola (aquí nadie la atiende todavía).
    monkeypatch.setattr(tasks.describe_business_role, "apply_async", lambda *a, **k: None)
    page, part = (
        reverse("detection:risks"),
        reverse("detection:business_role_context", args=["PAGOS"]),
    )
    dialog = _dialog(client.get(page).content.decode())
    assert business_roles.is_pending("PAGOS") and not BusinessRoleDescription.objects.exists()
    assert "la IA está redactando" in dialog and "En general" in dialog and GENERAL in dialog
    # Se consulta sola cada 5 s, y solo el cuadro que está abierto (no los nueve a la vez).
    polling = f"""hx-get="{part}" hx-trigger="every 5s [this.closest('dialog').open]\""""
    assert polling in dialog and polling in client.get(part).content.decode()
    # Abrir la página otra vez no la encola dos veces.
    assert not business_roles.request("PAGOS")
    # Cuando el modelo responde, el bloque trae el párrafo y deja de consultarse.
    business_roles.describe("PAGOS")
    fragment = client.get(part).content.decode()
    assert not business_roles.is_pending("PAGOS")
    assert BusinessRoleDescription.objects.get().summary in fragment and "hx-get" not in fragment


def test_the_page_of_a_risk_carries_the_same_card(client, as_role):
    as_role(AUDITOR)
    _payments()
    url = reverse("detection:business_risk", args=[RiskConsequence.CONFIDENTIALITY, "PAGOS"])
    dialog = _dialog(client.get(url).content.decode())
    assert "En Aseguradora Norte</h4>" in dialog and "api-pagos" in dialog and "por IA" in dialog
    card = business_risks.role_card("PAGOS")
    assert card["context"]["text"].source == "AI" and not card["context"]["pending"]

"""«Qué puede pasar» en un riesgo de la organización, dicho con sus sistemas (2026-11-18).

La página de un riesgo decía solo el significado general de la consecuencia («Fuga de información
en API: que información que la organización debe proteger acabe en manos ajenas»): corto y
ambiguo. Ahora lo dice el sistema para cada riesgo, también para los que aparezcan después:

- una frase que la IA arma con la descripción de los activos del riesgo y que dice qué se
  perdería, atada a esos datos por un validador;
- y, por código, cada sistema con su descripción, dónde está y la causa de su escenario.

Sin red, sin LLM real (modo simulado) y sin herramientas.
"""

import json
import re

import pytest
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from pydantic import ValidationError

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.detection import business_risk_texts, business_risks, profile, tasks
from apps.detection.models import (
    BusinessRiskDescription,
    OrganizationProfile,
    Risk,
    RiskConsequence,
    RiskStatus,
    Vulnerability,
    risk_level_for,
)
from apps.llm import client as llm_client
from apps.llm.models import InferenceLog
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db
LEAK, DOWN = RiskConsequence.CONFIDENTIALITY, RiskConsequence.AVAILABILITY
GENERAL = "que información que la organización debe proteger acabe en manos ajenas"


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
            "sector": "Aseguradora regional",
            "description": "Vende pólizas de vida y gastos médicos con una red de agentes.",
            **fields,
        },
    )
    profile.invalidate()


def _scenario(asset, consequence, likelihood, impact, cause):
    return Risk.objects.create(
        asset=asset,
        key=consequence,
        consequence=consequence,
        title=f"{RiskConsequence(consequence).label} en {asset.name} por {cause}",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=likelihood,
        impact=impact,
        level=risk_level_for(likelihood, impact),
        first_identified_at=timezone.now(),
    )


def _api_leak():
    """«Fuga de información en API»: dos sistemas descritos, el más grave con una debilidad que ya
    se usa en ataques reales."""
    _organization()
    claims = AssetFactory(
        name="app-siniestros",
        business_role="API",
        description="Los ajustadores suben la evidencia de cada reclamación: facturas médicas.",
        exposure="INTERNAL",
        data_classification="RESTRINGIDA",
        data_categories=["PII", "CLINICO"],
    )
    payroll = AssetFactory(
        name="portal-rh",
        business_role="API",
        description="Los empleados consultan sus recibos de nómina y piden vacaciones.",
        exposure="DMZ",
        data_classification="CONFIDENCIAL",
        data_categories=["PII", "FINANCIERO"],
    )
    worst = _scenario(
        claims, LEAK, 5, 5, "ejecución remota de código en pillow 8.1.0 y 24 vulnerabilidades más"
    )
    other = _scenario(payroll, LEAK, 3, 4, "recorrido de rutas en Apache httpd 2.4.49")
    now = timezone.now()
    kev = Vulnerability.objects.create(
        asset=claims,
        key="CVE-2021-0001",
        title="Ejecución remota de código en pillow 8.1.0",
        severity="CRITICAL",
        in_kev=True,
        first_detected_at=now,
        last_seen_at=now,
    )
    worst.vulnerabilities.add(kev)
    return worst, other


def _risk(consequence=LEAK, role="API"):
    return business_risks.get(consequence, role)


def _what(body):
    return " ".join(body.split('id="riesgo-que-puede-pasar"')[1].split("</dd>")[0].split())


def _systems(body):
    """Las filas «dónde y por dónde» de la página: (nombre del sistema, texto de la fila)."""
    rows = []
    for part in body.split("<li data-risk-system>")[1:]:
        text = " ".join(re.sub(r"<[^>]+>", " ", part.split("</li>")[0]).split())
        rows.append((text.split(" ")[0], text))
    return rows


# --------------------------------------------------------------------------
# La página del riesgo
# --------------------------------------------------------------------------


def test_the_risk_page_says_what_would_be_lost_and_lists_each_system_by_code(client, as_role):
    as_role(AUDITOR)
    _api_leak()
    page = reverse("detection:business_risk", args=[LEAK, "API"])
    body = client.get(page).content.decode()
    what = _what(body)

    # La frase la escribe el sistema al abrir la página: nadie la redactó a mano.
    found = BusinessRiskDescription.objects.get()
    assert (found.consequence, found.role, found.source) == (LEAK, "API", "AI")
    assert found.prompt_version == business_risk_texts.PROMPT_VERSION
    # Dice qué se perdería con lo que cuentan las descripciones de sus sistemas, y no habla de
    # debilidades: eso va debajo, por código.
    for part in ("ajustadores suben la evidencia", "empleados consultan sus recibos"):
        assert part in found.summary, part
    assert "pillow" not in found.summary and "Apache" not in found.summary
    assert found.summary in what and "por IA" in what and "Puede equivocarse" in what
    # El significado general, que antes era todo, queda de referencia debajo.
    assert f"En general: {GENERAL}." in what and what.index(found.summary) < what.index(GENERAL)

    # Dónde y por dónde: cada sistema con su descripción, dónde está y la causa de su escenario,
    # el más grave primero. Lo escribe el código con los datos de siempre.
    assert "Dónde y por dónde" in body and "En 2 activos con la función «API»." in body
    (first_name, first), (second_name, second) = _systems(body)
    assert (first_name, second_name) == ("app-siniestros", "portal-rh")
    assert "Los ajustadores suben la evidencia de cada reclamación: facturas médicas." in first
    assert "En la red interna · por ejecución remota de código en pillow 8.1.0." in first
    assert "Crítico" in first and "Explotación activa" in first
    assert "Los empleados consultan sus recibos de nómina y piden vacaciones." in second
    assert (
        "En la DMZ (la zona que da la cara a Internet) · por recorrido de rutas en Apache httpd "
        "2.4.49." in second
    )
    assert "Explotación activa" not in second
    assert "es el de su peor escenario, app-siniestros" in body
    assert "Corregir el texto" not in what  # quien solo lee no lo corrige
    # Abrir la página otra vez no vuelve a preguntar.
    client.get(page)
    assert InferenceLog.objects.filter(task="ORG_RISK_DESCRIBE").count() == 1


def test_the_model_gets_what_each_system_is_and_nothing_that_moves_with_every_scan():
    worst, other = _api_leak()
    payload = business_risk_texts.build_payload(_risk())
    assert payload["risk"] == {
        "name": "Fuga de información en API",
        "what_is_lost": "Fuga de información",
        "general_meaning": GENERAL,
        "business_function": "API",
    }
    assert payload["organization"]["name"] == "Aseguradora Norte"
    assert payload["how_many_systems"] == 2
    # Del más grave al menos, cada uno con lo que es y las clases de datos que maneja. Dónde
    # está y por qué debilidad puede ocurrir no se le envían: lo escribe el código. Tampoco la
    # clasificación de sus datos («información confidencial»): la copiaba en vez de decir qué es.
    assert payload["systems_from_most_to_least_serious"] == [
        {
            "name": "app-siniestros",
            "what_it_is": "Los ajustadores suben la evidencia de cada reclamación: facturas médicas.",
            "kinds_of_data": "datos personales, clínicos",
        },
        {
            "name": "portal-rh",
            "what_it_is": "Los empleados consultan sus recibos de nómina y piden vacaciones.",
            "kinds_of_data": "datos personales, financieros",
        },
    ]
    before = business_risk_texts.fingerprint(payload)
    # Ni los conteos de un escaneo ni otra causa cambian lo que se perdería: no se pregunta.
    worst.title = "Fuga de información en app-siniestros por contraseña por defecto en el panel"
    worst.save(update_fields=["title"])
    assert business_risk_texts.fingerprint(business_risk_texts.build_payload(_risk())) == before
    # Otra descripción sí.
    other.asset.description = "Los empleados descargan sus constancias de retención."
    other.asset.save(update_fields=["description"])
    assert business_risk_texts.fingerprint(business_risk_texts.build_payload(_risk())) != before


def test_each_system_row_gives_the_whole_cause_without_the_counts_that_move():
    worst, _other = _api_leak()
    rows = business_risk_texts.systems_of(_risk())
    assert [row["asset"].name for row in rows["shown"]] == ["app-siniestros", "portal-rh"]
    assert rows["more"] == []
    # Sin «y 24 vulnerabilidades más»: es un conteo que se mueve, no la causa.
    assert rows["shown"][0]["how"] == (
        "en la red interna · por ejecución remota de código en pillow 8.1.0"
    )
    for title, cause in (
        (
            "por inyección de comandos en nginx 1.27.3 y 209 vulnerabilid",
            "inyección de comandos en nginx 1.27.3",
        ),
        ("por inyección de comandos en nginx 1.27.3 y 2", "inyección de comandos en nginx 1.27.3"),
        (
            "por 5 debilidades de configuración del servicio",
            "debilidades de configuración del servicio",
        ),
        (
            "por cookies sin nombre en Werkzeug httpd 2.0.3 · 5000/tcp",
            "cookies sin nombre en Werkzeug httpd 2.0.3",
        ),
        ("sin la fórmula del título", ""),
    ):
        worst.title = f"Fuga de información en app-siniestros {title}"
        assert business_risk_texts.cause_of(worst) == cause, title
    # Una causa que el título dejó a media palabra se completa con la vulnerabilidad del escenario.
    long_title = (
        "Inyección de salida inadecuada en mod_rewrite en Apache HTTP Server 2.4.59 y versiones "
        "anteriores"
    )
    now = timezone.now()
    worst.vulnerabilities.add(
        Vulnerability.objects.create(
            asset=worst.asset,
            key="CVE-2024-0002",
            title=f"{long_title} (CVE-2024-0002)",
            severity="HIGH",
            first_detected_at=now,
            last_seen_at=now,
        )
    )
    cut = long_title[0].lower() + long_title[1:80]
    worst.title = f"Fuga de información en app-siniestros por {cut} y 41 vulnerabilidades más"
    assert worst.title.endswith("2.4.59 y ver y 41 vulnerabilidades más")
    assert business_risk_texts.cause_of(worst) == long_title[0].lower() + long_title[1:]
    # …y si esa vulnerabilidad ya no está, se queda sin la palabra cortada.
    worst.title = worst.title.replace("inyección de salida", "inyección de entrada")
    assert business_risk_texts.cause_of(worst).endswith("Apache HTTP Server 2.4.59 y")
    # La descripción de cada fila va en una línea, sin marcas y cortada en un espacio.
    worst.asset.description = "**Aplicación** de siniestros: " + "evidencia adjunta " * 12
    worst.asset.save(update_fields=["description"])
    what = business_risk_texts.systems_of(_risk())["shown"][0]["what"]
    assert what.startswith("Aplicación de siniestros: evidencia adjunta")
    assert what.endswith(("evidencia…", "adjunta…")) and len(what) <= business_risk_texts.WHAT_MAX
    # Un activo sin ubicación ni causa reconocible no tiene esa línea.
    worst.title = "Un título escrito de otra manera"
    worst.save(update_fields=["title"])
    worst.asset.exposure = ""
    worst.asset.save(update_fields=["exposure"])
    hows = {
        row["asset"].name: row["how"] for row in business_risk_texts.systems_of(_risk())["shown"]
    }
    assert hows["app-siniestros"] == ""


# --------------------------------------------------------------------------
# Riesgos nuevos: lo hace el sistema, sin que nadie abra la página
# --------------------------------------------------------------------------


def test_a_new_risk_gets_its_text_from_the_periodic_drain_and_is_rewritten_when_it_changes():
    worst, other = _api_leak()
    assert tasks.describe_pending_vulnerabilities()["risks"] == 1
    first = BusinessRiskDescription.objects.get()
    assert "fuga de información" in first.summary and "ajustadores suben" in first.summary
    assert "risks" not in tasks.describe_pending_vulnerabilities()  # al día: no se pregunta

    # Aparece un riesgo que no existía (otra consecuencia sobre la misma función).
    _scenario(other.asset, DOWN, 4, 4, "denegación de servicio en Apache httpd 2.4.49")
    assert tasks.describe_pending_vulnerabilities()["risks"] == 1
    down = BusinessRiskDescription.objects.get(consequence=DOWN)
    assert down.role == "API" and "interrupción del servicio" in down.summary
    assert "recibos de nómina" in down.summary

    # Otra causa en un escenario no cambia lo que se perdería: la muestra el código, al día.
    worst.title = "Fuga de información en app-siniestros por contraseña por defecto en el panel"
    worst.save(update_fields=["title"])
    assert business_risk_texts.queue_missing() == 0
    # Cambia la descripción de un activo: se vuelven a escribir los riesgos en que está.
    other.asset.description = "Los empleados descargan sus constancias de retención."
    other.asset.save(update_fields=["description"])
    assert business_risk_texts.queue_missing() == 2
    for found in BusinessRiskDescription.objects.all():
        assert "constancias de retención" in found.summary
    assert InferenceLog.objects.filter(task="ORG_RISK_DESCRIBE").count() == 4

    # Un riesgo que se queda sin escenarios abiertos ya no se pregunta.
    Risk.objects.filter(consequence=DOWN).update(status=RiskStatus.CLOSED)
    assert business_risk_texts.describe(DOWN, "API") is None
    assert business_risk_texts.queue_missing() == 0


def test_the_drain_takes_a_few_risks_per_pass_starting_with_the_most_serious():
    _organization()
    for index, (likelihood, impact) in enumerate([(1, 1), (5, 5), (3, 3)]):
        asset = AssetFactory(
            name=f"equipo-{index}", business_role=["PAGOS", "CORREO", "API"][index]
        )
        _scenario(asset, LEAK, likelihood, impact, "contraseña por defecto en el panel")
    assert business_risk_texts.queue_missing(limit=2) == 2
    assert set(BusinessRiskDescription.objects.values_list("role", flat=True)) == {"CORREO", "API"}
    assert business_risk_texts.queue_missing(limit=2) == 1


def test_after_a_failure_the_model_is_asked_again_with_another_draw(settings):
    """Con temperatura 0 el modelo responde lo mismo a la misma pregunta: repetirla igual
    repetiría el fallo."""
    _api_leak()
    key = _risk().key

    def last_options():
        options = InferenceLog.objects.order_by("-created_at").first().options
        return options["temperature"], options["seed"]

    business_risk_texts.describe(LEAK, "API")
    assert last_options() == (settings.LLM_TEMPERATURE, settings.LLM_SEED)
    business_risk_texts.note_failure(key)
    business_risk_texts.note_failure(key)
    business_risk_texts.describe(LEAK, "API")
    assert last_options() == (llm_client.RETRY_TEMPERATURE, settings.LLM_SEED + 2)
    # Un texto válido borra la cuenta: la siguiente pregunta vuelve a ser la de siempre.
    assert business_risk_texts.failures_of(key) == 0
    business_risk_texts.describe(LEAK, "API")
    assert last_options() == (settings.LLM_TEMPERATURE, settings.LLM_SEED)


def test_without_anything_to_go_on_the_page_keeps_the_general_meaning(client, as_role):
    as_role(ADMIN)
    OrganizationProfile.objects.update_or_create(pk=1, defaults={"name": "", "description": ""})
    profile.invalidate()
    bare = AssetFactory(name="caja-01", business_role="PAGOS", description="")
    _scenario(bare, LEAK, 3, 3, "contraseña por defecto en el panel")
    page = reverse("detection:business_risk", args=[LEAK, "PAGOS"])
    what = _what(client.get(page).content.decode())
    assert not BusinessRiskDescription.objects.exists() and not InferenceLog.objects.exists()
    assert business_risk_texts.queue_missing() == 0
    assert GENERAL.capitalize() + "." in what and "Es el significado general" in what
    assert "falta la descripción de los activos del riesgo" in what
    # La fila del sistema lo dice también, con el enlace para escribirla.
    ((name, row),) = _systems(client.get(page).content.decode())
    assert name == "caja-01" and "Sin descripción en el inventario: escríbela" in row
    # En cuanto alguien describe el activo, hay con qué.
    bare.description = "Terminal de cobro de la sucursal centro."
    bare.save(update_fields=["description"])
    assert business_risk_texts.queue_missing() == 1
    assert "sucursal centro" in BusinessRiskDescription.objects.get().summary


# --------------------------------------------------------------------------
# La respuesta del modelo va atada a los datos
# --------------------------------------------------------------------------


def test_the_sentence_must_say_what_would_be_lost_from_the_data():
    _api_leak()
    validator = business_risk_texts._validator(business_risk_texts.build_payload(_risk()), LEAK)
    good = (
        "Que la evidencia de las reclamaciones, con facturas médicas, y los recibos de nómina de "
        "los empleados queden a la vista de quien no debe."
    )
    assert validator.model_validate({"summary": f"**{good}**"}).summary == good
    for bad, why in (
        # El significado general, que es justo lo que resultaba corto y ambiguo.
        (
            good + " Es decir, que información que la organización debe proteger acabe fuera.",
            "quita «que información que la organización debe proteger acabe»",
        ),
        # «Información» a secas es lo que no decía nada.
        (
            "Que la información confidencial de la organización salga de app-siniestros y de "
            "portal-rh hacia terceros que no deben verla.",
            "con palabras de su what_it_is: ni «información» o «el servicio» a secas, ni lo que "
            "hace la organización en general. Por ejemplo, app-siniestros es «Los ajustadores "
            "suben la evidencia de cada reclamación: facturas médicas»",
        ),
        # Las debilidades y los ataques los escribe el código debajo, sistema por sistema.
        (
            good[:-1] + " por una falla de ejecución remota de código.",
            "no habla de debilidades, fallas ni ataques (la plataforma los muestra debajo, "
            "sistema por sistema): quita «una falla de»",
        ),
        (good + " Ya se usa en ataques reales.", "quita «en ataques reales»"),
        # La pérdida de este riesgo y no otra: en una fuga algo sale o queda a la vista.
        (
            "Que la evidencia de las reclamaciones, con facturas médicas, y los recibos de nómina "
            "de los empleados se cambien sin que nadie lo note.",
            "debe decir la pérdida de este riesgo: que algo sale o queda a la vista",
        ),
        (
            good[:-1] + ", y que el portal pueda caer.",
            "habla de otra pérdida (este riesgo no es una interrupción): quita «pueda caer». "
            "Aquí nada «cae» ni «deja de funcionar»; di solo que algo sale",
        ),
        # Una frase que no termina.
        (good[:-1], "quedó a media frase"),
        # El nivel lo pone el código al lado.
        (good + " Por eso el riesgo es crítico.", "quita riesgo es crítico"),
        (good + " También afecta a srv-nominas y a 4500 personas.", "srv-nominas"),
        (good + " También afecta a srv-nominas y a 4500 personas.", "4500"),
        (
            "The claims evidence and the payroll receipts of the employees could leak to people "
            "outside the company.",
            "español",
        ),
        ("Que salga información de app-siniestros.", "en una frase qué se perdería"),
        # Una frase, dos como mucho: los sistemas se listan aparte.
        (good + " " + " ".join([good] * 2), "no pasa de 340 caracteres"),
    ):
        with pytest.raises(ValidationError) as error:
            validator.model_validate({"summary": bad})
        assert why in str(error.value), (bad, str(error.value))
    # Todos los problemas de una respuesta se dicen juntos.
    with pytest.raises(ValidationError) as error:
        validator.model_validate(
            {
                "summary": "Que la información de la organización se altere por una "
                "vulnerabilidad, con un riesgo muy alto para sus 300 clientes"
            }
        )
    for part in (
        "quedó a media frase",
        "debe decir la pérdida de este riesgo",
        "(este riesgo no es una alteración): quita «se altere»",
        "quita «una vulnerabilidad»",
        "con palabras de su what_it_is",
        "riesgo muy alto",
        "300",
    ):
        assert part in str(error.value), part


def test_a_stray_accent_on_the_verb_is_removed_by_the_code():
    """«Que el servidor dejé de funcionar»: avisárselo al modelo no sirvió (repitió la misma
    frase los cuatro intentos), así que la tilde la quita el código."""
    from apps.llm.schemas import business_risk_validator

    _api_leak()
    validator = business_risk_texts._validator(business_risk_texts.build_payload(_risk()), LEAK)
    slip = (
        "Que la evidencia de las reclamaciones, con facturas médicas, y cada recibo de nómina de "
        "los empleados acabé en manos ajenas."
    )
    assert validator.model_validate({"summary": slip}).summary == slip.replace("acabé", "acabe")
    # «Esté» sí la lleva, y las palabras que acaban así sin ser verbos.
    kept = (
        "Que la evidencia de las reclamaciones, con facturas médicas, esté a la vista de quien "
        "no debe, igual que los recibos de nómina del comité."
    )
    assert validator.model_validate({"summary": kept}).summary == kept
    # Una palabra que viene de los datos se deja como está.
    about = "Bitácora de guardias que lleva Salomé: guarda los reportes de cada revisión."
    named = "Que los reportes de cada revisión de la bitácora de Salomé queden a la vista de otros."
    with_data = business_risk_validator(
        known_text=f"bitacora-01 {about}",
        systems=["bitacora-01"],
        about={"bitacora-01": about},
        loss=LEAK,
    )
    assert with_data.model_validate({"summary": named}).summary == named


def test_an_interruption_can_be_said_as_inaccessible_and_the_y_before_i_is_fixed_by_the_code():
    from apps.llm.schemas import _y_before_i, business_risk_validator

    about = (
        "Los ajustadores suben aquí la evidencia de cada reclamación: facturas médicas, fotos "
        "e identificaciones."
    )
    validator = business_risk_validator(
        known_text=f"app-siniestros {about}",
        systems=["app-siniestros"],
        about={"app-siniestros": about},
        loss="AVAILABILITY",
    )
    # «Quede inaccesible» se rechazaba doce veces seguidas por no decir «cae» ni «deja de».
    said = "Que la evidencia de cada reclamación que suben los ajustadores quede inaccesible."
    assert validator.model_validate({"summary": said}).summary == said
    slip = (
        "Que los ajustadores se queden sin subir la evidencia de cada reclamación: facturas "
        "médicas, fotos y identificaciones."
    )
    assert validator.model_validate({"summary": slip}).summary == slip.replace(
        "fotos y identificaciones", "fotos e identificaciones"
    )
    assert _y_before_i("cotizaciones y información") == "cotizaciones e información"
    assert (
        _y_before_i("el correo y Internet, padres y hijos")
        == "el correo e Internet, padres e hijos"
    )
    assert (
        _y_before_i("agua y hielo, cobre y hierro, hoy y ayer")
        == "agua y hielo, cobre y hierro, hoy y ayer"
    )


def test_a_word_that_only_exists_in_the_examples_of_the_prompt_is_not_accepted():
    """«Que las cajas y los equipos de la fuerza de ventas se queden sin conexión»: las cajas son
    de la cadena de farmacias del ejemplo, no de esta organización."""
    from apps.llm.prompts import load_prompt
    from apps.llm.schemas import business_risk_validator

    _api_leak()
    validator = business_risk_texts._validator(business_risk_texts.build_payload(_risk()), LEAK)
    copied = (
        "Que la evidencia de las reclamaciones, con facturas médicas, de las cajas de las "
        "sucursales quede a la vista de quien no debe."
    )
    with pytest.raises(ValidationError) as error:
        validator.model_validate({"summary": copied})
    assert "copia del ejemplo, que es de otra organización: quita «sucursal», «cajas»" in str(
        error.value
    )
    # Si la organización sí tiene sucursales y lo dicen sus datos, la palabra es suya.
    about = "Punto de venta de las sucursales: las cajas registran aquí cada cobro del día."
    own = "Que los cobros del día que registran las cajas de las sucursales queden a la vista."
    with_data = business_risk_validator(
        known_text=f"punto-venta {about}",
        systems=["punto-venta"],
        about={"punto-venta": about},
        loss=LEAK,
        from_examples=business_risk_texts.EXAMPLE_WORDS,
    )
    assert with_data.model_validate({"summary": own}).summary == own
    # La lista habla de los ejemplos que el modelo recibe: si cambian, cambia con ellos.
    examples = load_prompt("org_risk_describe", business_risk_texts.PROMPT_VERSION).lower()
    assert [word for word in business_risk_texts.EXAMPLE_WORDS if word not in examples] == []


def test_a_sentence_with_an_added_consequence_gets_another_draw(monkeypatch, settings):
    """La consecuencia que el modelo añade al final es donde inventa («…, dejando a los
    desarrolladores sin acceso para pruebas»): se le piden otras versiones y se prefiere la que
    termina en la pérdida."""
    from apps.llm.schemas import added_consequence

    for text, tail in (
        ("Que el correo deje de funcionar, dejando a los agentes sin avisos.", "dejando a los"),
        ("Que el proxy se altere, cambiándolo sin que nadie lo note.", "cambiándolo sin que"),
        ("Que los recibos queden a la vista, lo que afectaría a los empleados.", "lo que afect"),
        ("Que los recibos queden a la vista, sin que nadie lo sepa.", "sin que nadie"),
        ("Que el correo, cuando falle el respaldo, deje de funcionar.", ""),
        ("Que las recetas, con los datos de los pacientes, queden a la vista de otros.", ""),
    ):
        assert added_consequence(text).startswith(tail) and bool(added_consequence(text)) == bool(
            tail
        ), text

    _api_leak()
    clean = (
        "Que la evidencia de las reclamaciones, con facturas médicas, y los recibos de nómina de "
        "los empleados queden a la vista de quien no debe."
    )
    tails = [
        clean[:-1] + ", dejando a la aseguradora sin la confianza de sus empleados.",
        clean[:-1] + ", causando la desconfianza de sus empleados.",
        clean[:-1] + ", lo que molestaría a sus empleados.",
    ]

    def answering(*answers):
        left = list(answers)
        monkeypatch.setitem(
            llm_client.MOCK_GENERATORS,
            business_risk_texts.TASK,
            lambda _payload: {"summary": left.pop(0)},
        )
        InferenceLog.objects.all().delete()
        BusinessRiskDescription.objects.all().delete()
        business_risk_texts.describe(LEAK, "API")
        assert not left
        logs = InferenceLog.objects.filter(task="ORG_RISK_DESCRIBE").order_by("created_at")
        options = [(log.options["temperature"], log.options["seed"]) for log in logs]
        return BusinessRiskDescription.objects.get(), options

    again = (llm_client.RETRY_TEMPERATURE, settings.LLM_SEED + 1)
    usual = (settings.LLM_TEMPERATURE, settings.LLM_SEED)
    # Termina en la pérdida: una sola pregunta.
    found, options = answering(clean)
    assert found.summary == clean and options == [usual]
    # Trae una consecuencia añadida: otra tirada, y se queda la que termina en la pérdida.
    found, options = answering(tails[0], clean)
    assert found.summary == clean and options == [usual, again]
    assert found.inference.options["seed"] == settings.LLM_SEED + 1
    # Si todas la traen, se queda la primera: lo que repite suele salir de los datos.
    found, options = answering(*tails)
    assert found.summary == tails[0]
    assert options == [usual, again, (llm_client.RETRY_TEMPERATURE, settings.LLM_SEED + 2)]


def test_words_of_another_loss_or_of_weaknesses_are_allowed_when_the_data_brings_them():
    from apps.llm.schemas import business_risk_validator

    about = "Proxy de salida para los equipos de las sucursales: control y filtrado de contenido."

    def validator(loss):
        return business_risk_validator(
            known_text=f"proxy-saliente {about}",
            systems=["proxy-saliente"],
            about={"proxy-saliente": about},
            loss=loss,
        )

    good = "Que los equipos de las sucursales se queden sin salida ni filtrado de contenido."
    # «Filtrado» es de la descripción del proxy: no habla de una fuga.
    validator("AVAILABILITY").model_validate({"summary": good})
    with pytest.raises(ValidationError) as error:
        validator("AVAILABILITY").model_validate(
            {"summary": good[:-1] + ", y sus registros quedarían a la vista."}
        )
    assert "(este riesgo no es una fuga): quita «quedarian a la vista»" in str(error.value)
    assert "que algo cae o deja de funcionar" in str(error.value)
    # «Caer en manos ajenas» es una fuga, no una interrupción.
    validator(LEAK).model_validate(
        {
            "summary": "Que el control de contenido de los equipos de las sucursales pueda caer "
            "en manos ajenas."
        }
    )
    # Un sistema que trata de vulnerabilidades puede nombrarlas.
    scanner = "Escáner de vulnerabilidades de la red: guarda los reportes de cada revisión."
    business_risk_validator(
        known_text=f"escaner-01 {scanner}",
        systems=["escaner-01"],
        about={"escaner-01": scanner},
        loss=LEAK,
    ).model_validate(
        {
            "summary": "Que los reportes de vulnerabilidades de cada revisión salgan del escáner "
            "y lleguen a quien no debe."
        }
    )


def test_with_many_systems_the_page_lists_the_most_serious_and_folds_the_rest(client, as_role):
    as_role(AUDITOR)
    _organization()
    names = []
    for index in range(5):
        asset = AssetFactory(
            name=f"nodo-{index}",
            business_role="API",
            description=f"Guarda los contratos del distrito {'abcde'[index] * 6}.",
        )
        names.append(asset.name)
        _scenario(asset, LEAK, 5 - index, 5, "contraseña por defecto en el panel")
    payload = business_risk_texts.build_payload(_risk())
    assert [s["name"] for s in payload["systems_from_most_to_least_serious"]] == names
    validator = business_risk_texts._validator(payload, LEAK)
    validator.model_validate(
        {
            "summary": "Que los contratos del distrito aaaaaa y los del distrito cccccc queden a "
            "la vista de quien no debe."
        }
    )
    # El nombre de la organización no cuenta como «lo que guarda» un sistema, pero sus letras no
    # se llevan otras palabras: «asegurados» no es «Aseguradora Norte».
    from apps.llm.schemas import business_risk_validator

    files = "Guarda los expedientes de los asegurados."
    by_name = business_risk_validator(
        known_text=f"archivo-01 {files} Aseguradora Norte",
        systems=["archivo-01"],
        about={"archivo-01": files},
        organization="Aseguradora Norte",
        loss=LEAK,
    )
    by_name.model_validate(
        {"summary": "Que los expedientes de los asegurados queden a la vista de quien no debe."}
    )
    with pytest.raises(ValidationError):
        by_name.model_validate(
            {"summary": "Que los expedientes de Aseguradora Norte queden a la vista de otros."}
        )
    # Vale también si habla de lo que guarda otro sistema del riesgo: todos se listan debajo.
    validator.model_validate(
        {"summary": "Que los contratos del distrito dddddd queden a la vista de quien no debe."}
    )
    # La respuesta simulada cumple las mismas reglas que la del modelo.
    mock = business_risk_texts.mock_description(payload)
    assert "aaaaaa" in validator.model_validate(mock).summary
    # La página lista los tres más graves y pliega los demás.
    body = client.get(reverse("detection:business_risk", args=[LEAK, "API"])).content.decode()
    assert [name for name, _row in _systems(body)] == names
    assert "<summary>y 2 más</summary>" in body
    assert (
        body.index("nodo-2</a>")
        < body.index("<summary>y 2 más</summary>")
        < body.index("nodo-3</a>")
    )


# --------------------------------------------------------------------------
# Mientras se escribe, y cuando una persona lo corrige
# --------------------------------------------------------------------------


def test_while_the_model_writes_the_page_shows_the_general_meaning_and_checks_by_itself(
    client, as_role, monkeypatch
):
    as_role(AUDITOR)
    _api_leak()
    monkeypatch.setattr(tasks.describe_business_risk, "apply_async", lambda *a, **k: None)
    page = reverse("detection:business_risk", args=[LEAK, "API"])
    part = reverse("detection:business_risk_text", args=[LEAK, "API"])
    what = _what(client.get(page).content.decode())
    assert business_risk_texts.is_pending(f"{LEAK}:API")
    assert GENERAL.capitalize() + "." in what and "la IA está redactando" in what
    polling = f'hx-get="{part}" hx-trigger="every 5s" hx-swap="outerHTML"'
    assert (
        polling in client.get(page).content.decode()
        and polling in client.get(part).content.decode()
    )
    assert not business_risk_texts.request(_risk())  # no se encola dos veces
    business_risk_texts.describe(LEAK, "API")
    fragment = client.get(part).content.decode()
    assert BusinessRiskDescription.objects.get().summary in fragment and "hx-get" not in fragment
    # Un riesgo que no existe no tiene bloque.
    assert (
        client.get(reverse("detection:business_risk_text", args=[DOWN, "API"])).status_code == 404
    )
    assert (
        client.get(reverse("detection:business_risk_text", args=["OTRA", "API"])).status_code == 404
    )


def test_a_person_can_correct_it_and_is_told_when_the_risk_changed_afterwards(client, as_role):
    operator = as_role(OPERATOR)
    worst, _other = _api_leak()
    page = reverse("detection:business_risk", args=[LEAK, "API"])
    write = reverse("detection:business_risk_text", args=[LEAK, "API"])
    assert "Corregir el texto" in _what(client.get(page).content.decode())
    text = "Que los expedientes de siniestros de los asegurados salgan de app-siniestros."
    response = client.post(write, {"summary": text, "next": page}, follow=True)
    assert response.redirect_chain[-1][0] == page
    assert "guardado a tu nombre" in response.content.decode()
    found = BusinessRiskDescription.objects.get()
    assert (found.source, found.summary, found.edited_by) == ("HUMAN", text, operator)
    what = _what(response.content.decode())
    assert text in what and "por una persona" in what and "Desde entonces" not in what
    # Lo que escribió una persona la IA no lo toca, cambie lo que cambie; la página avisa.
    worst.asset.description = "Los ajustadores suben fotos de cada siniestro."
    worst.asset.save(update_fields=["description"])
    assert business_risk_texts.describe(LEAK, "API") is None
    assert business_risk_texts.queue_missing() == 0
    assert BusinessRiskDescription.objects.get().summary == text
    assert "Desde entonces cambiaron" in _what(client.get(page).content.decode())
    # Con el texto vacío vuelve a escribirlo la IA.
    client.post(write, {"summary": " ", "next": page})
    assert BusinessRiskDescription.objects.get().source == "AI"
    as_role(AUDITOR)
    assert client.post(write, {"summary": "otra cosa"}).status_code == 403
    assert BusinessRiskDescription.objects.get().source == "AI"


def test_assets_without_a_function_have_their_text_too(client, as_role):
    as_role(AUDITOR)
    _organization()
    loose = AssetFactory(
        name="suelto-01", business_role="", description="Equipo de pruebas del área de sistemas."
    )
    _scenario(loose, DOWN, 2, 2, "contraseña por defecto en el panel")
    page = reverse("detection:business_risk", args=[DOWN, business_risks.NO_ROLE])
    what = _what(client.get(page).content.decode())
    found = BusinessRiskDescription.objects.get()
    assert (found.consequence, found.role) == (DOWN, "")
    assert found.summary in what and "equipo de pruebas del área" in found.summary
    body = client.get(page).content.decode()
    assert "En un activo sin función de negocio definida." in body
    assert [name for name, _row in _systems(body)] == ["suelto-01"]
    payload = json.dumps(business_risk_texts.build_payload(_risk(DOWN, business_risks.NO_ROLE)))
    assert '"business_function": null' in payload

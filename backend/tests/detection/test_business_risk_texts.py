"""«Qué puede pasar» en un riesgo de la organización, dicho con sus sistemas (2026-11-18).

La página de un riesgo decía solo el significado general de la consecuencia («Fuga de información
en API: que información que la organización debe proteger acabe en manos ajenas»): corto y
ambiguo. Ahora lo dice el sistema para cada riesgo, también para los que aparezcan después: dos o
tres frases que la IA arma con la descripción de los activos del riesgo, sus datos y la causa de
cada escenario, atadas a esos datos por un validador.

Sin red, sin LLM real (modo simulado) y sin herramientas.
"""

import json

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


# --------------------------------------------------------------------------
# La página del riesgo
# --------------------------------------------------------------------------


def test_the_risk_page_says_what_can_happen_with_its_own_systems(client, as_role):
    as_role(AUDITOR)
    _api_leak()
    page = reverse("detection:business_risk", args=[LEAK, "API"])
    body = client.get(page).content.decode()
    what = _what(body)

    # Lo escribe el sistema al abrir la página: nadie lo redactó a mano.
    found = BusinessRiskDescription.objects.get()
    assert (found.consequence, found.role, found.source) == (LEAK, "API", "AI")
    assert found.prompt_version == business_risk_texts.PROMPT_VERSION
    # Dice qué se pierde, en qué sistemas (el más grave primero) y por dónde.
    for part in ("app-siniestros", "ajustadores suben la evidencia", "pillow 8.1.0", "portal-rh"):
        assert part in found.summary, part
    assert found.summary in what and "por IA" in what and "Puede equivocarse" in what
    # El significado general, que antes era todo, queda de referencia debajo.
    assert f"En general: {GENERAL}." in what and what.index(found.summary) < what.index(GENERAL)
    # Dónde y por qué ese nivel siguen saliendo del código.
    assert "Qué puede pasar" in body and "con la función «API»" in body
    assert "es el de su peor escenario, app-siniestros" in body
    assert "Corregir el texto" not in what  # quien solo lee no lo corrige
    # Abrir la página otra vez no vuelve a preguntar.
    client.get(page)
    assert InferenceLog.objects.filter(task="ORG_RISK_DESCRIBE").count() == 1


def test_the_model_gets_each_system_and_its_cause_without_the_counts_that_move():
    worst, _other = _api_leak()
    payload = business_risk_texts.build_payload(_risk())
    assert payload["risk"] == {
        "name": "Fuga de información en API",
        "what_is_lost": "Fuga de información",
        "general_meaning": GENERAL,
        "business_function": "API",
    }
    assert payload["organization"]["name"] == "Aseguradora Norte"
    assert payload["how_many_systems"] == 2
    # Del más grave al menos, cada uno con lo que es, dónde está, sus datos y su causa.
    assert payload["systems_from_most_to_least_serious"] == [
        {
            "name": "app-siniestros",
            "what_it_is": "Los ajustadores suben la evidencia de cada reclamación: facturas médicas.",
            "where": "en la red interna",
            "reachable_from_outside": False,
            "data": "información restringida, la más sensible: datos personales, clínicos",
            "main_weakness": "ejecución remota de código en pillow 8.1.0",
            "has_weaknesses_already_used_in_real_attacks": True,
        },
        {
            "name": "portal-rh",
            "what_it_is": "Los empleados consultan sus recibos de nómina y piden vacaciones.",
            "where": "en la DMZ (la zona que da la cara a Internet)",
            "reachable_from_outside": True,
            "data": "información confidencial: datos personales, financieros",
            "main_weakness": "recorrido de rutas en Apache httpd 2.4.49",
            # Sin la bandera cuando no aplica: con un «false» el modelo decía que el sistema
            # «no tiene debilidades conocidas».
        },
    ]
    before = business_risk_texts.fingerprint(payload)
    # Un escaneo que solo cambia cuántas vulnerabilidades hay no cambia lo que puede pasar…
    worst.title = worst.title.replace("24 vulnerabilidades", "31 vulnerabilidades")
    worst.save(update_fields=["title"])
    assert business_risk_texts.fingerprint(business_risk_texts.build_payload(_risk())) == before
    # …ni un título que se cortó a media frase, ni el conteo de debilidades de configuración.
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
    # Otra causa principal sí.
    worst.title = "Fuga de información en app-siniestros por contraseña por defecto en el panel"
    worst.save(update_fields=["title"])
    assert business_risk_texts.fingerprint(business_risk_texts.build_payload(_risk())) != before


# --------------------------------------------------------------------------
# Riesgos nuevos: lo hace el sistema, sin que nadie abra la página
# --------------------------------------------------------------------------


def test_a_new_risk_gets_its_text_from_the_periodic_drain_and_is_rewritten_when_it_changes():
    worst, other = _api_leak()
    assert tasks.describe_pending_vulnerabilities()["risks"] == 1
    first = BusinessRiskDescription.objects.get()
    assert "app-siniestros" in first.summary and "pillow" in first.summary
    assert "risks" not in tasks.describe_pending_vulnerabilities()  # al día: no se pregunta

    # Aparece un riesgo que no existía (otra consecuencia sobre la misma función).
    _scenario(other.asset, DOWN, 4, 4, "denegación de servicio en Apache httpd 2.4.49")
    assert tasks.describe_pending_vulnerabilities()["risks"] == 1
    down = BusinessRiskDescription.objects.get(consequence=DOWN)
    assert down.role == "API" and "portal-rh" in down.summary and "denegación" in down.summary

    # Cambia la causa principal de un escenario: su riesgo se vuelve a escribir, el otro no.
    worst.title = "Fuga de información en app-siniestros por contraseña por defecto en el panel"
    worst.save(update_fields=["title"])
    assert business_risk_texts.queue_missing() == 1
    assert "contraseña por defecto" in BusinessRiskDescription.objects.get(consequence=LEAK).summary
    assert InferenceLog.objects.filter(task="ORG_RISK_DESCRIBE").count() == 3

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
    assert last_options() == (business_risk_texts.RETRY_TEMPERATURE, settings.LLM_SEED + 2)
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
    # En cuanto alguien describe el activo, hay con qué.
    bare.description = "Terminal de cobro de la sucursal centro."
    bare.save(update_fields=["description"])
    assert business_risk_texts.queue_missing() == 1
    assert "sucursal centro" in BusinessRiskDescription.objects.get().summary


# --------------------------------------------------------------------------
# La respuesta del modelo va atada a los datos
# --------------------------------------------------------------------------


def test_the_answer_must_say_what_where_and_how_from_the_data():
    _api_leak()
    validator = business_risk_texts._validator(business_risk_texts.build_payload(_risk()), LEAK)
    good = (
        "Que la evidencia de las reclamaciones, con facturas médicas, salga de app-siniestros por "
        "una falla de ejecución remota de código en pillow 8.1.0, de las que ya se usan en ataques "
        "reales. También quedarían a la vista los recibos de nómina de los empleados en portal-rh, "
        "que está en la DMZ."
    )
    assert validator.model_validate({"summary": f"**{good}**"}).summary == good
    for bad, why in (
        # El significado general, que es justo lo que resultaba corto y ambiguo.
        (
            good + " Es decir, que información que la organización debe proteger acabe fuera.",
            "quita «que información que la organización debe proteger acabe»",
        ),
        # Siempre el sistema del escenario más grave, y con dos sistemas, los dos.
        (
            "Que los recibos de nómina de los empleados salgan de portal-rh por un recorrido de "
            "rutas en Apache httpd 2.4.49, alcanzable desde la DMZ de la organización.",
            "faltan: app-siniestros",
        ),
        # Nombrarlos no basta: «información» a secas es lo que no decía nada.
        (
            "Que la información confidencial de la organización salga de app-siniestros y de "
            "portal-rh por una falla de ejecución remota de código que alguien de fuera aproveche.",
            "falta decirlo de: app-siniestros (es «Los ajustadores suben la evidencia de cada reclamación:…»), "
            "portal-rh (es «Los empleados consultan sus recibos de nómina y…»)",
        ),
        # Por dónde: la clase de debilidad de al menos un sistema.
        (
            "Que la evidencia de las reclamaciones, con facturas médicas, salga de app-siniestros "
            "y que los recibos de nómina de los empleados salgan de portal-rh hacia terceros.",
            "debe decir por dónde",
        ),
        # Cada debilidad con su sistema: el recorrido de rutas es de portal-rh.
        (
            "Que la evidencia de las reclamaciones, con facturas médicas, salga de app-siniestros "
            "por un recorrido de rutas en Apache httpd 2.4.49. También quedarían a la vista los "
            "recibos de nómina de los empleados en portal-rh, que está en la DMZ.",
            "le atribuye a app-siniestros la debilidad de portal-rh («recorrido de rutas en Apache "
            "httpd 2.4.49»); la de app-siniestros es «ejecución remota de código en pillow 8.1.0»",
        ),
        # «Ya se usa en ataques reales» solo del sistema del que los datos lo dicen.
        (
            good + " Las fallas de portal-rh ya se usan en ataques reales.",
            "no dice de portal-rh que sus debilidades ya se usan en ataques reales",
        ),
        # El sistema alcanzable desde fuera se nombra y se dice: es lo que lo hace más probable.
        (
            good.replace(", que está en la DMZ", ""),
            "debe nombrar portal-rh y decir que es alcanzable",
        ),
        # La pérdida de este riesgo y no otra: en una fuga algo sale o queda a la vista.
        (
            "Que la evidencia de las reclamaciones, con facturas médicas, se falsee en "
            "app-siniestros por una falla de ejecución remota de código en pillow 8.1.0, y los "
            "recibos de nómina de los empleados en portal-rh, que está en la DMZ.",
            "debe decir la pérdida de este riesgo: que algo sale o queda a la vista",
        ),
        # Ni las palabras de otra pérdida: un sistema que «puede caer» es una interrupción.
        (
            good.replace("salga de app-siniestros", "salga de app-siniestros, que puede caer,"),
            "habla de otra pérdida (este riesgo no es una interrupción): quita «puede caer». Aquí de "
            "un sistema di que «tiene» la debilidad, no que «cae»; di solo que algo sale",
        ),
        # El software solo no dice por dónde: hace falta la clase de debilidad.
        (
            "Que la evidencia de las reclamaciones, con facturas médicas, salga de app-siniestros "
            "por una debilidad en pillow 8.1.0. También quedarían a la vista los recibos de "
            "nómina de los empleados en portal-rh, que está en la DMZ, por otra en Apache httpd.",
            "no basta el nombre del software); la de app-siniestros es «ejecución remota de código»",
        ),
        # Una respuesta que llegó al tope y quedó a media frase.
        (good[:-14], "quedó a media frase"),
        # El nivel lo pone el código al lado.
        (good + " Por eso el riesgo es crítico.", "quita riesgo es crítico"),
        (good + " También afecta a srv-nominas y a 4500 personas.", "srv-nominas"),
        (good + " También afecta a srv-nominas y a 4500 personas.", "4500"),
        (
            "The claims evidence could leak from app-siniestros and portal-rh through a remote code "
            "execution flaw in pillow 8.1.0 that is already used in real attacks.",
            "español",
        ),
        ("Que salga información de app-siniestros.", "dos o tres frases"),
    ):
        with pytest.raises(ValidationError) as error:
            validator.model_validate({"summary": bad})
        assert why in str(error.value), (bad, str(error.value))
    # Todos los problemas de una respuesta se dicen juntos.
    with pytest.raises(ValidationError) as error:
        validator.model_validate(
            {
                "summary": "Que la información de la organización salga de portal-rh hacia "
                "terceros, con un riesgo muy alto para sus 300 clientes y para sus agentes."
            }
        )
    for part in (
        "faltan: app-siniestros",
        "falta decirlo de",
        "por dónde",
        "alcanzable desde fuera",
        "riesgo muy alto",
        "300",
    ):
        assert part in str(error.value), part


def test_it_summarizes_each_system_instead_of_copying_its_description():
    from apps.llm.schemas import business_risk_validator

    long = (
        "Aplicación interna donde los ajustadores suben y procesan la evidencia de cada "
        "reclamación de gastos médicos de los asegurados."
    )
    cause = "ejecución remota de código en pillow 8.1.0"
    validator = business_risk_validator(
        systems=["app-siniestros"],
        known_text=f"app-siniestros {cause}",
        about={"app-siniestros": long},
        causes={"app-siniestros": cause},
        loss=LEAK,
    )
    validator.model_validate(
        {
            "summary": "Que la evidencia de las reclamaciones de gastos médicos salga de "
            f"app-siniestros por una falla de {cause}."
        }
    )
    with pytest.raises(ValidationError) as error:
        validator.model_validate(
            {
                "summary": f"Que salga lo de app-siniestros, una {long.lower()[:-1]}, por una "
                f"falla de {cause}."
            }
        )
    assert "no copia la descripción de app-siniestros" in str(error.value)
    assert "di en pocas palabras" in str(error.value)


def test_the_words_of_another_loss_are_allowed_only_when_the_data_brings_them():
    from apps.llm.schemas import business_risk_validator

    about = "Proxy de salida para los equipos de las sucursales: control y filtrado de contenido."
    cause = "denegación de servicio mediante ICP en Squid http proxy 6.13"
    validator = business_risk_validator(
        systems=["proxy-saliente"],
        known_text=f"proxy-saliente {cause}",
        about={"proxy-saliente": about},
        causes={"proxy-saliente": cause},
        loss="AVAILABILITY",
    )
    good = (
        "Que los equipos de las sucursales se queden sin salida: proxy-saliente, que hace el "
        "filtrado de contenido, puede caer por una denegación de servicio mediante ICP en Squid."
    )
    # «Filtrado» es de la descripción del proxy: no habla de una fuga.
    validator.model_validate({"summary": good})
    with pytest.raises(ValidationError) as error:
        validator.model_validate({"summary": good[:-1] + ", y sus registros quedarían a la vista."})
    assert "(este riesgo no es una fuga): quita «quedarian a la vista»" in str(error.value)
    assert "que algo cae o deja de funcionar" in str(error.value)
    # «Caer en manos ajenas» es una fuga, no una interrupción.
    leak = business_risk_validator(
        systems=["proxy-saliente"],
        known_text=f"proxy-saliente {cause}",
        about={"proxy-saliente": about},
        causes={"proxy-saliente": cause},
        loss=LEAK,
    )
    leak.model_validate(
        {
            "summary": "Que el control de contenido de los equipos de las sucursales pueda "
            "caer en manos ajenas: proxy-saliente tiene una falla de denegación de servicio "
            "mediante ICP en Squid."
        }
    )


def test_with_many_systems_it_names_three_and_always_the_most_serious():
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
    text = (
        "Que los contratos de los distritos salgan de {} por la contraseña por defecto de su "
        "panel, que cualquiera que llegue a ellos puede probar sin esfuerzo alguno."
    )
    validator.model_validate({"summary": text.format("nodo-0, nodo-3 y nodo-4")})
    with pytest.raises(ValidationError) as error:
        validator.model_validate({"summary": text.format("nodo-1, nodo-2 y nodo-3")})
    assert "siempre el primero (nodo-0)" in str(error.value)
    assert "faltan: nodo-0" in str(error.value)
    # La respuesta simulada cumple las mismas reglas que la del modelo.
    mock = business_risk_texts.mock_description(payload)
    assert validator.model_validate(mock).summary.count("nodo-") == 3


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
    worst.title = "Fuga de información en app-siniestros por contraseña por defecto en el panel"
    worst.save(update_fields=["title"])
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
    assert found.summary in what and "suelto-01" in found.summary
    payload = json.dumps(business_risk_texts.build_payload(_risk(DOWN, business_risks.NO_ROLE)))
    assert '"business_function": null' in payload

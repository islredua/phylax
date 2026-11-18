"""La corrección como eje de las vulnerabilidades (2026-11-18).

Toda vulnerabilidad tiene exactamente una corrección: actualizar un software (que resuelve todas
las de ese software en el activo) o cambiar una configuración (que resuelve una). La página de la
corrección dice qué hacer, qué es el software, por qué importa y a qué riesgo alimenta; solo «Qué
es» lo escribe la IA. La versión a la que hay que llegar la pone el código.

Sin red, sin LLM real (modo simulado) y sin herramientas.
"""

import json

import pytest
from django.urls import reverse
from django.utils import timezone
from pydantic import ValidationError

from apps.accounts.roles import ADMIN, AUDITOR, OPERATOR
from apps.detection import corrections, descriptions, grouping, software, titles
from apps.detection.models import (
    ComponentSource,
    Finding,
    FindingEvidence,
    FindingSource,
    Risk,
    RiskConsequence,
    SoftwareComponent,
    SoftwareDescription,
    StatusSource,
    Vulnerability,
    VulnerabilityStatus,
    risk_level_for,
)
from apps.llm.models import InferenceLog
from apps.llm.schemas import SoftwareDescribeOutput
from tests.factories import AssetFactory

pytestmark = pytest.mark.django_db
RCE = "Ejecución remota de código en log4j-core 2.14.1"


@pytest.fixture(autouse=True)
def _setup(settings):
    from django.core.cache import cache

    cache.clear()
    settings.LLM_MOCK_MODE = True


@pytest.fixture
def as_role(client, make_user):
    def login(role):
        user = make_user(role, mfa=role == ADMIN)
        client.force_login(user)
        return user

    return login


def _software(asset, name="log4j-core", version="2.14.1", **extra):
    return SoftwareComponent.objects.create(
        asset=asset,
        name=name,
        version=version,
        fingerprint=f"{name}-{version}-{extra.get('port', '')}",
        **{
            "source": ComponentSource.SBOM,
            "product_key": name,
            "purl": f"pkg:maven/org.example/{name}@{version}",
            **extra,
        },
    )


def _vuln(asset, key, title, component=None, *, fix=None, **extra):
    """Una vulnerabilidad con su reporte; ``fix`` es lo que dijo Grype («fixed 2.15.0»)."""
    now = timezone.now()
    vuln = Vulnerability.objects.create(
        asset=asset,
        key=key,
        title=title,
        component=component,
        first_detected_at=now,
        last_seen_at=now,
        **{
            "severity": "HIGH",
            "status": VulnerabilityStatus.CONFIRMED,
            "status_source": StatusSource.AI,
            "contextual_score": 7.0,
            "summary": f"Qué es {key}.",
            "description_source": StatusSource.AI,
            **extra,
        },
    )
    report = Finding.objects.create(
        asset=asset,
        vulnerability_id=key,
        title=key,
        component=component,
        sources=[FindingSource.GRYPE if component else FindingSource.NUCLEI],
        first_detected_at=now,
        last_seen_at=now,
        consolidated=vuln,
    )
    if fix:
        FindingEvidence.objects.create(
            finding=report,
            source=FindingSource.GRYPE,
            summary="Grype",
            data={"fix": fix},
            observed_at=now,
        )
    return vuln


def _payments():
    """Un activo con tres fallas de log4j-core (dos se llaman igual), una de configuración y un
    CVE de un software que su inventario no tiene."""
    asset = AssetFactory(
        name="api-pagos", business_role="PAGOS", criticality="CRITICO", exposure="DMZ"
    )
    log4j = _software(asset)
    return {
        "asset": asset,
        "log4j": log4j,
        "shell": _vuln(
            asset,
            "CVE-2021-44228",
            RCE,
            log4j,
            fix="fixed 2.15.0",
            contextual_score=9.6,
            severity="CRITICAL",
            in_kev=True,
            kev_due_at=timezone.localdate() - timezone.timedelta(days=30),
            summary="Permite a alguien de fuera ejecutar sus propias instrucciones en el servidor.",
            business_impact="Podrían leerse o alterarse los pagos.",
            actions=[
                "Aplicar la actualización a la versión 2.15.0 o superior.",
                "Comprobar el aviso del fabricante y seguir sus recomendaciones.",
                "Verificar que la versión instalada del paquete es 2.14.1.",
                "Realizar un nuevo escaneo para confirmar que quedó corregida.",
            ],
        ),
        "shell_2": _vuln(asset, "CVE-2021-45046", RCE, log4j, fix="fixed 2.16.0, 2.12.2"),
        "loop": _vuln(
            asset,
            "CVE-2021-44832",
            "Carga de configuración remota en log4j-core 2.14.1",
            log4j,
            fix="fixed 2.17.1",
            severity="MEDIUM",
            contextual_score=6.3,
        ),
        "headers": _vuln(
            asset,
            "WEAKNESS:CABECERAS_HTTP",
            "Cabeceras de seguridad HTTP ausentes en api-pagos",
            severity="LOW",
            contextual_score=3.1,
            actions=["Añadir las cabeceras HSTS y CSP.", "Deshabilitar TLS 1.0 y 1.1."],
        ),
        "phpunit": _vuln(asset, "CVE-2017-9841", "Ejecución remota de código en phpunit"),
    }


# --------------------------------------------------------------------------
# El eje es la corrección, no el software
# --------------------------------------------------------------------------


def test_every_vulnerability_has_one_correction_and_software_is_only_one_kind(client, as_role):
    as_role(OPERATOR)
    made = _payments()
    asset, log4j = made["asset"], made["log4j"]

    response = client.get("/detection/vulnerabilities/")
    body = response.content.decode()
    rows = {g["key"]: g for g in response.context["groups"]}
    # Cinco vulnerabilidades, tres correcciones: ninguna queda fuera ni se cuenta dos veces.
    assert response.context["total_vulnerabilities"] == 5 == sum(g["total"] for g in rows.values())
    assert response.context["total_groups"] == 3 == len(rows)
    assert "5 en 3 correcciones" in " ".join(body.split())

    update = rows[grouping.group_key(asset.pk, log4j.pk)]
    assert (update["type"], update["total"], update["kev"]) == (grouping.UPDATE, 3, 1)
    # La versión es la mayor de las que piden sus fallas: la que las resuelve todas.
    assert update["action"] == "Actualizar log4j-core 2.14.1 a 2.17.1 o superior"
    assert update["detail"] == "corrige las 3 · Grype"
    assert update["url"] == reverse("detection:correction", args=[asset.pk, log4j.pk])

    # Una debilidad sin CVE ni software no es «software sin identificar»: es de configuración, es
    # su propia corrección y la fila lleva a ella.
    config = rows[grouping.group_key(asset.pk, None, made["headers"].pk)]
    assert (config["type"], config["total"]) == (grouping.CONFIG, 1)
    assert config["action"] == made["headers"].title and config["detail"] == ""
    assert config["url"] == reverse("detection:vulnerability", args=[made["headers"].pk])

    # Un CVE siempre es de un software, aunque el inventario del activo no lo tenga.
    loose = rows[grouping.group_key(asset.pk, None, made["phpunit"].pk)]
    assert loose["type"] == grouping.UPDATE and loose["detail"] == grouping.OUT_OF_INVENTORY

    for text in (
        "Por corrección",
        "Actualizar software",
        "Cambiar configuración",
        "Actualizar log4j-core 2.14.1 a 2.17.1 o superior",
        "El inventario del activo no tiene este software",
    ):
        assert text in body, text
    assert "Sin software identificado" not in body

    assert grouping.correction_type(log4j.pk, None) == grouping.UPDATE
    assert grouping.correction_type(None, "CVE-2017-9841") == grouping.UPDATE
    assert grouping.correction_type(None, None, "GHSA-4fx9-vc88-q2xc") == grouping.UPDATE
    assert grouping.correction_type(None, None, "WEAKNESS:SOFTWARE_SIN_SOPORTE") == grouping.CONFIG


def test_marking_a_correction_reaches_its_vulnerabilities_and_only_those(client, as_role):
    as_role(OPERATOR)
    made = _payments()
    asset = made["asset"]
    qs = Vulnerability.objects.all()
    single = grouping.group_key(asset.pk, None, made["headers"].pk)
    assert grouping.parse_key(single) == (asset.pk, None, made["headers"].pk)
    assert grouping.members(qs, [single]) == [made["headers"].pk]
    software_key = grouping.group_key(asset.pk, made["log4j"].pk)
    assert set(grouping.members(qs, [software_key])) == {
        made["shell"].pk,
        made["shell_2"].pk,
        made["loop"].pk,
    }
    # La clave de antes («todas las del activo sin software») sigue valiendo para un envío viejo.
    assert set(grouping.members(qs, [f"{asset.pk}:none"])) == {
        made["headers"].pk,
        made["phpunit"].pk,
    }
    assert grouping.parse_key(f"{asset.pk}:{made['log4j'].pk}:{made['headers'].pk}") is None

    response = client.post(
        "/detection/vulnerabilities/bulk/",
        {
            "groups": [single],
            "query": "",
            "status": "FALSE_POSITIVE",
            "note": "lo pone el balanceador",
        },
        follow=True,
    )
    assert "1 vulnerabilidad de 1 corrección → " in response.content.decode()
    made["headers"].refresh_from_db()
    assert made["headers"].status == VulnerabilityStatus.FALSE_POSITIVE
    assert Vulnerability.objects.filter(status_source=StatusSource.HUMAN).count() == 1


# --------------------------------------------------------------------------
# La página de la corrección
# --------------------------------------------------------------------------


def test_the_correction_page_says_what_to_do_what_it_is_why_and_what_it_feeds(client, as_role):
    as_role(AUDITOR)
    made = _payments()
    asset, log4j = made["asset"], made["log4j"]
    scenario = Risk.objects.create(
        asset=asset,
        key=RiskConsequence.CONFIDENTIALITY,
        consequence=RiskConsequence.CONFIDENTIALITY,
        title="Fuga de información en api-pagos",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=5,
        impact=5,
        level=risk_level_for(5, 5),
        first_identified_at=timezone.now(),
    )
    scenario.vulnerabilities.add(made["shell"], made["loop"])

    response = client.get(reverse("detection:correction", args=[asset.pk, log4j.pk]))
    assert response.status_code == 200
    card = response.context["card"]
    body = " ".join(response.content.decode().split())

    # Qué hacer: la versión sale de Grype, y es la mayor de las que pide cada falla.
    assert card["fix"] == {
        "version": "2.17.1",
        "covered": 3,
        "total": 3,
        "missing": 0,
        "unfixed": 0,
        "source": "Grype",
    }
    assert "Actualizar a la versión <strong" in body and ">2.17.1</strong> o superior" in body
    assert "Corrige sus 3 vulnerabilidades abiertas" in body and "no de la IA" in body
    assert [(v.key, v.fix["version"]) for v in card["vulnerabilities"]] == [
        ("CVE-2021-44228", "2.15.0"),
        ("CVE-2021-45046", "2.16.0"),  # 2.12.2 es de otra rama: no supera a la instalada
        ("CVE-2021-44832", "2.17.1"),
    ]
    # Qué es: lo único que escribe la IA; al abrir la página queda pedido y escrito.
    assert card["what"].source == "AI" and "log4j-core es un programa" in card["what"].summary
    assert "Qué es log4j-core" in body and "por IA" in body
    # Por qué importa: con los datos, y lo que permite la más grave con su descripción.
    assert card["why"] == [
        "1 de sus 3 vulnerabilidades ya se usan en ataques reales (catálogo KEV de CISA); "
        "el plazo que CISA fijó para corregirlas ya venció.",
        "Está en api-pagos, un activo crítico, en la DMZ (la zona que da la cara a Internet).",
        "La más grave tiene puntaje contextual 9.6 (crítica).",
    ]
    assert "Lo más grave que permite" in body and made["shell"].summary in body
    # A qué riesgo alimenta: el escenario del activo y el riesgo de la organización.
    assert [item["scenario"].pk for item in card["feeds"]] == [scenario.pk]
    assert "Fuga de información en Pagos" in body
    assert reverse("detection:risk", args=[scenario.pk]) in body
    # Evidencia: quién lo reportó, y a un clic lo que dijo cada herramienta.
    assert card["evidence"]["reports"] == 3 and card["evidence"]["sources"] == [("GRYPE", 3)]
    assert "Ver los 3 reportes de las herramientas" in body
    listed = client.get(card["evidence"]["url"])
    assert listed.status_code == 200 and listed.context["paginator"].count == 3
    # Quien solo lee no ve el formulario de estado ni el de la descripción.
    assert 'name="groups"' not in body and "Corregir la descripción" not in body

    # Un software sin vulnerabilidades en ese activo no tiene corrección; el de otro activo, tampoco.
    other = AssetFactory(name="otro")
    clean = _software(other, name="flask", version="3.0.3")
    assert client.get(reverse("detection:correction", args=[other.pk, clean.pk])).status_code == 404
    assert client.get(reverse("detection:correction", args=[other.pk, log4j.pk])).status_code == 404


def test_a_correction_is_decided_for_all_its_vulnerabilities_from_its_page(client, as_role):
    operator = as_role(OPERATOR)
    made = _payments()
    asset, log4j = made["asset"], made["log4j"]
    page = reverse("detection:correction", args=[asset.pk, log4j.pk])
    body = client.get(page).content.decode()
    assert f'name="groups" value="{asset.pk}:{log4j.pk}"' in body and "Fijar en las 3" in body

    response = client.post(
        "/detection/vulnerabilities/bulk/",
        {"groups": [f"{asset.pk}:{log4j.pk}"], "query": "", "status": "MITIGATED", "next": page},
        follow=True,
    )
    assert response.redirect_chain[-1][0] == page
    assert set(
        Vulnerability.objects.filter(component=log4j).values_list("status", "status_by")
    ) == {(VulnerabilityStatus.MITIGATED, operator.pk)}
    # Ya no queda nada abierto: la página lo dice y conserva lo resuelto.
    body = " ".join(response.content.decode().split())
    assert "Nada pendiente" in body and "Ya resueltas o descartadas" in body
    # Y la corrección sale de la lista de abiertas, que sigue contando lo demás.
    listed = client.get("/detection/vulnerabilities/")
    assert listed.context["total_vulnerabilities"] == 2 == listed.context["total_groups"]


def test_a_software_with_no_known_fix_says_so_instead_of_a_version(client, as_role):
    as_role(OPERATOR)
    asset = AssetFactory(name="proxy")
    squid = _software(
        asset,
        name="squid",
        version="6.13",
        source=ComponentSource.SERVICE,
        port=3128,
        protocol="tcp",
        purl="",
    )
    _vuln(asset, "CVE-2026-0001", "Desbordamiento en squid 6.13", squid, fix="not-fixed")
    _vuln(asset, "CVE-2026-0002", "Fuga de memoria en squid 6.13", squid)
    row = client.get("/detection/vulnerabilities/").context["groups"][0]
    assert row["action"] == "squid 6.13: sin corrección publicada"
    assert row["detail"] == "para 1 de 2: mitigar o aceptar" and row["where"] == "3128/tcp"
    body = " ".join(client.get(row["url"]).content.decode().split())
    assert "Sin corrección publicada." in body and "mitigar" in body
    assert 'responde en <span class="font-mono">3128/tcp</span>' in body
    # Sin dato de nadie no se inventa una versión.
    Vulnerability.objects.filter(key="CVE-2026-0001").delete()
    row = client.get("/detection/vulnerabilities/").context["groups"][0]
    assert (row["action"], row["fix"]) == ("Actualizar squid 6.13", None)
    assert "ni Grype ni NVD dicen a qué versión" in row["detail"]


# --------------------------------------------------------------------------
# «Qué es» un software: lo único que escribe la IA
# --------------------------------------------------------------------------


def test_what_a_software_is_is_asked_once_per_software_not_per_asset_or_version():
    made = _payments()
    log4j = made["log4j"]
    other = AssetFactory(name="api-cobros")
    newer = _software(other, version="2.17.0")
    _vuln(other, "CVE-2021-44832", "Carga de configuración remota en log4j-core 2.17.0", newer)

    payload = software.build_payload(log4j)
    sent = json.dumps(payload, ensure_ascii=False)
    # El modelo recibe con qué reconocerlo, no dónde está ni qué versión es.
    assert payload["software"]["name"] == "log4j-core"
    assert payload["software"]["language_or_platform"] == "Java"
    assert payload["software"]["package"] == "org.example/log4j-core"
    assert "2.14.1" not in sent and "api-pagos" not in sent

    assert software.queue_missing() == 1  # dos activos, dos versiones, una sola pregunta
    found = SoftwareDescription.objects.get()
    assert (found.key, found.name, found.source, found.known) == (
        "log4j-core",
        "log4j-core",
        "AI",
        True,
    )
    assert found.prompt_version == software.PROMPT_VERSION and found.inference_id
    assert InferenceLog.objects.filter(task="SOFTWARE_DESCRIBE").count() == 1
    assert software.for_component(newer) == found and not software.needs(newer)
    assert software.queue_missing() == 0 and not software.request(newer)
    assert InferenceLog.objects.filter(task="SOFTWARE_DESCRIBE").count() == 1
    # Un prompt nuevo sí vuelve a preguntar lo que escribió la IA.
    SoftwareDescription.objects.update(prompt_version="v0")
    assert software.needs(log4j) and software.queue_missing() == 1


def test_what_a_software_is_never_talks_about_flaws_or_versions():
    ok = SoftwareDescribeOutput.model_validate(
        {
            "known": True,
            "summary": "Es una pieza que las aplicaciones usan para anotar  lo que hacen.",
        }
    )
    assert ok.summary == "Es una pieza que las aplicaciones usan para anotar lo que hacen."
    for bad in (
        "Es una biblioteca con una vulnerabilidad que permite a un atacante tomar el servidor.",
        "Es el servidor web en su versión 2.4.49, el que entrega las páginas del sitio.",
        "Es el programa afectado por CVE-2021-44228 que registra lo que hace la aplicación.",
        "A logging library that applications use to write what they are doing to a file.",
        "Es un programa.",
    ):
        with pytest.raises(ValidationError):
            SoftwareDescribeOutput.model_validate({"known": True, "summary": bad})
    # «No lo reconozco» es una respuesta válida y no deja texto.
    unknown = SoftwareDescribeOutput.model_validate({"known": False, "summary": "No sé qué es."})
    assert unknown.summary == ""


def test_an_unknown_software_is_not_described_and_a_person_can_write_it(
    client, as_role, monkeypatch
):
    from apps.llm import client as llm_client

    made = _payments()
    asset, log4j = made["asset"], made["log4j"]
    page = reverse("detection:correction", args=[asset.pk, log4j.pk])
    monkeypatch.setitem(
        llm_client.MOCK_GENERATORS, software.TASK, lambda payload: {"known": False, "summary": ""}
    )
    operator = as_role(OPERATOR)
    body = " ".join(client.get(page).content.decode().split())
    found = SoftwareDescription.objects.get()
    assert (found.known, found.summary) == (False, "")
    assert "La IA no reconoció este software y prefirió no describirlo" in body
    # Guardado el «no sé», no se vuelve a preguntar en cada visita.
    client.get(page)
    assert InferenceLog.objects.filter(task="SOFTWARE_DESCRIBE").count() == 1

    write = reverse("detection:software_description", args=[log4j.pk])
    text = "Es la pieza que las aplicaciones de Java usan para llevar su bitácora."
    response = client.post(write, {"summary": text, "next": page}, follow=True)
    assert "guardada a tu nombre" in response.content.decode()
    found.refresh_from_db()
    assert (found.source, found.summary, found.edited_by) == ("HUMAN", text, operator)
    assert text in response.content.decode() and "por una persona" in response.content.decode()
    # Lo que escribió una persona la IA no lo toca.
    assert software.describe(log4j.pk) is None and not software.request(log4j, force=True)
    # Con el texto vacío vuelve a escribirlo la IA.
    monkeypatch.undo()
    client.post(write, {"summary": "  ", "next": page})
    assert SoftwareDescription.objects.get().source == "AI"
    # El fragmento que se consulta mientras se escribe.
    assert "Qué es log4j-core" in client.get(write).content.decode()
    as_role(AUDITOR)
    assert client.post(write, {"summary": "otra cosa"}).status_code == 403
    assert SoftwareDescription.objects.get().source == "AI"


# --------------------------------------------------------------------------
# La vulnerabilidad dentro de su corrección
# --------------------------------------------------------------------------


def test_the_update_step_is_written_by_code_with_the_version_of_the_whole_correction(
    client, as_role
):
    as_role(OPERATOR)
    made = _payments()
    shell = made["shell"]
    # El paso de la IA que nombra la versión de esta falla se aparta; el resto se queda.
    assert shell.own_steps() == [
        "Comprobar el aviso del fabricante y seguir sus recomendaciones.",
        "Verificar que la versión instalada del paquete es 2.14.1.",
        "Realizar un nuevo escaneo para confirmar que quedó corregida.",
    ]
    correction = corrections.of_vulnerability(shell)
    assert (correction["others"], correction["own"]["version"], correction["fix"]["version"]) == (
        2,
        "2.15.0",
        "2.17.1",
    )
    assert corrections.update_step(correction) == (
        "Actualizar log4j-core a la versión 2.17.1 o superior: corrige esta falla y otras 2 de "
        "este software. Esta deja de aplicar desde la 2.15.0, pero las demás piden llegar a la 2.17.1."
    )

    body = " ".join(
        client.get(reverse("detection:vulnerability", args=[shell.pk])).content.decode().split()
    )
    assert "Parte de la corrección" in body
    assert "Actualizar log4j-core 2.14.1 a 2.17.1 o superior</a>" in body
    assert "resuelve esta y otras 2 vulnerabilidades de este software" in body
    assert "Actualizar log4j-core a la versión 2.17.1 o superior" in body and "dato, no IA" in body
    assert "Aplicar la actualización a la versión 2.15.0 o superior" not in body
    assert "Deja de aplicar desde" in body and "Riesgo que alimenta" in body
    # El fragmento que se refresca mientras la IA redacta lleva los mismos pasos.
    fragment = client.get(reverse("detection:vulnerability_description", args=[shell.pk]))
    assert "Actualizar log4j-core a la versión 2.17.1 o superior" in fragment.content.decode()

    # La que pide la versión mayor no necesita la aclaración.
    last = corrections.update_step(corrections.of_vulnerability(made["loop"]))
    assert last == (
        "Actualizar log4j-core a la versión 2.17.1 o superior: corrige esta falla y otras 2 de "
        "este software."
    )


def test_a_configuration_vulnerability_is_its_own_correction_and_keeps_its_steps(client, as_role):
    as_role(OPERATOR)
    made = _payments()
    headers = made["headers"]
    # Sin software, «TLS 1.0» es el paso y no una versión de destino: no se toca.
    assert headers.own_steps() == [
        "Añadir las cabeceras HSTS y CSP.",
        "Deshabilitar TLS 1.0 y 1.1.",
    ]
    correction = corrections.of_vulnerability(headers)
    assert correction["single"] and correction["type"] == grouping.CONFIG
    assert corrections.update_step(correction) == ""
    body = " ".join(
        client.get(reverse("detection:vulnerability", args=[headers.pk])).content.decode().split()
    )
    assert "Corrección: cambiar configuración." in body and "Deshabilitar TLS 1.0 y 1.1." in body
    assert "Parte de la corrección" not in body and "dato, no IA" not in body

    loose = " ".join(
        client.get(reverse("detection:vulnerability", args=[made["phpunit"].pk]))
        .content.decode()
        .split()
    )
    assert "Corrección: actualizar software." in loose
    assert "el inventario de api-pagos no tiene ese software" in loose


def test_a_vulnerability_page_links_the_risk_it_feeds_and_shows_its_evidence(client, as_role):
    as_role(AUDITOR)
    made = _payments()
    shell = made["shell"]
    page = reverse("detection:vulnerability", args=[shell.pk])
    body = " ".join(client.get(page).content.decode().split())
    assert "Ningún riesgo abierto la contiene" in body
    scenario = Risk.objects.create(
        asset=made["asset"],
        key=RiskConsequence.INTEGRITY,
        consequence=RiskConsequence.INTEGRITY,
        title="Alteración de datos en api-pagos",
        scenario="s",
        threat_source="EXTERNAL",
        likelihood=4,
        impact=5,
        level=risk_level_for(4, 5),
        first_identified_at=timezone.now(),
    )
    scenario.vulnerabilities.add(shell)
    body = " ".join(client.get(page).content.decode().split())
    assert "Alteración de datos o sistemas en Pagos" in body
    assert reverse("detection:risk", args=[scenario.pk]) in body
    assert 'id="evidencia"' in body and "Reporte que la sustenta" in body
    report = shell.observations.get()
    assert reverse("detection:finding", args=[report.pk]) in body


# --------------------------------------------------------------------------
# Dos vulnerabilidades del mismo software no se llaman igual
# --------------------------------------------------------------------------


def test_repeated_titles_within_a_software_get_their_identifier():
    made = _payments()
    asset, log4j = made["asset"], made["log4j"]
    mine = _vuln(asset, "CVE-2021-45105", RCE, log4j, description_source=StatusSource.HUMAN)
    internal = _vuln(asset, "WEAKNESS:ghsa_x", RCE, log4j)

    assert descriptions.distinguish_titles(asset.pk) == 2
    titles_now = dict(Vulnerability.objects.values_list("key", "title"))
    assert titles_now["CVE-2021-44228"] == f"{RCE} (CVE-2021-44228)"
    assert titles_now["CVE-2021-45046"] == f"{RCE} (CVE-2021-45046)"
    # La que es única se queda como está; la que tituló una persona y la de clave interna, también.
    assert titles_now["CVE-2021-44832"] == "Carga de configuración remota en log4j-core 2.14.1"
    assert titles_now[mine.key] == RCE and titles_now[internal.key] == RCE
    event = made["shell"].events.latest("occurred_at")
    assert "se añadió su identificador" in event.message and event.data["previous_title"] == RCE
    # Repetirlo no cambia nada, y el repaso periódico lo incluye.
    assert descriptions.distinguish_titles(asset.pk, log4j.pk) == 0
    assert descriptions.review_titles()["distinguished"] == 0

    # Las tablas que ya muestran el identificador en su propia línea no lo repiten en el título.
    made["shell"].refresh_from_db()
    assert (
        made["shell"].title_without_key == RCE
        and made["loop"].title_without_key == made["loop"].title
    )

    assert titles.identifier("CVE-2021-44228") == "CVE-2021-44228"
    assert titles.identifier("GHSA-4fx9-vc88-q2xc") == "GHSA-4fx9-vc88-q2xc"
    assert titles.identifier("WEAKNESS:CABECERAS_HTTP") == ""
    assert titles.bare(f"{RCE} (CVE-2021-44228)") == RCE
    long = titles.with_identifier("x" * 300, "CVE-2021-44228")
    assert len(long) == 200 and long.endswith(" (CVE-2021-44228)")

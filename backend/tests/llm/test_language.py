"""El texto que llega a la persona debe estar en español: heurística y reintento con retroalimentación."""

import json

import httpx
import pytest

from apps.llm.language import looks_spanish, non_spanish
from tests.llm.helpers import BASE, VALID, chat_response
from tests.llm.test_client import run


@pytest.mark.parametrize(
    "text",
    [
        "Ejecución remota de código en log4j-core 2.14.1",
        "Un atacante sin autenticación puede leer archivos fuera de la raíz del sitio web.",
        "Cabeceras de seguridad HTTP ausentes en el portal",
        "CVE-2021-44228",  # demasiado corto para juzgar: se acepta
        "Apache HTTP Server 2.4.49",  # nombre propio, sin palabras funcionales inglesas
        "Actualizar OpenSSH a 9.8p1 y reiniciar el servicio sshd.",
    ],
)
def test_spanish_or_neutral_texts_pass(text):
    assert looks_spanish(text)


@pytest.mark.parametrize(
    "text",
    [
        "The system is using outdated versions of jackson-databind, which are vulnerable to RCE.",
        "Multiple vulnerabilities in Apache HTTP Server versions prior to 2.4.69",
        "Heap-Buffer-Overflow and Heap-Use-After-Free in Python",
        "An attacker could inject untrusted user input into response.redirect()",
        "Vulnerabilities in Jackson Databind and Spring",
    ],
)
def test_english_texts_are_rejected(text):
    assert not looks_spanish(text)


def test_non_spanish_lists_only_the_offending_texts():
    assert non_spanish("Texto en español para la persona", "The attacker can read files", "") == [
        "The attacker can read files"
    ]


@pytest.mark.django_db
def test_retry_tells_the_model_what_failed(ollama):
    """El segundo intento lleva la respuesta anterior y los errores de validación."""
    bad = '{"criticality": "ENORME", "confidence": 2, "rationale": "x"}'
    route = ollama.post(f"{BASE}/api/chat").mock(
        side_effect=[
            httpx.Response(200, json=chat_response(bad)),
            httpx.Response(200, json=chat_response(VALID)),
        ]
    )
    log = run()
    assert log.parsed_ok and log.attempts == 2
    first = json.loads(route.calls[0].request.content)["messages"]
    second = json.loads(route.calls[1].request.content)["messages"]
    assert len(first) == 1 and len(second) == 3 and second[1]["role"] == "assistant"
    first, second = json.dumps(first, ensure_ascii=False), json.dumps(second, ensure_ascii=False)
    assert "ENORME" not in first and "ENORME" in second
    assert "no cumplió" in second and "criticality" in second and "español" in second


def test_three_english_words_are_enough_to_reject():
    assert not looks_spanish("Low Severity Vulnerabilities")
    assert not looks_spanish("Remote Code Execution")
    assert looks_spanish("Apache HTTP Server")


def test_null_characters_from_the_model_are_dropped_before_saving():
    from apps.llm.client import _strip_nul

    assert _strip_nul('{"a": "x\\u0000y"}') == '{"a": "xy"}'
    assert _strip_nul("a\x00b") == "ab"
    assert _strip_nul(None) == ""

"""Lo que una herramienta deja de reportar (W6 de la revisión del 2026-11-16).

El silencio de nuclei solo cuenta como «ya no se observa» si la pasada pudo verla: el perfil corre
esa plantilla, el puerto estaba entre los objetivos y respondía. Sin red y sin herramientas.
"""

from pathlib import Path

import pytest

from apps.detection import verification
from apps.detection.models import Finding, FindingEventKind, FindingStatus
from apps.scanners import profiles, services
from apps.scanners.runner import CommandResult
from tests.factories import AssetFactory, AssetIdentifierFactory, NetworkRangeFactory

pytestmark = pytest.mark.django_db
NUCLEI = (Path(__file__).parent / "fixtures" / "nuclei.jsonl").read_text()
APACHE, NGINX, SSH = "CVE-2021-41773", "NUCLEI:NGINX-VERSION", "CVE-2024-6387"


@pytest.fixture(autouse=True)
def _immediate_on_commit(monkeypatch):
    from django.db import transaction

    from apps.detection import planner

    monkeypatch.setattr(transaction, "on_commit", lambda func, using=None, robust=False: func())
    monkeypatch.setattr(planner, "enqueue_ready", lambda ids: None)


@pytest.fixture
def scan(monkeypatch):
    """Corre nuclei (simulado) sobre el activo y devuelve la ejecución."""
    NetworkRangeFactory(cidr="10.7.0.0/24")
    asset = AssetFactory()
    AssetIdentifierFactory(asset=asset, value="10.7.0.10")

    def run(stdout, profile="cves", targets=("10.7.0.10",), truncated=False):
        monkeypatch.setattr(
            services,
            "run_command",
            lambda argv, *, timeout=None, env=None: CommandResult(stdout, "", 0, 0.1, truncated),
        )
        execution = services.request_execution(
            tool="NUCLEI", profile=profile, asset_id=asset.pk, targets=list(targets)
        )
        execution.refresh_from_db()
        assert execution.status == "SUCCEEDED"
        return execution

    run.asset = asset
    return run


def _finding(asset, key):
    return Finding.objects.get(asset=asset, vulnerability_id=key)


def _last_note(finding):
    return finding.events.filter(kind=FindingEventKind.RESCANNED).last().message


@pytest.mark.parametrize(
    ("profile", "tags", "kind", "covered"),
    [
        ("cves", ["cve", "rce"], "http", True),
        ("cves", ["exposure"], "http", False),  # «cves» no corre las de exposición
        ("cves-web", ["exposure", "config"], "http", True),
        ("cves-network", ["cve"], "http", False),  # el perfil de red excluye las HTTP
        ("cves-network", ["cve"], "tcp", True),
        ("all", [], "http", True),  # el que lo corre todo no necesita etiquetas
        ("cves", [], "http", False),  # sin etiquetas conocidas no se puede afirmar
        ("inventado", ["cve"], "http", False),
        # Las de comparador global no las corre ningún perfil: su silencio no dice nada.
        ("cves-web", ["global-matchers", "exposure"], "http", False),
        ("all", ["global-matchers"], "http", False),
    ],
)
def test_profile_coverage(profile, tags, kind, covered):
    assert profiles.nuclei_covers(profile, tags, kind) is covered


def test_silence_counts_only_when_the_pass_could_see_it(scan, monkeypatch):
    asset = scan.asset
    scan(NUCLEI)
    assert Finding.objects.filter(asset=asset, status=FindingStatus.NEW).count() == 3

    # Pasada de red contra el puerto 22, sin resultados.
    scan("", profile="cves-network", targets=["10.7.0.10:22"])
    apache, nginx, ssh = (_finding(asset, key) for key in (APACHE, NGINX, SSH))
    # Las plantillas HTTP no las corre este perfil: su silencio no dice nada de ellas.
    assert apache.unseen == {} and "no corre la plantilla" in _last_note(apache)
    assert nginx.unseen == {} and "no corre la plantilla" in _last_note(nginx)
    # La de SSH sí pudo verla y no la reportó: primera pasada en silencio.
    assert ssh.unseen == {"NUCLEI": 1} and ssh.is_open
    assert "la revisó y ya no la reporta" in _last_note(ssh) and "1 de 2" in _last_note(ssh)

    # Un equipo que no responde no reporta nada, y no por eso está corregido.
    monkeypatch.setattr(services, "_reachable", lambda *a, **k: False)
    scan("", profile="cves-network", targets=["10.7.0.10:22"])
    ssh.refresh_from_db()
    assert ssh.unseen == {"NUCLEI": 1} and ssh.is_open
    assert "10.7.0.10:22 no respondió" in _last_note(ssh)

    # Segunda pasada que sí pudo verla: se cierra.
    monkeypatch.setattr(services, "_reachable", lambda *a, **k: True)
    scan("", profile="cves-network", targets=["10.7.0.10:22"])
    ssh.refresh_from_db()
    assert ssh.status == FindingStatus.MITIGATED
    assert ssh.events.last().kind == FindingEventKind.AUTO_RESOLVED
    assert "la revisó y ya no la reporta" in ssh.events.last().message
    # Si vuelve a aparecer, se reabre.
    scan(NUCLEI.splitlines()[3], profile="cves-network", targets=["10.7.0.10:22"])
    ssh.refresh_from_db()
    assert ssh.status == FindingStatus.REOPENED and ssh.unseen == {}


def test_a_cut_output_says_nothing_about_what_it_did_not_report(scan):
    """Un escaneo cuya salida se cortó en el límite termina como exitoso. Lo que falta pudo traer
    cualquiera de las observaciones anteriores, así que su silencio no cuenta para cerrarlas."""
    asset = scan.asset
    scan(NUCLEI)
    cut = scan("", profile="all", truncated=True)
    assert cut.output_incomplete and cut.output_cut == {"limit_mb": 50}
    for key in (APACHE, NGINX, SSH):
        finding = _finding(asset, key)
        assert finding.unseen == {} and finding.is_open, key
        assert "recortó su salida al llegar al límite" in _last_note(finding)
    # La misma pasada con la salida completa sí cuenta.
    whole = scan("", profile="all")
    assert not whole.output_incomplete
    assert all(_finding(asset, key).unseen == {"NUCLEI": 1} for key in (APACHE, NGINX, SSH))


def test_port_outside_the_targets_is_not_reviewed(scan):
    asset = scan.asset
    scan(NUCLEI)
    scan("", profile="cves-web", targets=["10.7.0.10:8443"])
    apache = _finding(asset, APACHE)
    assert apache.unseen == {} and "no estaba entre los objetivos" in _last_note(apache)
    # Con su puerto entre los objetivos, sí cuenta.
    scan("", profile="cves-web", targets=["10.7.0.10:80", "10.7.0.10:8443"])
    apache.refresh_from_db()
    nginx = _finding(asset, NGINX)
    assert apache.unseen == {"NUCLEI": 1} and nginx.unseen == {"NUCLEI": 1}


def test_a_pass_requested_to_verify_a_fix_counts_in_full(scan, monkeypatch):
    asset = scan.asset
    scan(NUCLEI)
    # La pasada la pidió quien dice haberlo corregido: un solo silencio basta.
    monkeypatch.setattr(verification, "requested_for", lambda action_id: True)
    scan(NUCLEI.splitlines()[1], profile="cves-web", targets=["10.7.0.10:80"])
    apache = _finding(asset, APACHE)
    assert apache.status == FindingStatus.MITIGATED
    assert _finding(asset, NGINX).is_open  # la que sí volvió a salir sigue abierta
    assert _finding(asset, SSH).is_open  # y la del puerto 22 no era objetivo


def test_observations_from_other_sources_get_no_note(scan):
    from apps.detection import findings

    asset = scan.asset
    other = findings.upsert_finding(
        asset_id=asset.pk, vulnerability_id="CVE-2030-0100", source="CTI_MATCH"
    ).finding
    scan(NUCLEI)
    scan("")
    assert not other.events.filter(kind=FindingEventKind.RESCANNED).exists()
    assert other.unseen == {} and Finding.objects.get(pk=other.pk).is_open

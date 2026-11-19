"""Buscador global (revisión del 2026-11-16, N3): una búsqueda recorre activos, riesgos,
vulnerabilidades y el catálogo de CVE, con el permiso de cada lista."""

import pytest
from django.contrib.auth.models import Permission
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.cti.models import CveRecord
from apps.detection.models import Risk, RiskStatus, Vulnerability
from apps.presentation import search
from tests.factories import AssetFactory, AssetIdentifierFactory

pytestmark = pytest.mark.django_db


@pytest.fixture
def as_role(client, make_user):
    def login(role, **kwargs):
        user = make_user(role, **kwargs)
        client.force_login(user)
        return user

    return login


def _asset(name="portal-pagos", ip="10.20.30.40"):
    asset = AssetFactory(name=name, criticality="ALTO")
    AssetIdentifierFactory(asset=asset, value=ip)
    return asset


def _vulnerability(
    asset, key="CVE-2021-44228", title="Ejecución remota en log4j-core 2.14.1", **kw
):
    cve = CveRecord.objects.filter(pk=key).first() if key.startswith("CVE-") else None
    now = timezone.now()
    defaults = {"severity": "CRITICAL", "status": "CONFIRMED"}
    return Vulnerability.objects.create(
        asset=asset,
        key=key,
        cve=cve,
        title=title,
        first_detected_at=now,
        last_seen_at=now,
        **{**defaults, **kw},
    )


def _risk(asset, title, key, status=RiskStatus.OPEN, level="CRITICAL", **kw):
    return Risk.objects.create(
        asset=asset,
        key=key,
        title=title,
        scenario="Escenario",
        threat_source="EXTERNAL",
        likelihood=4,
        impact=5,
        level=level,
        status=status,
        first_identified_at=timezone.now(),
        **kw,
    )


def _groups(response):
    return {g["key"]: g for g in response.context["search"]["groups"]}


def test_one_search_finds_the_asset_by_name_or_address(client, as_role):
    as_role(OPERATOR)
    asset = _asset()
    _asset("otro-equipo", "10.99.0.1")
    for text in ("portal", "10.20.30.40", "  PORTAL-pagos  "):
        groups = _groups(client.get("/search/", {"q": text}))
        assert [a.pk for a in groups["assets"]["items"]] == [asset.pk], text
    body = client.get("/search/", {"q": "10.20.30.40"}).content.decode()
    assert "portal-pagos" in body and f"/inventory/{asset.pk}/" in body
    assert "1 resultado para «10.20.30.40»" in body


def test_a_cve_finds_its_vulnerabilities_risks_and_catalog_entry(client, as_role):
    as_role(OPERATOR)
    CveRecord.objects.create(
        cve_id="CVE-2021-44228", description="Log4Shell", severity="CRITICAL", cvss_score=10.0
    )
    CveRecord.objects.create(cve_id="CVE-2021-44229", description="Otro", severity="NONE")
    asset = _asset()
    vuln = _vulnerability(asset)
    risk = _risk(
        asset,
        "Compromiso del portal-pagos por Log4Shell",
        "r1",
        details="Fallas: CVE-2021-44228",
    )
    risk.vulnerabilities.add(vuln)

    response = client.get("/search/", {"q": "cve-2021-44228"})
    groups = _groups(response)
    assert list(groups) == ["risks", "vulnerabilities", "catalog"]
    assert [v.pk for v in groups["vulnerabilities"]["items"]] == [vuln.pk]
    assert [r.pk for r in groups["risks"]["items"]] == [risk.pk]
    record = groups["catalog"]["items"][0]
    assert record.cve_id == "CVE-2021-44228" and record.affected_assets == 1
    body = response.content.decode()
    assert "en 1 activo" in body and "Log4Shell" in body

    # Un CVE que el catálogo conoce pero ningún activo tiene: la respuesta es «no nos afecta».
    response = client.get("/search/", {"q": "CVE-2021-44229"})
    assert list(_groups(response)) == ["catalog"]
    body = response.content.decode()
    assert "no se observa en ningún activo" in body
    # «NONE» es la severidad de lo que el catálogo aún no trae: no rompe la página.
    assert "sin severidad en el catálogo" in body

    # El prefijo lista los que coinciden; un CVE exacto que nadie conoce lo dice.
    assert _groups(client.get("/search/", {"q": "CVE-2021-4422"}))["catalog"]["total"] == 2
    body = client.get("/search/", {"q": "CVE-2030-99999"}).content.decode()
    assert "Nada coincide con «CVE-2030-99999»" in body
    assert "no está en ningún activo ni en el catálogo local" in body


def test_groups_link_to_the_same_list_with_the_same_count(client, as_role):
    as_role(OPERATOR)
    asset = _asset()
    for i in range(search.GROUP_LIMIT + 3):
        _vulnerability(asset, key=f"WEAKNESS:APACHE_{i}", title=f"Falla {i} en Apache httpd")
    _vulnerability(asset, key="WEAKNESS:CERRADA", title="Apache ya corregido", status="MITIGATED")
    open_risk = _risk(asset, "Fuga de información por Apache httpd", "abierto", level="LOW")
    closed = _risk(asset, "Compromiso por Apache httpd", "cerrado", status=RiskStatus.CLOSED)

    response = client.get("/search/", {"q": "apache"})
    groups = _groups(response)
    vulns = groups["vulnerabilities"]
    assert vulns["total"] == search.GROUP_LIMIT + 3 and len(vulns["items"]) == search.GROUP_LIMIT
    assert vulns["more"] == 3
    # El enlace abre la lista con el mismo texto y la lista cuenta lo mismo.
    page = client.get(vulns["url"] + "&flat=1")
    assert page.status_code == 200 and page.context["total_vulnerabilities"] == vulns["total"]
    # Riesgos: abiertos y cerrados, los abiertos primero aunque sean de menor nivel.
    assert [r.pk for r in groups["risks"]["items"]] == [open_risk.pk, closed.pk]
    listed = client.get(groups["risks"]["url"]).context["paginator"].count
    assert listed == groups["risks"]["total"] == 2
    body = response.content.decode()
    assert f"Ver los {vulns['total']} en la lista" in body
    assert "11 resultados para «apache»" in body


def test_each_group_follows_the_permission_of_its_list(client, make_user):
    asset = _asset()
    _vulnerability(asset, key="WEAKNESS:X", title="Falla en portal")
    _risk(asset, "Fuga en portal-pagos", "r1")
    user = make_user()
    user.user_permissions.add(Permission.objects.get(codename="view_asset"))
    client.force_login(type(user).objects.get(pk=user.pk))
    groups = _groups(client.get("/search/", {"q": "portal"}))
    assert list(groups) == ["assets"]
    # Quien solo lee ve los tres grupos.
    client.force_login(make_user(AUDITOR))
    assert list(_groups(client.get("/search/", {"q": "portal"}))) == [
        "assets",
        "risks",
        "vulnerabilities",
    ]


def test_empty_short_and_no_result_states(client, as_role):
    as_role(OPERATOR)
    body = client.get("/search/").content.decode()
    assert "Una sola búsqueda recorre" in body and "CVE-2021-44228" in body
    assert "Escribe al menos dos caracteres" in client.get("/search/", {"q": "a"}).content.decode()
    response = client.get("/search/", {"q": "no-existe-zz"})
    assert response.context["search"]["state"] == "none"
    assert "Nada coincide con «no-existe-zz»" in response.content.decode()
    # Lo que se escribe se muestra escapado.
    body = client.get("/search/", {"q": "<script>x</script>"}).content.decode()
    assert "<script>x</script>" not in body and "&lt;script&gt;" in body


def test_search_field_is_on_every_page_and_has_its_place_in_navigation(client, as_role):
    as_role(OPERATOR)
    body = client.get("/").content.decode()
    assert 'role="search"' in body and "data-global-search" in body
    assert 'action="/search/"' in body
    response = client.get("/search/", {"q": "x1"})
    nav = response.context["nav"]
    # No es un enlace más de la barra lateral: es el campo. La página tiene título y migas.
    assert nav.section.key == "search" and "search" not in [i.key for i in nav.main]
    assert [c.label for c in nav.breadcrumbs] == ["Inicio", "Buscar"]
    assert 'value="x1"' in response.content.decode()


def test_search_requires_a_session(client):
    response = client.get("/search/", {"q": "portal"})
    assert response.status_code == 302 and "/accounts/login/" in response["Location"]

"""Servicios del inventario: identidad, upsert, alcance, ciclo de vida y contrato."""

from datetime import timedelta

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from apps.accounts.roles import AUDITOR, OPERATOR
from apps.assets import services
from apps.assets.contracts import DiscoveredHost, DiscoveredService
from apps.assets.enums import (
    AssetOrigin,
    AssetStatus,
    AssetType,
    ConflictResolution,
    CriticalitySource,
    Exposure,
    ExposureSource,
    IdentifierKind,
    SuggestionState,
)
from apps.assets.models import Asset, AssetConflict, AssetIdentifier, CriticalitySuggestion, Service
from tests.factories import (
    AssetFactory,
    AssetIdentifierFactory,
    NetworkRangeFactory,
    ServiceFactory,
)

pytestmark = pytest.mark.django_db

NOW = timezone.now()


def host(**kwargs):
    defaults = {"source": "nmap", "observed_at": timezone.now()}
    return DiscoveredHost(**{**defaults, **kwargs})


def ident(asset, kind, value):
    return AssetIdentifierFactory(asset=asset, kind=kind, value=value)


@pytest.fixture
def operator(make_user):
    return make_user(OPERATOR)


# --- resolve_asset ------------------------------------------------------------


def test_resolve_returns_none_without_match():
    assert services.resolve_asset([(IdentifierKind.IPV4, "10.1.1.1")]) is None


def test_resolve_by_any_identifier():
    asset = AssetFactory()
    ident(asset, IdentifierKind.FQDN, "web.phylax.local")
    assert services.resolve_asset([(IdentifierKind.FQDN, "WEB.phylax.local.")]) == asset


def test_resolve_conflict_mac_vs_fqdn_is_persisted_without_changes():
    a, b = AssetFactory(), AssetFactory()
    ident(a, IdentifierKind.MAC, "aa:bb:cc:dd:ee:01")
    ident(b, IdentifierKind.FQDN, "db.phylax.local")
    result = services.resolve_asset(
        [(IdentifierKind.FQDN, "db.phylax.local"), (IdentifierKind.MAC, "AA:BB:CC:DD:EE:01")]
    )
    assert isinstance(result, AssetConflict)
    assert set(result.candidate_assets.all()) == {a, b}
    # La identidad disputada es la que no coincide con el identificador de mayor precedencia.
    assert (result.identifier_kind, result.identifier_value) == ("FQDN", "db.phylax.local")


def test_resolve_conflict_is_reused_while_open():
    a, b = AssetFactory(), AssetFactory()
    ident(a, IdentifierKind.MAC, "aa:bb:cc:dd:ee:02")
    ident(b, IdentifierKind.IPV4, "10.2.2.2")
    ids = [(IdentifierKind.MAC, "aa:bb:cc:dd:ee:02"), (IdentifierKind.IPV4, "10.2.2.2")]
    first = services.resolve_asset(ids)
    second = services.resolve_asset(ids)
    assert first.pk == second.pk
    assert AssetConflict.objects.count() == 1


def test_resolve_preview_does_not_persist_conflicts():
    a, b = AssetFactory(), AssetFactory()
    ident(a, IdentifierKind.MAC, "aa:bb:cc:dd:ee:03")
    ident(b, IdentifierKind.IPV4, "10.3.3.3")
    result = services.resolve_asset(
        [(IdentifierKind.MAC, "aa:bb:cc:dd:ee:03"), (IdentifierKind.IPV4, "10.3.3.3")],
        persist=False,
    )
    assert result.pk is not None or result._state.adding
    assert AssetConflict.objects.count() == 0
    assert set(result.preview_candidates) == {a, b}


def test_resolve_follows_merged_into_and_ignores_retired():
    target, absorbed, retired = AssetFactory(), AssetFactory(), AssetFactory()
    ident(absorbed, IdentifierKind.IPV4, "10.4.4.4")
    ident(retired, IdentifierKind.IPV4, "10.4.4.5")
    Asset.objects.filter(pk=absorbed.pk).update(status=AssetStatus.RETIRED, merged_into=target)
    Asset.objects.filter(pk=retired.pk).update(status=AssetStatus.RETIRED)
    assert services.resolve_asset([(IdentifierKind.IPV4, "10.4.4.4")]) == target
    assert services.resolve_asset([(IdentifierKind.IPV4, "10.4.4.5")]) is None


def test_precedence_digest_over_mac():
    image = AssetFactory(asset_type=AssetType.CONTAINER_IMAGE)
    digest = "sha256:" + "b" * 64
    ident(image, IdentifierKind.IMAGE_DIGEST, digest)
    assert services.resolve_asset([(IdentifierKind.IMAGE_DIGEST, digest)]) == image


# --- upsert_discovered_host --------------------------------------------------------


def test_upsert_creates_unconfirmed_asset_with_range_and_exposure():
    NetworkRangeFactory(cidr="10.50.0.0/16", zone=Exposure.INTERNAL)
    dmz = NetworkRangeFactory(cidr="10.50.1.0/24", zone=Exposure.DMZ)
    result = services.upsert_discovered_host(
        host(ipv4="10.50.1.20", hostnames=("Web01.Phylax.Local",), os_guess="Linux 5.x")
    )
    asset = result.asset
    assert result.created and not result.updated
    assert asset.status == AssetStatus.UNCONFIRMED
    assert asset.origin == AssetOrigin.DISCOVERY
    assert asset.criticality is None
    assert asset.name == "web01.phylax.local"
    # Longest-prefix match: /24 gana a /16 y hereda su zona.
    assert asset.network_range == dmz
    assert asset.exposure == Exposure.DMZ
    assert asset.identifiers.get(kind=IdentifierKind.IPV4).is_primary


def test_upsert_without_hostname_uses_ip_as_name():
    result = services.upsert_discovered_host(host(ipv4="10.60.0.9"))
    assert result.asset.name == "10.60.0.9"


def test_upsert_is_idempotent():
    h = host(
        ipv4="10.70.0.1",
        mac="aa:bb:cc:00:00:01",
        services=(DiscoveredService(port=22, protocol="tcp", state="open", service_name="ssh"),),
    )
    services.upsert_discovered_host(h)
    second = services.upsert_discovered_host(h)
    assert second.updated and not second.created
    assert Asset.objects.count() == 1
    assert AssetIdentifier.objects.count() == 2
    assert Service.objects.count() == 1


def test_upsert_updates_services_and_closes_unseen_on_complete_scan():
    asset = AssetFactory()
    ident(asset, IdentifierKind.IPV4, "10.80.0.1")
    old = ServiceFactory(
        asset=asset, port=21, service_name="ftp", last_seen=timezone.now() - timedelta(days=1)
    )
    services.upsert_discovered_host(
        host(
            ipv4="10.80.0.1",
            services=(
                DiscoveredService(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service_name="https",
                    product="nginx",
                    version="1.27",
                ),
            ),
            services_complete=True,
        )
    )
    old.refresh_from_db()
    assert old.state == "closed"
    assert asset.services.get(port=443).product == "nginx"


def test_partial_scan_never_closes_services():
    asset = AssetFactory()
    ident(asset, IdentifierKind.IPV4, "10.80.0.2")
    old = ServiceFactory(asset=asset, port=21, last_seen=timezone.now() - timedelta(days=1))
    services.upsert_discovered_host(host(ipv4="10.80.0.2"))
    old.refresh_from_db()
    assert old.state == "open"


def test_upsert_returns_stale_to_active_and_keeps_ignored():
    stale, ignored = AssetFactory(status=AssetStatus.STALE), AssetFactory(
        status=AssetStatus.IGNORED
    )
    ident(stale, IdentifierKind.IPV4, "10.90.0.1")
    ident(ignored, IdentifierKind.IPV4, "10.90.0.2")
    services.upsert_discovered_host(host(ipv4="10.90.0.1"))
    services.upsert_discovered_host(host(ipv4="10.90.0.2"))
    stale.refresh_from_db()
    ignored.refresh_from_db()
    assert stale.status == AssetStatus.ACTIVE
    assert ignored.status == AssetStatus.IGNORED
    assert ignored.last_seen is not None


def test_upsert_conflict_does_not_modify_assets():
    a, b = AssetFactory(os_guess=""), AssetFactory(os_guess="")
    ident(a, IdentifierKind.MAC, "aa:bb:cc:00:00:09")
    ident(b, IdentifierKind.IPV4, "10.91.0.1")
    result = services.upsert_discovered_host(
        host(ipv4="10.91.0.1", mac="aa:bb:cc:00:00:09", os_guess="Windows")
    )
    assert result.conflict is not None and result.asset is None
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.os_guess == b.os_guess == ""
    assert a.last_seen is None and b.last_seen is None
    assert AssetIdentifier.objects.count() == 2


def test_upsert_adds_new_identifiers_to_known_asset():
    asset = AssetFactory()
    ident(asset, IdentifierKind.IPV4, "10.92.0.1")
    services.upsert_discovered_host(
        host(ipv4="10.92.0.1", mac="aa:bb:cc:00:00:10", hostnames=("app.phylax.local",))
    )
    assert set(asset.identifiers.values_list("kind", flat=True)) == {"IPV4", "MAC", "FQDN"}


def test_upsert_drops_invalid_identifiers():
    result = services.upsert_discovered_host(host(ipv4="10.93.0.1", hostnames=("mal nombre",)))
    assert list(result.asset.identifiers.values_list("kind", flat=True)) == ["IPV4"]


def test_retired_asset_releases_identifiers_when_seen_again():
    old = AssetFactory(status=AssetStatus.RETIRED)
    ident(old, IdentifierKind.IPV4, "10.94.0.1")
    result = services.upsert_discovered_host(host(ipv4="10.94.0.1"))
    assert result.created
    assert result.asset.identifiers.filter(value="10.94.0.1").exists()


# --- Exposición y rangos ----------------------------------------------------


def test_manual_exposure_override_is_not_overwritten():
    NetworkRangeFactory(cidr="10.95.0.0/24", zone=Exposure.INTERNAL)
    asset = AssetFactory(exposure=Exposure.INTERNET, exposure_source=ExposureSource.MANUAL)
    ident(asset, IdentifierKind.IPV4, "10.95.0.7")
    services.upsert_discovered_host(host(ipv4="10.95.0.7"))
    asset.refresh_from_db()
    assert asset.exposure == Exposure.INTERNET


def test_refresh_range_membership_after_new_range():
    asset = AssetFactory()
    ident(asset, IdentifierKind.IPV4, "10.96.0.7")
    services.upsert_discovered_host(host(ipv4="10.96.0.7"))
    asset.refresh_from_db()
    assert asset.network_range is None
    NetworkRangeFactory(cidr="10.96.0.0/24", zone=Exposure.DMZ)
    assert services.refresh_range_membership() == 1
    asset.refresh_from_db()
    assert asset.exposure == Exposure.DMZ


# --- Alcance y objetivos ---------------------------------------------------------


def test_is_in_scope_rules():
    NetworkRangeFactory(cidr="10.97.0.0/24", in_scope=True)
    NetworkRangeFactory(cidr="10.98.0.0/24", in_scope=False, authorization_reference="")
    NetworkRangeFactory(
        cidr="10.99.0.0/24", authorization_expires_at=timezone.now() - timedelta(hours=1)
    )
    assert services.is_in_scope("10.97.0.10")
    assert services.is_in_scope("10.97.0.128/25")
    assert not services.is_in_scope("10.97.0.0/23")
    assert not services.is_in_scope("10.98.0.10")
    assert not services.is_in_scope("10.99.0.10")
    assert not services.is_in_scope("192.0.2.1")
    excluded = AssetFactory(in_scope=False)
    ident(excluded, IdentifierKind.IPV4, "10.97.0.20")
    assert not services.is_in_scope("10.97.0.20")


def test_get_scan_targets_excludes_non_scannable_and_out_of_scope():
    NetworkRangeFactory(cidr="10.110.0.0/24")
    statuses = {
        "10.110.0.1": AssetStatus.ACTIVE,
        "10.110.0.2": AssetStatus.STALE,
        "10.110.0.3": AssetStatus.UNCONFIRMED,
        "10.110.0.4": AssetStatus.IGNORED,
        "10.110.0.5": AssetStatus.RETIRED,
    }
    for ip, status in statuses.items():
        ident(AssetFactory(status=status), IdentifierKind.IPV4, ip)
    ident(AssetFactory(in_scope=False), IdentifierKind.IPV4, "10.110.0.6")
    ident(AssetFactory(), IdentifierKind.IPV4, "192.0.2.50")  # sin rango autorizado
    targets = services.get_scan_targets()
    ips = {t.value for t in targets if t.kind == "ip"}
    assert ips == {"10.110.0.1", "10.110.0.2"}
    assert {t.value for t in targets if t.kind == "cidr"} == {"10.110.0.0/24"}


# --- Ciclo de vida -------------------------------------------------------------------


def test_confirm_requires_minimum_fields(operator):
    asset = AssetFactory(status=AssetStatus.UNCONFIRMED, environment=None, business_role=None)
    with pytest.raises(ValidationError, match="faltan"):
        services.confirm_asset(asset, user=operator)
    services.confirm_asset(
        asset,
        user=operator,
        fields={"environment": "PROD", "business_role": "API"},
        criticality="ALTO",
    )
    asset.refresh_from_db()
    assert asset.status == AssetStatus.ACTIVE
    assert asset.criticality_source == CriticalitySource.MANUAL


def test_confirm_records_history_user(operator):
    asset = AssetFactory(status=AssetStatus.UNCONFIRMED)
    services.confirm_asset(asset, user=operator, criticality="BAJO")
    assert asset.history.first().history_user == operator


def test_auditor_cannot_change_assets(make_user):
    with pytest.raises(PermissionDenied):
        services.ignore_asset(AssetFactory(), user=make_user(AUDITOR))


def test_ignore_and_retire(operator):
    asset = AssetFactory(status=AssetStatus.UNCONFIRMED)
    services.ignore_asset(asset, user=operator)
    assert Asset.objects.get(pk=asset.pk).status == AssetStatus.IGNORED
    services.retire_asset(asset, user=operator)
    assert Asset.objects.get(pk=asset.pk).status == AssetStatus.RETIRED
    with pytest.raises(ValidationError):
        services.ignore_asset(asset, user=operator)


def test_mark_stale_assets_only_for_observed():
    old = timezone.now() - timedelta(days=30)
    seen = AssetFactory(last_seen=old)
    never_seen = AssetFactory(last_seen=None)
    recent = AssetFactory(last_seen=timezone.now())
    assert services.mark_stale_assets() == 1
    assert Asset.objects.get(pk=seen.pk).status == AssetStatus.STALE
    assert Asset.objects.get(pk=never_seen.pk).status == AssetStatus.ACTIVE
    assert Asset.objects.get(pk=recent.pk).status == AssetStatus.ACTIVE


def test_merge_moves_everything_and_resolves_duplicates(operator):
    source, target = AssetFactory(), AssetFactory()
    ident(source, IdentifierKind.IPV4, "10.120.0.1")
    ident(target, IdentifierKind.FQDN, "app.phylax.local")
    newer = timezone.now()
    older = newer - timedelta(days=2)
    ServiceFactory(asset=source, port=443, product="nginx-nuevo", last_seen=newer)
    ServiceFactory(asset=target, port=443, product="nginx-viejo", last_seen=older)
    ServiceFactory(asset=source, port=22, service_name="ssh")
    suggestion = CriticalitySuggestion.objects.create(asset=source)
    conflict = AssetConflict.objects.create(
        identifier_kind="IPV4", identifier_value="10.120.0.1", source="discovery"
    )
    conflict.candidate_assets.set([source, target])

    services.merge_assets(source, target, user=operator)

    source.refresh_from_db()
    assert source.status == AssetStatus.RETIRED and source.merged_into == target
    assert set(target.identifiers.values_list("value", flat=True)) == {
        "10.120.0.1",
        "app.phylax.local",
    }
    assert target.services.count() == 2
    assert target.services.get(port=443).product == "nginx-nuevo"
    suggestion.refresh_from_db()
    assert suggestion.asset == target
    conflict.refresh_from_db()
    assert conflict.resolved and conflict.resolution == ConflictResolution.MERGED
    assert services.resolve_asset([(IdentifierKind.IPV4, "10.120.0.1")]) == target


def test_merge_rejects_self_and_retired(operator):
    asset = AssetFactory()
    with pytest.raises(ValidationError):
        services.merge_assets(asset, asset, user=operator)
    with pytest.raises(ValidationError):
        services.merge_assets(AssetFactory(status=AssetStatus.RETIRED), asset, user=operator)


def test_resolve_conflict_distinct_and_merged(operator):
    a, b = AssetFactory(), AssetFactory()
    conflict = AssetConflict.objects.create(
        identifier_kind="IPV4", identifier_value="10.1.2.3", source="discovery"
    )
    conflict.candidate_assets.set([a, b])
    with pytest.raises(ValidationError):
        services.resolve_conflict(conflict, user=operator, resolution=ConflictResolution.MERGED)
    services.resolve_conflict(
        conflict, user=operator, resolution=ConflictResolution.MERGED, target=b
    )
    a.refresh_from_db()
    assert a.merged_into == b
    other = AssetConflict.objects.create(
        identifier_kind="IPV4", identifier_value="10.1.2.4", source="discovery"
    )
    other.candidate_assets.set([b, AssetFactory()])
    services.resolve_conflict(other, user=operator, resolution=ConflictResolution.DISTINCT)
    other.refresh_from_db()
    assert other.resolved and other.resolved_by == operator
    with pytest.raises(ValidationError):
        services.resolve_conflict(other, user=operator, resolution=ConflictResolution.DISMISSED)


# --- Alta manual -------------------------------------------------------------------


def test_create_asset_normalises_and_rejects_duplicates(operator):
    asset = services.create_asset(
        user=operator,
        fields={
            "name": "portal",
            "asset_type": AssetType.WEB_APP,
            "environment": "PROD",
            "business_role": "WEB_PUBLICA",
        },
        identifiers=[(IdentifierKind.FQDN, "Portal.Phylax.Local")],
        criticality="ALTO",
    )
    assert asset.status == AssetStatus.ACTIVE
    assert asset.criticality_source == CriticalitySource.MANUAL
    assert asset.identifiers.get().value == "portal.phylax.local"
    with pytest.raises(ValidationError, match="Ya existe"):
        services.create_asset(
            user=operator,
            fields={"name": "dup"},
            identifiers=[(IdentifierKind.FQDN, "portal.phylax.local")],
        )


def test_update_exposure_manual_then_inherit(operator):
    rng = NetworkRangeFactory(cidr="10.130.0.0/24", zone=Exposure.DMZ)
    asset = services.create_asset(
        user=operator, fields={"name": "x"}, identifiers=[(IdentifierKind.IPV4, "10.130.0.5")]
    )
    assert asset.network_range == rng and asset.exposure == Exposure.DMZ
    services.update_asset(asset, user=operator, exposure=Exposure.INTERNET)
    asset.refresh_from_db()
    assert (asset.exposure, asset.exposure_source) == (Exposure.INTERNET, ExposureSource.MANUAL)
    services.update_asset(asset, user=operator, exposure=None)
    asset.refresh_from_db()
    assert (asset.exposure, asset.exposure_source) == (Exposure.DMZ, ExposureSource.RANGE)


def test_add_identifier_rejects_identifier_of_other_asset(operator):
    other = AssetFactory()
    ident(other, IdentifierKind.IPV4, "10.140.0.1")
    with pytest.raises(ValidationError, match="ya pertenece"):
        services.add_identifier(AssetFactory(), IdentifierKind.IPV4, "10.140.0.1", user=operator)


# --- Contexto ---------------------------------------------------------------------


def test_asset_context_defaults_null_criticality():
    ctx = services.get_asset_context(AssetFactory(criticality=None).pk)
    assert ctx.criticality == "MEDIO" and ctx.criticality_defaulted


def test_asset_context_at_reconstructs_from_history(operator):
    asset = AssetFactory(criticality="CRITICO")
    before = timezone.now()
    services.update_asset(asset, user=operator, criticality="BAJO")
    assert services.get_asset_context(asset.pk).criticality == "BAJO"
    assert services.get_asset_context_at(asset.pk, before).criticality == "CRITICO"
    with pytest.raises(Asset.DoesNotExist):
        services.get_asset_context_at(asset.pk, before - timedelta(days=1))


# --- decide_suggestion ----------------------------------------------------------


@pytest.fixture
def ready_suggestion(db):
    from apps.llm.models import InferenceLog

    asset = AssetFactory(criticality=None)
    log = InferenceLog.objects.create(
        task="ASSET_CRITICALITY", model="m", prompt_version="v1", parsed_ok=True
    )
    return CriticalitySuggestion.objects.create(
        asset=asset, inference=log, suggested="ALTO", confidence=0.8
    )


@pytest.mark.parametrize(
    ("decision", "value", "expected", "source"),
    [
        (SuggestionState.ACCEPTED, None, "ALTO", CriticalitySource.LLM_ACCEPTED),
        (SuggestionState.EDITED, "CRITICO", "CRITICO", CriticalitySource.LLM_EDITED),
        (SuggestionState.REJECTED, None, None, None),
    ],
)
def test_decide_suggestion(ready_suggestion, operator, decision, value, expected, source):
    services.decide_suggestion(ready_suggestion.pk, user=operator, decision=decision, value=value)
    ready_suggestion.refresh_from_db()
    asset = ready_suggestion.asset
    asset.refresh_from_db()
    assert ready_suggestion.state == decision
    assert ready_suggestion.final_value == expected
    assert ready_suggestion.decided_by == operator and ready_suggestion.decided_at
    assert (asset.criticality, asset.criticality_source) == (expected, source)


def test_decide_suggestion_rules(ready_suggestion, operator, make_user):
    with pytest.raises(PermissionDenied):
        services.decide_suggestion(
            ready_suggestion.pk, user=make_user(AUDITOR), decision=SuggestionState.ACCEPTED
        )
    with pytest.raises(ValidationError):
        services.decide_suggestion(
            ready_suggestion.pk, user=operator, decision=SuggestionState.EDITED, value="ENORME"
        )
    services.decide_suggestion(
        ready_suggestion.pk, user=operator, decision=SuggestionState.REJECTED
    )
    with pytest.raises(ValidationError, match="no está pendiente"):
        services.decide_suggestion(
            ready_suggestion.pk, user=operator, decision=SuggestionState.ACCEPTED
        )


def test_processing_suggestion_cannot_be_decided(operator):
    pending = CriticalitySuggestion.objects.create(asset=AssetFactory())
    assert pending.is_processing
    with pytest.raises(ValidationError):
        services.decide_suggestion(pending.pk, user=operator, decision=SuggestionState.ACCEPTED)


def test_mark_stale_task_runs_via_celery():
    from apps.assets.tasks import mark_stale_assets

    AssetFactory(last_seen=timezone.now() - timedelta(days=60))
    assert mark_stale_assets.delay().get() == 1


def test_beat_schedule_and_routes_are_configured():
    from django.conf import settings

    tasks = {entry["task"] for entry in settings.CELERY_BEAT_SCHEDULE.values()}
    assert "apps.assets.tasks.mark_stale_assets" in tasks
    assert settings.CELERY_TASK_ROUTES["apps.llm.tasks.*"]["queue"] == "llm"

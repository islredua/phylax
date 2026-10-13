"""Admin del inventario: consulta y soporte. Sin borrado físico de activos."""

from django.contrib import admin
from simple_history.admin import SimpleHistoryAdmin

from .models import (
    Asset,
    AssetConflict,
    AssetIdentifier,
    ContainerImage,
    ContainerRegistry,
    CriticalitySuggestion,
    NetworkRange,
    SbomDocument,
    Service,
    Tag,
)


class NoDeleteMixin:
    """El inventario es evidencia: los activos se retiran, nunca se borran."""

    def has_delete_permission(self, request, obj=None):
        return False


class IdentifierInline(admin.TabularInline):
    model = AssetIdentifier
    extra = 0


@admin.register(Asset)
class AssetAdmin(NoDeleteMixin, SimpleHistoryAdmin):
    list_display = ("name", "asset_type", "status", "criticality", "exposure", "environment")
    list_filter = ("status", "asset_type", "criticality", "exposure", "environment", "origin")
    search_fields = ("name", "identifiers__value")
    inlines = [IdentifierInline]


@admin.register(NetworkRange)
class NetworkRangeAdmin(NoDeleteMixin, SimpleHistoryAdmin):
    list_display = ("name", "cidr", "zone", "environment", "in_scope", "discovery_schedule")


@admin.register(AssetIdentifier)
class AssetIdentifierAdmin(NoDeleteMixin, SimpleHistoryAdmin):
    list_display = ("kind", "value", "asset", "is_primary", "last_seen")
    search_fields = ("value",)


@admin.register(ContainerRegistry)
class ContainerRegistryAdmin(admin.ModelAdmin):
    # El token es write-only: se gestiona desde la UI de Atalaya, nunca aquí.
    exclude = ("token",)
    list_display = ("name", "url", "environment", "last_check_ok")


admin.site.register(Tag)
admin.site.register(Service)
admin.site.register(AssetConflict)
admin.site.register(ContainerImage)
admin.site.register(SbomDocument)
admin.site.register(CriticalitySuggestion)

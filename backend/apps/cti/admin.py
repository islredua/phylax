from django.contrib import admin

from .models import CtiChange, CtiSource, CtiSyncRun, CveRecord, ProductCoverage


class ReadOnlyMixin:
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(CtiSource)
class CtiSourceAdmin(admin.ModelAdmin):
    list_display = ("kind", "enabled", "interval_hours", "last_success_at", "last_status")
    readonly_fields = ("last_run_at", "last_success_at", "last_status", "last_detail")


@admin.register(CveRecord)
class CveRecordAdmin(ReadOnlyMixin, admin.ModelAdmin):
    list_display = ("cve_id", "severity", "cvss_score", "epss_score", "kev_added_at", "modified_at")
    search_fields = ("cve_id", "description")
    list_filter = ("severity",)


@admin.register(CtiSyncRun)
class CtiSyncRunAdmin(ReadOnlyMixin, admin.ModelAdmin):
    list_display = ("source", "trigger", "status", "started_at", "records_seen", "changes")


@admin.register(CtiChange)
class CtiChangeAdmin(ReadOnlyMixin, admin.ModelAdmin):
    list_display = ("kind", "cve", "created_at")
    list_filter = ("kind",)


@admin.register(ProductCoverage)
class ProductCoverageAdmin(ReadOnlyMixin, admin.ModelAdmin):
    list_display = ("product_key", "vendor", "last_pulled_at", "cve_count", "last_error")

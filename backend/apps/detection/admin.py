from django.contrib import admin

from .models import (
    DetectionEvent,
    EventBatch,
    Finding,
    FindingEvent,
    FindingEvidence,
    SoftwareComponent,
)


@admin.register(SoftwareComponent)
class SoftwareComponentAdmin(admin.ModelAdmin):
    list_display = ("asset", "source", "name", "version", "product_key", "is_current", "last_seen")
    list_filter = ("source", "is_current")
    search_fields = ("name", "product_key", "cpe", "purl")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class ReadOnly:
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class EvidenceInline(ReadOnly, admin.TabularInline):
    model = FindingEvidence
    extra = 0


class EventInline(ReadOnly, admin.TabularInline):
    model = FindingEvent
    extra = 0


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "vulnerability_id",
        "asset",
        "severity",
        "status",
        "in_kev",
        "epss_score",
        "last_seen_at",
    )
    list_filter = ("status", "severity", "in_kev")
    search_fields = ("vulnerability_id", "title", "asset__name")
    inlines = [EvidenceInline, EventInline]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(DetectionEvent)
class DetectionEventAdmin(ReadOnly, admin.ModelAdmin):
    list_display = ("kind", "status", "asset", "cve", "triage_reason", "created_at")
    list_filter = ("kind", "status")


@admin.register(EventBatch)
class EventBatchAdmin(ReadOnly, admin.ModelAdmin):
    list_display = ("source", "reference", "size", "processed_at", "stats")

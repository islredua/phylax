from django.contrib import admin

from .models import (
    AutomationLogEntry,
    AutomationSettings,
    DetectionEvent,
    EventBatch,
    Finding,
    FindingEvent,
    FindingEvidence,
    OrganizationProfile,
    PlannedAction,
    PlannerDecision,
    SoftwareComponent,
    WatchItem,
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


@admin.register(PlannerDecision)
class PlannerDecisionAdmin(ReadOnly, admin.ModelAdmin):
    list_display = (
        "action",
        "urgency",
        "asset",
        "model_requested",
        "model_mismatch",
        "fallback",
        "created_at",
    )
    list_filter = ("action", "urgency", "fallback", "model_mismatch")


@admin.register(WatchItem)
class WatchItemAdmin(admin.ModelAdmin):
    list_display = ("product_label", "product_key", "cve", "is_active", "matched_at")


@admin.register(AutomationSettings)
class AutomationSettingsAdmin(admin.ModelAdmin):
    list_display = ("mode", "paused", "escalate_critical", "max_scans_per_hour", "updated_at")


@admin.register(PlannedAction)
class PlannedActionAdmin(ReadOnly, admin.ModelAdmin):
    list_display = ("action", "status", "urgency", "priority", "asset", "not_before", "created_at")
    list_filter = ("action", "status", "urgency")


@admin.register(AutomationLogEntry)
class AutomationLogEntryAdmin(ReadOnly, admin.ModelAdmin):
    list_display = ("kind", "timestamp", "action", "user", "message")
    list_filter = ("kind",)


@admin.register(OrganizationProfile)
class OrganizationProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "sector", "location", "draft_state", "updated_at")

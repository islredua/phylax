from django.contrib import admin

from .models import CTISnapshot, CVERecord


class CVERecordInline(admin.TabularInline):
    model = CVERecord
    extra = 0
    fields = ("cve_id", "cvss_score", "epss_score", "in_kev")
    readonly_fields = fields


@admin.register(CTISnapshot)
class CTISnapshotAdmin(admin.ModelAdmin):
    list_display = ("label", "cve_count", "source_hash", "loaded_at")
    inlines = [CVERecordInline]

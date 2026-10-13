from django.contrib import admin

from .models import Finding


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "cve_id",
        "asset",
        "severity",
        "cvss_score",
        "in_kev",
        "detected_at",
        "is_synthetic",
    )
    list_filter = ("severity", "in_kev", "is_synthetic", "scanner_source")
    search_fields = ("cve_id", "asset__name")

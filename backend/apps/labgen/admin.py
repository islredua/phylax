from django.contrib import admin

from .models import SyntheticDataset


@admin.register(SyntheticDataset)
class SyntheticDatasetAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "seed",
        "assets_count",
        "findings_count",
        "cti_snapshot_hash",
        "created_at",
    )
    readonly_fields = ("created_at", "updated_at")

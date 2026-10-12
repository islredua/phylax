from django.contrib import admin

from .models import DiscoveryRun


@admin.register(DiscoveryRun)
class DiscoveryRunAdmin(admin.ModelAdmin):
    list_display = ("created_at", "profile", "network_range", "target_asset", "status")
    list_filter = ("status", "profile")
    readonly_fields = [f.name for f in DiscoveryRun._meta.fields]

    def has_add_permission(self, request):
        return False

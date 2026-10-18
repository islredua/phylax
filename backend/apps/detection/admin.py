from django.contrib import admin

from .models import SoftwareComponent


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

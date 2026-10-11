from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import AuditLogEntry, User

admin.site.register(User, UserAdmin)


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    """Solo lectura: la bitácora no se edita ni se borra desde el admin."""

    list_display = ("timestamp", "event_type", "user", "ip_address")
    list_filter = ("event_type",)
    search_fields = ("user__username",)
    date_hierarchy = "timestamp"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

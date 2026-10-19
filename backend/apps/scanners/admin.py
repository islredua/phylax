from django.contrib import admin

from .models import ToolExecution


@admin.register(ToolExecution)
class ToolExecutionAdmin(admin.ModelAdmin):
    list_display = ("tool", "profile", "asset", "status", "started_at", "findings_seen", "error")
    list_filter = ("tool", "status")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

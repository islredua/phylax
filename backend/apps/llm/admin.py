from django.contrib import admin

from .models import InferenceLog


@admin.register(InferenceLog)
class InferenceLogAdmin(admin.ModelAdmin):
    """Solo lectura: cada inferencia es evidencia para la evaluación."""

    list_display = ("created_at", "task", "model", "parsed_ok", "total_duration_ms")
    list_filter = ("task", "model", "parsed_ok")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

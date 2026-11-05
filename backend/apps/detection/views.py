"""Vistas del módulo de detección. Toda modificación pasa por los servicios (re-verifican permisos)."""

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import ListView, TemplateView

from apps.assets import catalogs
from apps.cti import services as cti
from apps.cti.models import CtiSource, CtiSyncRun, SourceKind
from apps.scanners.models import ToolExecution
from apps.scoring import services as scoring

from . import actions, activity, automation, events, findings, planner, profile
from .forms import (
    TRANSITION_LABELS,
    AutomationForm,
    FindingFilterForm,
    FindingTransitionForm,
    NoteForm,
    PauseForm,
    ProfileForm,
    ReviewForm,
    SourceForm,
)
from .models import (
    OPEN_STATUSES,
    DetectionEvent,
    Finding,
    FindingSeverity,
    FindingStatus,
    PlannedAction,
)


class Perm(PermissionRequiredMixin):
    raise_exception = True


def _messages_from(request, error):
    for message in getattr(error, "messages", [str(error)]):
        messages.error(request, message)


def _safe_next(request, default):
    target = request.POST.get("next") or request.GET.get("next")
    if target and url_has_allowed_host_and_scheme(target, {request.get_host()}):
        return target
    return default


# --------------------------------------------------------------------------
# Panel de detección
# --------------------------------------------------------------------------


def filter_findings(params):
    qs = Finding.objects.select_related("asset", "cve", "component")
    form = FindingFilterForm(params or None)
    status = ""
    if form.is_valid():
        data = form.cleaned_data
        status = data["status"]
        if data["q"]:
            qs = qs.filter(
                Q(vulnerability_id__icontains=data["q"])
                | Q(title__icontains=data["q"])
                | Q(asset__name__icontains=data["q"])
            )
        if data["severity"]:
            qs = qs.filter(severity=data["severity"])
        if data["in_kev"]:
            qs = qs.filter(in_kev=data["in_kev"] == "1")
        if data["environment"]:
            qs = qs.filter(environment=data["environment"])
        if data["source"]:
            qs = qs.filter(sources__contains=[data["source"]])
        if data["asset"]:
            qs = qs.filter(asset_id=data["asset"])
    if status == "all":
        pass
    elif status:
        qs = qs.filter(status=status)
    else:
        qs = qs.filter(status__in=OPEN_STATUSES)
    return qs, form


SEVERITY_ORDER = {s: i for i, s in enumerate(reversed(FindingSeverity.values))}


class PanelView(Perm, ListView):
    permission_required = "detection.view_finding"
    template_name = "detection/panel.html"
    context_object_name = "findings"
    paginate_by = 25

    def get_queryset(self):
        qs, self.filter_form = filter_findings(self.request.GET)
        # Prioridad del motor de scoring si existe; si no, provisional: KEV, severidad, EPSS.
        items = list(qs)
        items.sort(
            key=lambda f: (
                f.priority_score if f.priority_score is not None else -1,
                int(f.in_kev),
                SEVERITY_ORDER.get(f.severity, 0),
                f.epss_score or 0,
                f.first_detected_at,
            ),
            reverse=True,
        )
        return items

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            filter_form=self.filter_form,
            summary=findings.summary(),
            queue_size=actions.approval_queue().count(),
            automation=automation.summary(),
            scoring_available=scoring.is_available(),
        )
        return context


class FindingDetailView(Perm, TemplateView):
    permission_required = "detection.view_finding"
    template_name = "detection/finding_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        finding = get_object_or_404(
            Finding.objects.select_related("asset", "cve", "component", "status_changed_by"),
            pk=kwargs["pk"],
        )
        allowed = findings.TRANSITIONS.get(finding.status, set())
        context.update(
            finding=finding,
            evidence=finding.evidence.select_related("component"),
            timeline=finding.events.select_related("actor").order_by("-occurred_at", "-id"),
            transitions=[(s, TRANSITION_LABELS[s]) for s in TRANSITION_LABELS if s in allowed],
            can_reopen=FindingStatus.CONFIRMED in allowed and not finding.is_open,
            scoring_available=scoring.is_available(),
        )
        return context


class FindingTransitionView(Perm, View):
    permission_required = "detection.work_findings"

    def post(self, request, pk):
        form = FindingTransitionForm(request.POST)
        back = _safe_next(request, reverse("detection:finding", args=[pk]))
        if not form.is_valid():
            messages.error(request, "Elige una acción válida.")
            return HttpResponseRedirect(back)
        try:
            finding = findings.transition(
                pk,
                user=request.user,
                status=form.cleaned_data["status"],
                note=form.cleaned_data["note"],
            )
            messages.success(
                request, f"Hallazgo marcado como {finding.get_status_display().lower()}."
            )
        except ValidationError as error:
            _messages_from(request, error)
        return HttpResponseRedirect(back)


class FindingNoteView(Perm, View):
    permission_required = "detection.work_findings"

    def post(self, request, pk):
        form = NoteForm(request.POST)
        if form.is_valid():
            try:
                findings.add_note(pk, user=request.user, text=form.cleaned_data["text"])
                messages.success(request, "Nota agregada a la línea de tiempo.")
            except ValidationError as error:
                _messages_from(request, error)
        else:
            messages.error(request, "La nota está vacía.")
        return redirect("detection:finding", pk=pk)


# --------------------------------------------------------------------------
# Actividad, eventos, acciones y ejecuciones
# --------------------------------------------------------------------------


class ActivityView(Perm, TemplateView):
    permission_required = "detection.view_detectionevent"
    template_name = "detection/activity.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        kind = self.request.GET.get("kind", "")
        kinds = [kind] if kind in ("event", "decision", "action", "execution", "log") else None
        context.update(
            entries=activity.recent(kinds=kinds),
            kind=kind,
            kinds=(
                ("", "Todo"),
                ("event", "Eventos"),
                ("decision", "Decisiones"),
                ("action", "Acciones"),
                ("execution", "Herramientas"),
                ("log", "Bitácora"),
            ),
            automation=automation.summary(),
            open_actions=actions.open_actions().count(),
            planner_calls=planner.planner_calls_this_hour(),
        )
        return context

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        if request.htmx:
            return render(request, "detection/_activity_feed.html", context)
        return self.render_to_response(context)


class EventDetailView(Perm, TemplateView):
    permission_required = "detection.view_detectionevent"
    template_name = "detection/event_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        event = get_object_or_404(
            DetectionEvent.objects.select_related("asset", "cve", "batch"), pk=kwargs["pk"]
        )
        context.update(
            event=event,
            decisions=event.decisions.select_related("inference", "asset"),
            actions=event.actions.select_related("asset"),
        )
        return context


class ActionDetailView(Perm, TemplateView):
    permission_required = "detection.view_plannedaction"
    template_name = "detection/action_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        action = get_object_or_404(
            PlannedAction.objects.select_related(
                "decision", "event", "asset", "approved_by", "rejected_by", "discovery_run"
            ),
            pk=kwargs["pk"],
        )
        context.update(
            action=action,
            executions=action.executions.all(),
            log_entries=action.log_entries.select_related("user"),
        )
        return context


class ExecutionDetailView(Perm, TemplateView):
    permission_required = "scanners.view_toolexecution"
    template_name = "detection/execution_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        execution = get_object_or_404(
            ToolExecution.objects.select_related("asset", "action"), pk=kwargs["pk"]
        )
        context.update(
            execution=execution,
            findings=Finding.objects.filter(evidence__execution_ref=str(execution.pk)).distinct(),
        )
        return context


class EvaluateAssetView(Perm, View):
    """Vía manual de respaldo: «evalúa este activo ahora»."""

    permission_required = "detection.request_evaluation"

    def post(self, request, pk):
        back = _safe_next(request, f"{reverse('assets:detail', args=[pk])}?tab=hallazgos")
        try:
            event, batch = events.request_evaluation(pk, user=request.user)
        except ValidationError as error:
            _messages_from(request, error)
            return HttpResponseRedirect(back)
        from .tasks import process_event_batch

        process_event_batch.delay(str(batch.pk))
        messages.success(
            request, "Evaluación solicitada: el planificador decidirá en breve (ver Actividad)."
        )
        return HttpResponseRedirect(back)


# --------------------------------------------------------------------------
# Cola de aprobación
# --------------------------------------------------------------------------


class QueueView(Perm, TemplateView):
    permission_required = "detection.view_plannedaction"
    template_name = "detection/queue.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            queue=list(actions.approval_queue()),
            waiting=PlannedAction.objects.filter(status__in=("APPROVED", "QUEUED", "RUNNING"))
            .select_related("asset")
            .order_by("-priority")[:25],
            automation=automation.summary(),
        )
        return context


class ApproveActionView(Perm, View):
    permission_required = "detection.approve_actions"

    def post(self, request, pk):
        form = ReviewForm(request.POST)
        note = form.cleaned_data["note"] if form.is_valid() else ""
        try:
            action = actions.approve(pk, user=request.user, note=note)
            messages.success(
                request, f"{action.get_action_display()}: {action.get_status_display().lower()}."
            )
        except ValidationError as error:
            _messages_from(request, error)
        return HttpResponseRedirect(_safe_next(request, reverse("detection:queue")))


class RejectActionView(Perm, View):
    permission_required = "detection.approve_actions"

    def post(self, request, pk):
        form = ReviewForm(request.POST)
        note = form.cleaned_data["note"] if form.is_valid() else ""
        try:
            actions.reject(pk, user=request.user, note=note)
            messages.success(request, "Acción rechazada.")
        except ValidationError as error:
            _messages_from(request, error)
        return HttpResponseRedirect(_safe_next(request, reverse("detection:queue")))


class BulkQueueView(Perm, View):
    permission_required = "detection.approve_actions"

    def post(self, request):
        ids = request.POST.getlist("ids")
        decision = request.POST.get("decision", "approve")
        if not ids:
            messages.error(request, "Selecciona al menos una acción.")
            return redirect("detection:queue")
        if decision == "reject":
            done, failed = [], []
            for action_id in ids:
                try:
                    done.append(
                        actions.reject(action_id, user=request.user, note="Rechazada en lote")
                    )
                except (ValidationError, PlannedAction.DoesNotExist) as exc:
                    failed.append((action_id, str(exc)))
            label = "rechazada(s)"
        else:
            done, failed = actions.approve_many(ids, user=request.user)
            label = "aprobada(s) en lote"
        if done:
            messages.success(request, f"{len(done)} acción(es) {label}.")
        if failed:
            messages.warning(request, f"{len(failed)} acción(es) ya no esperaban aprobación.")
        return redirect("detection:queue")


class CancelActionView(Perm, View):
    permission_required = "detection.approve_actions"

    def post(self, request, pk):
        try:
            actions.cancel(pk, user=request.user)
            messages.success(request, "Acción cancelada.")
        except ValidationError as error:
            _messages_from(request, error)
        return HttpResponseRedirect(_safe_next(request, reverse("detection:queue")))


# --------------------------------------------------------------------------
# Automatización
# --------------------------------------------------------------------------


class AutomationView(Perm, View):
    permission_required = "detection.view_automationsettings"
    template_name = "detection/automation.html"

    def _context(self, form=None):
        config = automation.current_settings()
        environments = catalogs.choices(catalogs.ENVIRONMENT)
        return {
            "config": config,
            "summary": automation.summary(config),
            "form": form
            or AutomationForm(
                initial=AutomationForm.initial_for(config, environments), environments=environments
            ),
            "pause_form": PauseForm(),
            "log_entries": automation.AutomationLogEntry.objects.select_related(
                "user", "asset", "action"
            )[:40],
            "planner_calls": planner.planner_calls_this_hour(),
            "can_manage": self.request.user.has_perm("detection.manage_automation"),
        }

    def get(self, request):
        return render(request, self.template_name, self._context())

    def post(self, request):
        if not request.user.has_perm("detection.manage_automation"):
            raise PermissionDenied
        environments = catalogs.choices(catalogs.ENVIRONMENT)
        form = AutomationForm(request.POST, environments=environments)
        if form.is_valid():
            try:
                automation.update_settings(user=request.user, fields=form.settings_fields())
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, "Configuración de automatización guardada.")
                return redirect("detection:automation")
        return render(request, self.template_name, self._context(form))


class PauseView(Perm, View):
    permission_required = "detection.manage_automation"

    def post(self, request):
        form = PauseForm(request.POST)
        reason = form.cleaned_data["reason"] if form.is_valid() else ""
        paused = request.POST.get("paused") == "1"
        automation.set_paused(paused, user=request.user, reason=reason)
        messages.success(
            request, "Pausa de emergencia activada." if paused else "Automatización reanudada."
        )
        return redirect("detection:automation")


# --------------------------------------------------------------------------
# Perfil de la organización
# --------------------------------------------------------------------------


class OrganizationView(Perm, View):
    permission_required = "detection.view_organizationprofile"
    template_name = "detection/organization.html"

    def _context(self, form=None):
        current = profile.get_profile()
        return {
            "profile": current,
            "form": form
            or ProfileForm(
                initial={
                    "name": current.name,
                    "sector": current.sector,
                    "location": current.location,
                    "description": current.description,
                }
            ),
            "can_manage": self.request.user.has_perm("detection.manage_profile"),
        }

    def get(self, request):
        if request.htmx:
            return render(request, "detection/_draft_status.html", self._context())
        return render(request, self.template_name, self._context())

    def post(self, request):
        if not request.user.has_perm("detection.manage_profile"):
            raise PermissionDenied
        form = ProfileForm(request.POST)
        if form.is_valid():
            try:
                profile.update_profile(user=request.user, fields=form.cleaned_data)
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, "Perfil de la organización guardado.")
                return redirect("detection:organization")
        return render(request, self.template_name, self._context(form))


class DraftView(Perm, View):
    permission_required = "detection.manage_profile"

    def post(self, request):
        if request.POST.get("discard"):
            profile.discard_draft(user=request.user)
            messages.success(request, "Borrador descartado.")
            return redirect("detection:organization")
        try:
            profile.request_draft(user=request.user)
            messages.success(
                request, "Generando el borrador con el LLM local; la página se actualizará sola."
            )
        except ValidationError as error:
            _messages_from(request, error)
        return redirect("detection:organization")


# --------------------------------------------------------------------------
# Fuentes CTI
# --------------------------------------------------------------------------


class SourcesView(Perm, View):
    permission_required = "cti.view_ctisource"
    template_name = "detection/sources.html"

    def _context(self, forms=None):
        sources = cti.ensure_sources()
        forms = forms or {}
        rows = []
        for source in sources:
            form = forms.get(source.kind) or SourceForm(
                initial={
                    "url": source.url,
                    "enabled": source.enabled,
                    "interval_hours": source.interval_hours,
                },
                prefix=source.kind,
            )
            rows.append((source, form))
        return {
            "rows": rows,
            "stats": cti.summary(),
            "runs": CtiSyncRun.objects.select_related("requested_by")[:20],
            "can_manage": self.request.user.has_perm("cti.manage_sources"),
            "online": cti.settings.CTI_ONLINE,
        }

    def get(self, request):
        return render(request, self.template_name, self._context())

    def post(self, request):
        if not request.user.has_perm("cti.manage_sources"):
            raise PermissionDenied
        kind = request.POST.get("kind", "")
        if kind not in SourceKind.values:
            messages.error(request, "Fuente desconocida.")
            return redirect("detection:sources")
        form = SourceForm(request.POST, prefix=kind)
        if form.is_valid():
            try:
                cti.update_source(kind, user=request.user, fields=form.cleaned_data)
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, f"Fuente {SourceKind(kind).label} actualizada.")
                return redirect("detection:sources")
        return render(request, self.template_name, self._context({kind: form}))


class SyncSourceView(Perm, View):
    permission_required = "cti.manage_sources"

    def post(self, request, kind):
        if kind not in SourceKind.values:
            messages.error(request, "Fuente desconocida.")
            return redirect("detection:sources")
        source = get_object_or_404(CtiSource, kind=kind)
        if not source.enabled:
            messages.error(request, "La fuente está deshabilitada.")
            return redirect("detection:sources")
        from apps.cti.tasks import sync_cti_source

        sync_cti_source.delay(kind, request.user.pk)
        messages.success(
            request, f"Sincronización de {source.get_kind_display()} en curso (ver Actividad)."
        )
        return redirect("detection:sources")

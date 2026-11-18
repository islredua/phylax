"""Vistas del módulo de detección. Toda modificación pasa por los servicios (re-verifican permisos)."""

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Case, Count, FloatField, IntegerField, Max, Q, Value, When
from django.db.models.functions import Coalesce
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.text import slugify
from django.views import View
from django.views.generic import ListView, TemplateView

from apps.assets import catalogs
from apps.core.text import cuantos
from apps.core.views import PaginationMixin
from apps.cti import services as cti
from apps.cti.models import CtiSource, CtiSyncRun, SourceKind
from apps.scanners.models import ToolExecution
from apps.scoring import services as scoring

from . import (
    actions,
    activity,
    automation,
    business_risk_texts,
    business_risks,
    business_roles,
    consolidation,
    corrections,
    descriptions,
    events,
    exports,
    findings,
    grouping,
    planner,
    policy,
    profile,
    responsibles,
    risks,
    software,
    titles,
    verification,
)
from .forms import (
    BULK_ASSIGN,
    HUMAN_STATUS_LABELS,
    AutomationForm,
    FindingFilterForm,
    NoteForm,
    ObservationForm,
    PauseForm,
    ProfileForm,
    RejectForm,
    ReviewForm,
    RiskAssignForm,
    RiskBulkForm,
    RiskFilterForm,
    RiskTreatmentForm,
    SourceForm,
    TreatmentPolicyForm,
    VulnerabilityBulkForm,
    VulnerabilityFilterForm,
    VulnerabilityStatusForm,
)
from .models import (
    OPEN_STATUSES,
    RISK_OPEN_STATUSES,
    VULN_OPEN_STATUSES,
    Action,
    DetectionEvent,
    Finding,
    FindingSeverity,
    PlannedAction,
    Risk,
    RiskConsequence,
    RiskEvent,
    RiskEventKind,
    RiskLevel,
    Vulnerability,
    VulnerabilityStatus,
)

# Parámetros que no son filtros: con cualquier otro presente, la lista está filtrada y un
# resultado vacío significa «sin coincidencias», no «falta consolidar».
NON_FILTER_PARAMS = {"asset", "page", "per_page", "tab", "view", "export"}


def filters_active(params):
    return any(value for key, value in params.items() if key not in NON_FILTER_PARAMS)


def _export_url(request):
    """La misma lista, con sus filtros, como CSV."""
    params = request.GET.copy()
    params.pop("page", None)
    params["export"] = "csv"
    return f"?{params.urlencode()}"


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
    # ``consolidated`` va con la observación: la columna «Consolidada en» costaba una consulta
    # por fila (revisión del 2026-11-16, R2).
    qs = Finding.objects.select_related("asset", "cve", "component", "consolidated")
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
        if data["comp"]:
            # Los reportes de un software: los que lo nombran y los de sus vulnerabilidades (el de
            # Grype no lleva el componente; lo liga la vulnerabilidad que lo consolida).
            qs = qs.filter(
                Q(component_id=data["comp"]) | Q(consolidated__component_id=data["comp"])
            )
    if status == "all":
        pass
    elif status:
        qs = qs.filter(status=status)
    else:
        qs = qs.filter(status__in=OPEN_STATUSES)
    return qs, form


SEVERITY_ORDER = {s: i for i, s in enumerate(reversed(FindingSeverity.values))}


def order_findings(qs):
    """Prioridad del motor de scoring si existe; si no, provisional: KEV, severidad, EPSS.

    Ordena la base y devuelve la consulta: antes se traían todas las observaciones (más de mil
    en el laboratorio) para ordenarlas en memoria y mostrar 25 (revisión del 2026-11-16, R2)."""
    severity = Case(
        *[When(severity=value, then=Value(rank)) for value, rank in SEVERITY_ORDER.items()],
        default=Value(0),
        output_field=IntegerField(),
    )
    return qs.annotate(
        order_priority=Coalesce("priority_score", Value(-1.0), output_field=FloatField()),
        order_severity=severity,
        order_epss=Coalesce("epss_score", Value(0.0), output_field=FloatField()),
    ).order_by(
        "-order_priority", "-in_kev", "-order_severity", "-order_epss", "-first_detected_at", "-pk"
    )


# Las pestañas del activo muestran lo más urgente; el resto se ve en Riesgos y Vulnerabilidades con filtros (A1).
ASSET_TAB_LIMIT = 20


def asset_tab_context(asset, tab):
    """Datos de las pestañas Riesgos / Vulnerabilidades / Observaciones de la página del activo.

    Las tres listas viven dentro del activo para no sacar a la persona de su contexto; las
    pantallas de Riesgos y Vulnerabilidades son las mismas listas para toda la organización, con filtros.
    """
    params = {"asset": asset.pk, "status": ""}
    open_findings = findings.open_findings(asset.pk)
    ctx = {
        "asset_id": asset.pk,
        "observations_open": open_findings.count(),
        "unconsolidated": consolidation.consolidable(open_findings)
        .filter(consolidated__isnull=True)
        .count(),
        "consolidation_pending": consolidation.is_pending(asset.pk),
        "tab_limit": ASSET_TAB_LIMIT,
    }
    if tab == "riesgos":
        listed = policy.attach(list(risks.triage_order(filter_risks(params)[0])))
        ctx.update(risks=listed, matrix=risks.matrix(listed))
    elif tab == "vulnerabilidades":
        from . import descriptions

        qs = filter_vulnerabilities(params)[0]
        ctx["tab_total"] = qs.count()
        listed = list(qs[:ASSET_TAB_LIMIT])
        ctx["vulnerabilities"] = listed
        ctx["describing"] = descriptions.pending_ids([v.pk for v in listed])
    elif tab == "observaciones":
        ordered = order_findings(filter_findings(params)[0])
        ctx["tab_total"] = ordered.count()
        ctx["findings"] = list(ordered[:ASSET_TAB_LIMIT])
    return ctx


def filter_vulnerabilities(params):
    qs = Vulnerability.objects.select_related("asset", "cve", "component")
    form = VulnerabilityFilterForm(params or None)
    status = ""
    if form.is_valid():
        data = form.cleaned_data
        status = data["status"]
        if data["q"]:
            qs = qs.filter(
                Q(key__icontains=data["q"])
                | Q(title__icontains=data["q"])
                | Q(asset__name__icontains=data["q"])
            )
        if data["severity"]:
            qs = qs.filter(severity=data["severity"])
        if data["in_kev"]:
            qs = qs.filter(in_kev=data["in_kev"] == "1")
        if data["environment"]:
            qs = qs.filter(environment=data["environment"])
        if data["overdue"]:
            qs = qs.filter(in_kev=True, kev_due_at__lt=timezone.localdate())
        if data["exploitable"]:
            qs = qs.filter(Q(in_kev=True) | Q(cvss_score__gte=9))
        if data["status_source"]:
            qs = qs.filter(status_source=data["status_source"])
        if data["source"]:
            qs = qs.filter(observations__sources__contains=[data["source"]]).distinct()
        if data["component"]:
            words = data["component"].split()
            for word in words:
                qs = qs.filter(
                    Q(component__name__icontains=word)
                    | Q(component__vendor__icontains=word)
                    | Q(component__version__icontains=word)
                    | Q(title__icontains=word)
                )
        if data["days"]:
            cutoff = timezone.now() - timezone.timedelta(days=data["days"])
            qs = qs.filter(Q(status_at__gte=cutoff) | Q(resolved_at__gte=cutoff))
        if data["asset"]:
            qs = qs.filter(asset_id=data["asset"])
        if data["comp"] == grouping.NO_COMPONENT:
            qs = qs.filter(component__isnull=True)
        elif data["comp"]:
            qs = qs.filter(component_id=data["comp"])
    if status == "all":
        pass
    elif status == "resolved":
        qs = qs.filter(status__in=consolidation.RESOLVED_STATUSES)
    elif status:
        qs = qs.filter(status=status)
    else:
        qs = qs.filter(status__in=VULN_OPEN_STATUSES)
    return qs, form


class PanelView(Perm, PaginationMixin, ListView):
    """Vulnerabilidades consolidadas, vistas por su corrección o una por una.

    «Por corrección» (lo normal) da una fila por lo que hay que hacer: actualizar un software en
    un activo (y con eso resolver todas sus fallas) o cambiar una configuración. Es la unidad de
    trabajo de quien remedia. «Una por una» es la lista de siempre, ordenada por puntaje
    contextual. Las dos salen de la misma consulta filtrada, así que filtros y cifras coinciden.
    """

    permission_required = "detection.view_vulnerability"
    template_name = "detection/panel.html"
    context_object_name = "vulnerabilities"
    paginate_by = 25

    def get_queryset(self):
        self.flat, self.filter_form = filter_vulnerabilities(self.request.GET)
        self.mode = grouping.view_mode(self.request.GET)
        return grouping.groups(self.flat) if self.mode == grouping.BY_CORRECTION else self.flat

    def get(self, request, *args, **kwargs):
        if exports.wants_csv(request):
            # Una fila por vulnerabilidad aunque la lista esté agrupada por software.
            flat, _ = filter_vulnerabilities(request.GET)
            return exports.csv_response(
                "vulnerabilidades",
                exports.VULNERABILITY_COLUMNS,
                exports.vulnerability_rows(flat.order_by("-contextual_score", "key")),
            )
        return super().get(request, *args, **kwargs)

    def get_paginate_by(self, queryset):
        size = super().get_paginate_by(queryset)
        return max(size, grouping.PAGE_SIZE) if self.mode == grouping.BY_CORRECTION else size

    def _view_url(self, mode):
        """La misma lista en la otra vista. Al volver a «por corrección» se suelta el software
        elegido (y el activo que vino con él) para ver de nuevo todas las correcciones."""
        params = self.request.GET.copy()
        params.pop("page", None)
        params["view"] = mode
        if mode == grouping.BY_CORRECTION and params.get("comp"):
            params.pop("comp", None)
            params.pop("asset", None)
        return f"?{params.urlencode()}"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        data = self.filter_form.cleaned_data if self.filter_form.is_valid() else {}
        asset_id = data.get("asset")
        grouped = self.mode == grouping.BY_CORRECTION
        listed = [] if grouped else list(context["vulnerabilities"])
        comp = data.get("comp") or ""
        component = None
        if comp and comp != grouping.NO_COMPONENT:
            from .models import SoftwareComponent

            component = SoftwareComponent.objects.filter(pk=comp).first()
        open_reports = findings.open_findings(asset_id)
        context.update(
            filter_form=self.filter_form,
            summary=consolidation.summary(asset_id),
            observations_open=open_reports.count(),
            unconsolidated=consolidation.consolidable(open_reports)
            .filter(consolidated__isnull=True)
            .count(),
            asset_id=asset_id,
            consolidation_pending=consolidation.is_pending(asset_id) if asset_id else False,
            queue_size=actions.approval_queue().count(),
            automation=automation.summary(),
            filters_active=filters_active(self.request.GET),
            describing=descriptions.pending_ids([v.pk for v in listed]),
            bulk_statuses=list(HUMAN_STATUS_LABELS.items()),
            view=self.mode,
            vulnerabilities=listed,
            groups=grouping.decorate(context["vulnerabilities"], self.flat, self.request.GET)
            if grouped
            else [],
            total_vulnerabilities=self.flat.count() if grouped else context["paginator"].count,
            total_groups=context["paginator"].count
            if grouped
            else grouping.groups(self.flat).count(),
            export_url=_export_url(self.request),
            correction_url=self._view_url(grouping.BY_CORRECTION),
            list_url=self._view_url(grouping.ONE_BY_ONE),
            software_label=component.label
            if component
            else (grouping.NO_COMPONENT_LABEL if comp else ""),
            software_correction_url=corrections.url(component.asset_id, component.pk)
            if component
            else "",
            query=self.request.GET.urlencode(),
        )
        return context


class VulnerabilityBulkView(Perm, View):
    """Triaje en lote: el mismo estado (y nota) para todas las vulnerabilidades marcadas."""

    permission_required = "detection.work_findings"

    def post(self, request):
        from django.http import QueryDict

        back = _safe_next(request, reverse("detection:panel"))
        ids = request.POST.getlist("ids")
        group_keys = request.POST.getlist("groups")
        if group_keys:
            # Un grupo marcado son sus vulnerabilidades dentro de los filtros con los que se veía.
            listed, _form = filter_vulnerabilities(QueryDict(request.POST.get("query", "")[:2000]))
            ids = [*ids, *(str(pk) for pk in grouping.members(listed, group_keys))]
        form = VulnerabilityBulkForm(request.POST)
        if not ids:
            messages.error(request, "Marca al menos una vulnerabilidad o una corrección.")
            return HttpResponseRedirect(back)
        if not form.is_valid():
            messages.error(request, "Elige el estado que quieres fijar.")
            return HttpResponseRedirect(back)
        done, failed = 0, []
        for vuln_id in ids:
            try:
                consolidation.set_status(
                    vuln_id,
                    user=request.user,
                    status=form.cleaned_data["status"],
                    note=form.cleaned_data["note"],
                )
                done += 1
            except (ValueError, Vulnerability.DoesNotExist) as error:
                failed.append(str(error))
        label = HUMAN_STATUS_LABELS[form.cleaned_data["status"]].lower()
        if done:
            scope = (
                f" de {cuantos(len(group_keys), 'corrección', 'correcciones')}"
                if group_keys and not request.POST.getlist("ids")
                else ""
            )
            messages.success(
                request,
                f"{done} vulnerabilidad{'es' if done != 1 else ''}{scope} → {label}, fijado por ti.",
            )
        if failed:
            messages.error(request, f"{len(failed)} no se cambiaron: {failed[0]}")
        return HttpResponseRedirect(back)


def verification_plan(vuln, observations):
    """«Qué falta para decidir» de una vulnerabilidad por verificar: el motivo de la duda en
    palabras y los pasos que el sistema puede dar (escanear, reescanear) o que la persona decide
    (no aplica). Sin pasos no hay bloque vacío: se explica qué sí se puede hacer."""
    from . import capabilities

    if vuln.status != VulnerabilityStatus.NEEDS_VERIFICATION:
        return None
    import re

    flags = list(vuln.rule_flags or [])
    reasons = []
    for flag in flags:
        quoted = re.search(r"«([^»]+)»", flag)
        value = quoted.group(1) if quoted else ""
        if flag.startswith("versión imprecisa"):
            reasons.append(
                f"nmap solo pudo leer la versión «{value}», que es imprecisa: el cruce con NVD no "
                "puede saber si la versión instalada cae en el rango afectado."
            )
        elif flag.startswith("paquete de distribución"):
            reasons.append(
                f"La versión «{value}» es un paquete de la distribución: suele corregir el fallo "
                "sin cambiar el número de versión, así que el cruce con NVD puede ser un falso "
                "positivo (parche retroportado)."
            )
        elif flag.startswith("software no observado"):
            reasons.append(
                f"La plantilla habla de {flag[len('software no observado: '):]}, que no aparece "
                "en el software observado del activo."
            )
    if not reasons:
        reasons.append(
            "La IA no encontró evidencia directa (versión exacta en rango, varias fuentes o "
            "comparador específico) y por eso no la dio por probable."
        )
    caps = capabilities.for_asset(vuln.asset_id)
    sources = {s for f in observations for s in (f.sources or [])}
    steps = []
    if str(Action.DETECT_VULNS) in caps.allowed_actions and "NUCLEI" not in sources:
        steps.append(
            {
                "key": "detect",
                "label": "Detectar con herramienta",
                "help": "nuclei prueba el CVE contra el servicio y responde si lo encuentra.",
            }
        )
    if str(Action.RESCAN_SERVICES) in caps.allowed_actions:
        steps.append(
            {
                "key": "rescan",
                "label": "Reescanear servicios",
                "help": "Vuelve a leer las versiones con nmap; puede precisar la versión.",
            }
        )
    blocker = caps.scan_blocker if not caps.can_scan_network else ""
    return {"reasons": reasons, "steps": steps, "blocker": blocker}


class VulnerabilityVerifyView(Perm, View):
    """Botones de «Qué falta para decidir»: escanear con herramienta o reescanear servicios."""

    permission_required = "detection.request_evaluation"

    def post(self, request, pk):
        vuln = get_object_or_404(Vulnerability.objects.select_related("asset"), pk=pk)
        back = _safe_next(request, reverse("detection:vulnerability", args=[pk]))
        mode = request.POST.get("mode", "detect")
        action = Action.RESCAN_SERVICES if mode == "rescan" else Action.DETECT_VULNS
        try:
            planned = actions.request_manual(
                vuln.asset_id,
                action,
                user=request.user,
                reason=f"Verificar «{vuln.title}» ({vuln.key}) pedida desde la vulnerabilidad.",
            )
        except (ValidationError, PermissionDenied) as error:
            _messages_from(request, error)
            return HttpResponseRedirect(back)
        consolidation.add_note(
            pk,
            user=request.user,
            text=f"Pidió «{planned.get_action_display()}» para verificarla "
            f"({planned.get_status_display().lower()}).",
        )
        if planned.status in ("PROPOSED", "NEEDS_REVIEW"):
            messages.success(
                request,
                f"{planned.get_action_display()} propuesta: espera aprobación en la cola "
                "(modo manual).",
            )
        else:
            messages.success(
                request,
                f"{planned.get_action_display()}: {planned.get_status_display().lower()}. "
                "Al terminar, la consolidación vuelve a decidir el estado.",
            )
        return HttpResponseRedirect(back)


class VulnerabilityDetailView(Perm, TemplateView):
    permission_required = "detection.view_vulnerability"
    template_name = "detection/vulnerability_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        vuln = get_object_or_404(
            Vulnerability.objects.select_related(
                "asset", "cve", "component", "status_by", "inference"
            ),
            pk=kwargs["pk"],
        )
        from . import descriptions

        # Sin descripción en español y con modelo disponible: se redacta sola al abrir el detalle.
        description_pending = descriptions.is_pending(vuln.pk) or descriptions.request_description(
            vuln, requested_by=self.request.user
        )
        observations = list(
            vuln.observations.select_related("component").prefetch_related("evidence")
        )
        correction = corrections.of_vulnerability(vuln)
        context.update(
            vuln=vuln,
            observations=observations,
            description_pending=description_pending,
            correction=correction,
            steps=corrections.steps(vuln, correction),
            feeds=corrections.feeds_of(vuln),
            technical=technical_details(vuln, observations),
            origin=origin_story(vuln, observations),
            timeline=vuln.events.select_related("actor").order_by("-occurred_at", "-id"),
            statuses=[(s, HUMAN_STATUS_LABELS[s]) for s in HUMAN_STATUS_LABELS if s != vuln.status],
            consolidation_pending=consolidation.is_pending(vuln.asset_id),
            baselines=scoring.baselines(
                cvss=vuln.cvss_score, epss=vuln.epss_score, severity=vuln.severity
            ),
            verification=verification_plan(vuln, observations),
            next_vuln=next_in_asset(vuln),
            pending_action=PlannedAction.objects.filter(
                asset_id=vuln.asset_id,
                status__in=("PROPOSED", "NEEDS_REVIEW", "APPROVED", "QUEUED", "RUNNING"),
                action__in=(Action.DETECT_VULNS, Action.RESCAN_SERVICES),
            )
            .order_by("-created_at")
            .first(),
        )
        return context


def next_in_asset(vuln):
    """La siguiente vulnerabilidad abierta del mismo activo en orden de triaje (puntaje
    contextual), para revisar una tras otra sin volver a la lista."""
    if vuln.status not in VULN_OPEN_STATUSES:
        return None
    ordered = list(
        Vulnerability.objects.filter(asset_id=vuln.asset_id, status__in=VULN_OPEN_STATUSES)
        .order_by("-contextual_score", "pk")
        .values_list("pk", flat=True)
    )
    try:
        index = ordered.index(vuln.pk)
    except ValueError:
        return None
    return (
        Vulnerability.objects.filter(pk=ordered[index + 1]).first()
        if index + 1 < len(ordered)
        else None
    )


class VulnerabilityDescriptionView(Perm, View):
    """Fragmento «Descripción» del detalle; se consulta mientras la IA la redacta."""

    permission_required = "detection.view_vulnerability"

    def get(self, request, pk):
        from . import descriptions

        vuln = get_object_or_404(Vulnerability.objects.select_related("asset", "component"), pk=pk)
        return render(
            request,
            "detection/_vulnerability_description.html",
            {
                "vuln": vuln,
                "description_pending": descriptions.is_pending(vuln.pk),
                "steps": corrections.steps(vuln),
            },
        )


class CorrectionView(Perm, TemplateView):
    """La corrección de un software en un activo: qué hacer, qué es, por qué importa, a qué riesgo
    alimenta, sus vulnerabilidades y la evidencia. Se arma al leer (``corrections.card``)."""

    permission_required = "detection.view_vulnerability"
    template_name = "detection/correction.html"

    def get_context_data(self, **kwargs):
        from apps.assets.models import Asset

        from .models import SoftwareComponent

        context = super().get_context_data(**kwargs)
        asset = get_object_or_404(Asset, pk=kwargs["asset_id"])
        component = get_object_or_404(SoftwareComponent, pk=kwargs["component_id"], asset=asset)
        card = corrections.card(asset, component, user=self.request.user)
        if not card["vulnerabilities"] and not card["resolved"]:
            raise Http404("Este software no tiene vulnerabilidades en este activo.")
        context.update(
            card=card,
            asset=asset,
            component=component,
            bulk_statuses=list(HUMAN_STATUS_LABELS.items()),
            describing=descriptions.pending_ids([v.pk for v in card["vulnerabilities"]]),
        )
        return context


class SoftwareDescriptionView(Perm, View):
    """El «Qué es» de un software: el fragmento que se consulta mientras la IA lo escribe (GET) y
    la corrección de una persona (POST; con el texto vacío vuelve a escribirlo la IA)."""

    permission_required = "detection.view_vulnerability"

    def _component(self, component_id):
        from .models import SoftwareComponent

        return get_object_or_404(SoftwareComponent.objects.select_related("asset"), pk=component_id)

    def get(self, request, component_id):
        component = self._component(component_id)
        what = software.for_component(component)
        return render(
            request,
            "detection/_software_description.html",
            {
                "component": component,
                "card": {
                    "name": titles.software_name(component) or component.label,
                    "what": what if what and what.known and what.summary else None,
                    "what_unknown": bool(what and not what.known),
                    "what_pending": software.is_pending(software.key_of(component)),
                },
            },
        )

    def post(self, request, component_id):
        if not request.user.has_perm("detection.work_findings"):
            raise PermissionDenied
        component = self._component(component_id)
        back = _safe_next(request, corrections.url(component.asset_id, component.pk))
        found = software.set_by_person(component, request.POST.get("summary", ""), request.user)
        if found is None:
            messages.success(request, "Descripción borrada: la IA la volverá a escribir.")
        else:
            messages.success(
                request,
                f"Descripción de {found.name} guardada a tu nombre; vale para todos los activos "
                "que tienen este software y la IA ya no la cambia.",
            )
        return HttpResponseRedirect(back)


def origin_story(vuln, observations):
    """La cadena que llevó a esta vulnerabilidad: software visto → inteligencia → herramientas.

    Cada paso es ``{"when", "what", "source"}`` ordenado en el tiempo, para que quien lee entienda
    de dónde salió sin recorrer tres tarjetas.
    """
    from apps.cti.models import CtiSource

    steps = []
    comp = vuln.component
    if comp:
        if comp.source == "SBOM" and comp.sbom_id and comp.sbom:
            steps.append(
                {
                    "when": comp.sbom.uploaded_at,
                    "what": f"El SBOM «{comp.sbom.original_filename}» declara {comp.label}.",
                    "source": "Inventario",
                }
            )
        else:
            # comp.label ya incluye «· 25/tcp» cuando hay puerto: no se repite.
            steps.append(
                {
                    "when": comp.first_seen,
                    "what": f"El descubrimiento observó {comp.label} en el activo.",
                    "source": "Inventario",
                }
            )
    cve = vuln.cve if vuln.cve_id else None
    if cve:
        pub = f" publicado el {cve.published_at:%Y-%m-%d}" if cve.published_at else ""
        steps.append(
            {
                "when": cve.last_synced_at,
                "what": f"{cve.cve_id}{pub} está en el espejo local de NVD (última sincronización "
                f"de este registro).",
                "source": "Inteligencia",
            }
        )
    by_source = {}
    for f in observations:
        for src in f.sources or ["MANUAL"]:
            when = f.first_detected_at
            if src not in by_source or when < by_source[src]:
                by_source[src] = when
    what = {
        "CTI_MATCH": "El cruce del software inventariado con el espejo de NVD emparejó la versión "
        "observada con el rango afectado.",
        "GRYPE": "Grype confirmó la vulnerabilidad en el SBOM del activo.",
        "NUCLEI": "nuclei la comprobó contra el servicio expuesto.",
        "MANUAL": "Una persona la registró a mano.",
    }
    for src, when in sorted(by_source.items(), key=lambda kv: kv[1]):
        steps.append(
            {"when": when, "what": what.get(src, src), "source": SOURCE_LABELS.get(src, src)}
        )
    if cve:
        syncs = {s.kind: s.last_success_at for s in CtiSource.objects.all()}
        intel = []
        if vuln.in_kev and syncs.get("KEV"):
            intel.append(f"KEV sincronizado el {syncs['KEV']:%Y-%m-%d}")
        if vuln.epss_score is not None and syncs.get("EPSS"):
            intel.append(f"EPSS del {syncs['EPSS']:%Y-%m-%d}")
        if intel:
            steps.append(
                {
                    "when": max(v for k, v in syncs.items() if k in ("KEV", "EPSS") and v),
                    "what": "La inteligencia se actualizó: " + ", ".join(intel) + ".",
                    "source": "Inteligencia",
                }
            )
    steps.sort(key=lambda st: st["when"] or timezone.now())
    return steps


SOURCE_LABELS = {
    "CTI_MATCH": "Inteligencia (NVD)",
    "GRYPE": "Grype (SBOM)",
    "NUCLEI": "nuclei",
    "MANUAL": "Manual",
}


def technical_details(vuln, observations):
    """Datos técnicos deterministas del detalle, sacados de la evidencia de cada observación."""
    sources, templates, matched, fixes, cwes, matches, artifacts = (
        set(),
        {},
        set(),
        set(),
        set(),
        [],
        set(),
    )
    for f in observations:
        sources.update(f.sources or [])
        for ev in f.evidence.all():
            data = ev.data or {}
            meta = data.get("template") or {}
            if data.get("template-id") or meta.get("name"):
                templates[data.get("template-id") or meta.get("name")] = meta.get("name") or ""
            raw_cwe = meta.get("cwe") or meta.get("cwe-id") or []
            cwes.update([raw_cwe] if isinstance(raw_cwe, str) else raw_cwe)
            if data.get("matched-at"):
                matched.add(str(data["matched-at"])[:120])
            if data.get("fix"):
                fixes.add(str(data["fix"])[:160])
            if data.get("affected_range"):
                matches.append(
                    {
                        "product": data.get("product_key", ""),
                        "version": data.get("version", ""),
                        "range": data["affected_range"],
                        "confidence": data.get("confidence", ""),
                    }
                )
            if data.get("artifact"):
                art = data["artifact"]
                artifacts.add(
                    f"{art.get('name', '')} {art.get('version', '')}".strip()
                    if isinstance(art, dict)
                    else str(art)[:120]
                )
    return {
        "sources": sorted(sources),
        "templates": sorted(templates.items()),
        "matched": sorted(matched),
        "fixes": sorted(fixes),
        "cwes": sorted(cwes),
        "matches": matches,
        "artifacts": sorted(artifacts),
    }


class VulnerabilityStatusView(Perm, View):
    permission_required = "detection.work_findings"

    def post(self, request, pk):
        form = VulnerabilityStatusForm(request.POST)
        back = _safe_next(request, reverse("detection:vulnerability", args=[pk]))
        if not form.is_valid():
            messages.error(request, "Elige un estado válido.")
            return HttpResponseRedirect(back)
        try:
            vuln = consolidation.set_status(
                pk,
                user=request.user,
                status=form.cleaned_data["status"],
                note=form.cleaned_data["note"],
            )
            messages.success(
                request,
                f"Estado fijado por ti: {vuln.get_status_display().lower()}. La IA ya no lo cambiará.",
            )
        except ValueError as error:
            messages.error(request, str(error))
        return HttpResponseRedirect(back)


class VulnerabilityReleaseView(Perm, View):
    permission_required = "detection.work_findings"

    def post(self, request, pk):
        consolidation.release_to_ai(pk, user=request.user)
        messages.success(request, "El estado vuelve a decidirlo la IA en la próxima consolidación.")
        return redirect("detection:vulnerability", pk=pk)


class VulnerabilityNoteView(Perm, View):
    permission_required = "detection.work_findings"

    def post(self, request, pk):
        form = NoteForm(request.POST)
        if form.is_valid():
            consolidation.add_note(pk, user=request.user, text=form.cleaned_data["text"])
            messages.success(request, "Nota agregada a la línea de tiempo.")
        else:
            messages.error(request, "La nota está vacía.")
        return redirect("detection:vulnerability", pk=pk)


class ConsolidateAssetView(Perm, View):
    """«Reevaluar con IA»: consolida ahora las observaciones del activo (cola llm, sin retardo)."""

    permission_required = "detection.request_evaluation"

    def post(self, request, pk):
        back = _safe_next(request, f"{reverse('detection:panel')}?asset={pk}")
        if consolidation.is_pending(pk):
            messages.info(request, "Ya hay una consolidación en cola para este activo.")
        elif consolidation.request_consolidation(
            pk, reason="reevaluación pedida a mano", requested_by=request.user, delay=0
        ):
            messages.success(
                request, "Consolidación con IA en cola; la página se actualizará sola."
            )
        else:
            messages.info(request, "El activo no tiene reportes que consolidar.")
        return HttpResponseRedirect(back)


def filter_risks(params, user=None):
    qs = (
        Risk.objects.select_related("asset", "decided_by")
        .prefetch_related("vulnerabilities")
        .annotate(
            kev_count=Count(
                "vulnerabilities", filter=Q(vulnerabilities__in_kev=True), distinct=True
            ),
            epss_max=Max("vulnerabilities__epss_score"),
        )
    )
    form = RiskFilterForm(params or None)
    status = ""
    if form.is_valid():
        data = form.cleaned_data
        status = data["status"]
        if data["q"]:
            qs = qs.filter(
                Q(title__icontains=data["q"])
                | Q(scenario__icontains=data["q"])
                | Q(details__icontains=data["q"])
                | Q(asset__name__icontains=data["q"])
            )
        if data["level"]:
            qs = qs.filter(level=data["level"])
        if data["treatment"] == "none":
            qs = qs.filter(treatment="")
        elif data["treatment"]:
            qs = qs.filter(treatment=data["treatment"])
        if data["kev_overdue"]:
            qs = qs.filter(risks.kev_overdue_filter()).distinct()
        if data["owner"]:
            qs = qs.filter(responsibles.name_filter(data["owner"]))
        if data["mine"]:
            # «A mi nombre»: asignados a quien mira o heredados de sus activos.
            qs = qs.filter(responsibles.mine_filter(user)) if user is not None else qs.none()
        if data["unassigned"]:
            qs = qs.filter(responsibles.unassigned_filter())
        if data["overdue"]:
            qs = qs.filter(risks.followup_overdue_filter())
        if data["policy_overdue"]:
            qs = qs.filter(policy.overdue_filter())
        if data["likelihood"]:
            qs = qs.filter(likelihood=data["likelihood"])
        if data["impact"]:
            qs = qs.filter(impact=data["impact"])
        if data["asset"]:
            qs = qs.filter(asset_id=data["asset"])
    if status == "all":
        pass
    elif status:
        qs = qs.filter(status=status)
    else:
        qs = qs.filter(status__in=("OPEN", "TREATED", "ACCEPTED"))
    from django.db.models import OuterRef, Subquery

    qs = qs.annotate(
        closed_reason=Subquery(
            RiskEvent.objects.filter(risk=OuterRef("pk"), kind=RiskEventKind.CLOSED)
            .order_by("-occurred_at", "-id")
            .values("message")[:1]
        )
    )
    return policy.with_kev_due(responsibles.with_people(qs)), form


QUEUE_LIMIT = 500
QUEUE_LABELS = (
    ("mine", "escenarios a tu nombre"),
    ("policy_overdue", "escenarios fuera del plazo de la política"),
    ("kev_overdue", "escenarios con plazo de CISA vencido"),
    ("overdue", "escenarios con seguimiento vencido"),
    ("treatment", "escenarios sin tratamiento decidido"),
)
# El registro se abre por riesgo de la organización; con ``view=escenario``, o con cualquier
# filtro que solo tiene sentido escenario por escenario, se abre la lista de escenarios.
SCENARIO_VIEW = "escenario"
RISK_VIEW = "riesgo"
RISK_VIEW_PARAMS = {"level", "treatment", "view"}
# La casilla de la matriz de riesgos. Solo con ``view=riesgo``: sin él esos dos parámetros son los
# de la matriz de escenarios (Inicio, la ficha del activo) y abren la lista de escenarios.
RISK_CELL_PARAMS = {"likelihood", "impact"}


def risk_queue(query, current_pk=None, user=None):
    """Cola de trabajo sobre el registro: los riesgos que cumplen ``query`` (los mismos filtros
    de la lista), en orden de trabajo, para atenderlos uno tras otro sin volver a la lista.

    Devuelve ``None`` si la consulta no es válida o no queda nada; si no, cuántos quedan, la
    posición del riesgo actual (``None`` si ya salió de la cola, p. ej. porque se acaba de
    decidir), el enlace al siguiente y a la lista.
    """
    from urllib.parse import quote

    from django.http import QueryDict

    query = (query or "").lstrip("?")[:500]
    qs, form = filter_risks(QueryDict(query), user=user)
    if not form.is_valid():
        return None
    pks = list(risks.triage_order(qs).values_list("pk", flat=True)[:QUEUE_LIMIT])
    list_url = f"{reverse('detection:risks')}?{query}"
    if "view=" not in query:
        list_url += f"{'&' if query else ''}view={SCENARIO_VIEW}"
    label = next(
        (text for key, text in QUEUE_LABELS if f"{key}=" in query), "escenarios de la lista"
    )

    def url_for(pk):
        return f"{reverse('detection:risk', args=[pk])}?cola={quote(query, safe='')}#tratamiento"

    position = pks.index(current_pk) if current_pk in pks else None
    if position is None:
        following = pks[0] if pks else None
    else:
        following = pks[position + 1] if position + 1 < len(pks) else None
    return {
        "query": query,
        "label": label,
        "total": len(pks),
        "position": position + 1 if position is not None else None,
        "first_url": url_for(pks[0]) if pks else "",
        "next_url": url_for(following) if following else "",
        "list_url": list_url,
    }


class RiskRegisterView(Perm, PaginationMixin, ListView):
    """Registro de riesgos (ISO/IEC 27005), en dos vistas.

    **Por riesgo** (lo normal): lo que la organización puede perder en cada función de negocio
    (``business_risks``), con su mapa función × consecuencia. **Por escenario**: el riesgo en
    cada activo, que es donde se trabaja (filtros, colas, decisión en lote, matriz 5×5).
    """

    permission_required = "detection.view_risk"
    template_name = "detection/risks.html"
    context_object_name = "risks"
    paginate_by = 25

    @property
    def by_risk(self):
        """¿Toca la vista por riesgo? Solo si nadie pidió escenarios ni puso un filtro que
        solo se entiende escenario por escenario (un activo, un responsable, un plazo…)."""
        params = self.request.GET
        view = params.get("view", "")
        active = {key for key, value in params.items() if value} - {"export"}
        allowed = RISK_VIEW_PARAMS | (RISK_CELL_PARAMS if view == RISK_VIEW else set())
        return (
            view != SCENARIO_VIEW
            and active <= allowed
            and params.get("treatment", "") in ("", "none")
        )

    def cell(self):
        """La casilla (probabilidad, impacto) pedida en la matriz de riesgos; ``None`` = todas."""
        scale = {str(n): n for n in range(1, 6)}
        return scale.get(self.request.GET.get("likelihood", "")), scale.get(
            self.request.GET.get("impact", "")
        )

    def business(self):
        """Los riesgos de la organización que se listan y todos los abiertos (para el mapa)."""
        params = self.request.GET
        found = business_risks.register(rules=policy.current())
        level = params.get("level") if params.get("level") in RiskLevel.values else ""
        undecided = params.get("treatment") == "none"
        likelihood, impact = self.cell()
        shown = [
            r
            for r in found
            if (not level or r.level == level)
            and (not undecided or r.undecided)
            and (likelihood is None or r.likelihood == likelihood)
            and (impact is None or r.impact == impact)
        ]
        return shown, found

    def get_queryset(self):
        qs, self.filter_form = filter_risks(self.request.GET, user=self.request.user)
        return risks.triage_order(qs) if not self.by_risk else qs.none()

    def get(self, request, *args, **kwargs):
        if exports.wants_csv(request):
            if self.by_risk:
                return exports.csv_response(
                    "riesgos",
                    exports.BUSINESS_RISK_COLUMNS,
                    exports.business_risk_rows(self.business()[0]),
                )
            # «Exportar lo filtrado»: la misma consulta y el mismo orden que la lista, sin paginar.
            return exports.csv_response(
                "escenarios", exports.RISK_COLUMNS, exports.risk_rows(self.get_queryset())
            )
        return super().get(request, *args, **kwargs)

    def _view_url(self, view):
        """La otra vista del registro. Al cambiar de vista se sueltan los filtros: los de una
        no significan lo mismo en la otra."""
        base = reverse("detection:risks")
        return f"{base}?view={SCENARIO_VIEW}" if view == SCENARIO_VIEW else base

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            by_risk=self.by_risk,
            risk_view_url=self._view_url(""),
            scenario_view_url=self._view_url(SCENARIO_VIEW),
            open_scenarios=Risk.objects.filter(status__in=RISK_OPEN_STATUSES).count(),
            open_risks=business_risks.counts()["open"],
        )
        if self.by_risk:
            shown, found = self.business()
            context.update(
                business=shown,
                business_summary=business_risks.summary(found),
                grid=business_risks.grid(found),
                # Cada riesgo, en la casilla de su peor escenario.
                risk_matrix=risks.matrix(found),
                cell_filter=self.cell() if any(self.cell()) else None,
                roles=business_risks.role_cards(found, self.request.user),
                today=risks.today(user=self.request.user),
                export_url=_export_url(self.request),
                filters_active=filters_active(self.request.GET),
                level_filter=self.request.GET.get("level", ""),
                undecided_filter=self.request.GET.get("treatment") == "none",
            )
            return context
        asset_id = (
            self.filter_form.cleaned_data.get("asset") if self.filter_form.is_valid() else None
        )
        listed = list(self.object_list)
        rules = policy.current()
        context["risks"] = policy.attach(list(context["risks"]), rules)
        context.update(
            policy=rules,
            bulk_treatments=list(Risk._meta.get_field("treatment").choices),
            bulk_assign=BULK_ASSIGN,
            filter_form=self.filter_form,
            summary=risks.summary(asset_id),
            matrix=risks.matrix(listed),
            asset_id=asset_id,
            # Lo que cada enlace de la página debe conservar: el activo o la vista por escenario.
            scope=f"&asset={asset_id}" if asset_id else f"&view={SCENARIO_VIEW}",
            asset=listed[0].asset if asset_id and listed else None,
            consolidation_pending=consolidation.is_pending(asset_id) if asset_id else False,
            today=risks.today(asset_id, user=self.request.user),
            owners=responsibles.by_responsible(asset_id, user=self.request.user),
            responsible_choices=responsibles.choices(),
            export_url=_export_url(self.request),
            filters_active=filters_active(self.request.GET),
        )
        if asset_id and context["asset"] is None:
            from apps.assets.models import Asset

            context["asset"] = Asset.objects.filter(pk=asset_id).first()
        return context


class RiskDetailView(Perm, TemplateView):
    permission_required = "detection.view_risk"
    template_name = "detection/risk_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        risk = get_object_or_404(
            responsibles.with_people(Risk.objects.select_related("decided_by", "assigned_by")),
            pk=kwargs["pk"],
        )
        rules = policy.current()
        due = policy.deadline(risk, rules)
        intel = risks.intelligence(risk.vulnerabilities.select_related("cve"))
        closure = risks.closure(risk)
        responsible = responsibles.of(risk)
        context.update(
            brief=risks.brief(
                risk, intel=intel, deadline=due, closure=closure, responsible=responsible
            ),
            # La lectura de inteligencia tiene su sección: en «Detalles» no se repite.
            details_text=risks.details_without_support(risk.details),
            policy=rules,
            deadline=due,
            # Fecha compromiso propuesta: el plazo de la política mientras se pueda cumplir.
            suggested_target=risk.target_date or (due.date if due and not due.overdue else None),
            risk=risk,
            # El riesgo de la organización al que pertenece este escenario.
            business=business_risks.of(risk),
            evidence=risks.evidence(risk),
            intel=intel,
            timeline=risk.events.select_related("actor").order_by("-occurred_at", "-id"),
            matrix=risks.matrix([risk]),
            closure=closure,
            consolidation_pending=consolidation.is_pending(risk.asset_id),
            queue=risk_queue(self.request.GET["cola"], risk.pk, user=self.request.user)
            if self.request.GET.get("cola")
            else None,
            responsible=responsible,
            responsible_choices=responsibles.choices(risk.asset),
            responsible_choice=responsibles.current_choice(risk),
            verification=verification.view(risk),
            treatment_form=RiskTreatmentForm(
                initial={
                    "treatment": risk.treatment,
                    "owner": risk.owner,
                    "target_date": risk.target_date,
                    "review_at": risk.review_at,
                    "residual_likelihood": risk.residual_likelihood,
                    "residual_impact": risk.residual_impact,
                }
            ),
        )
        return context


class BusinessRoleContextView(Perm, View):
    """Qué es una función de negocio en esta organización: el bloque que se consulta mientras la IA
    lo escribe (GET) y la corrección de una persona (POST; con el texto vacío vuelve a escribirlo
    la IA)."""

    permission_required = "detection.view_risk"

    def _entry(self, role):
        entry = catalogs.get(catalogs.BUSINESS_ROLE, role)
        if not entry:
            raise Http404("No existe esa función de negocio.")
        return entry

    def get(self, request, role):
        self._entry(role)
        assets = business_roles.assets_of(role)
        card = {
            "role": role,
            "dialog_id": business_risks.dialog_id(role),
            "context": business_roles.context_of(role, assets, user=request.user),
        }
        return render(request, "detection/_business_role_context.html", {"card": card})

    def post(self, request, role):
        if not request.user.has_perm("detection.work_findings"):
            raise PermissionDenied
        entry = self._entry(role)
        back = _safe_next(request, reverse("detection:risks"))
        found = business_roles.set_by_person(role, request.POST.get("summary", ""), request.user)
        if found is None:
            messages.success(
                request, f"Explicación de «{entry['label']}» borrada: la IA la volverá a escribir."
            )
        else:
            messages.success(
                request,
                f"Explicación de «{entry['label']}» guardada a tu nombre; la IA ya no la cambia.",
            )
        return HttpResponseRedirect(back)


class BusinessRiskTextView(Perm, View):
    """«Qué puede pasar» de un riesgo de la organización: el bloque que se consulta mientras la IA
    lo escribe (GET) y la corrección de una persona (POST; con el texto vacío vuelve a escribirlo
    la IA)."""

    permission_required = "detection.view_risk"

    def _risk(self, consequence, role):
        known = consequence in RiskConsequence.values or consequence == business_risks.NO_ROLE
        risk = business_risks.get(consequence, role) if known else None
        if risk is None:
            raise Http404("Ese riesgo no existe o ya no tiene escenarios abiertos.")
        return risk

    def get(self, request, consequence, role):
        risk = self._risk(consequence, role)
        what = business_risk_texts.context_of(risk, user=request.user)
        return render(request, "detection/_business_risk_what.html", {"what": what})

    def post(self, request, consequence, role):
        if not request.user.has_perm("detection.work_findings"):
            raise PermissionDenied
        risk = self._risk(consequence, role)
        found = business_risk_texts.set_by_person(
            risk, request.POST.get("summary", ""), request.user
        )
        if found is None:
            messages.success(
                request, f"Texto de «{risk.title}» borrado: la IA lo volverá a escribir."
            )
        else:
            messages.success(
                request, f"Texto de «{risk.title}» guardado a tu nombre; la IA ya no lo cambia."
            )
        return HttpResponseRedirect(_safe_next(request, risk.url))


class BusinessRiskView(Perm, TemplateView):
    """Un riesgo de la organización: una consecuencia sobre una función de negocio, con sus
    escenarios (uno por activo). Aquí se decide el tratamiento de todos a la vez; cada decisión
    queda en su escenario (``RiskBulkView``)."""

    permission_required = "detection.view_risk"
    template_name = "detection/business_risk.html"

    def get(self, request, *args, **kwargs):
        consequence, role = kwargs["consequence"], kwargs["role"]
        if consequence not in RiskConsequence.values and consequence != business_risks.NO_ROLE:
            raise Http404("No existe esa consecuencia.")
        self.rules = policy.current()
        self.risk = business_risks.get(consequence, role, self.rules)
        if self.risk is None:
            # Una función que el catálogo no conoce no es un riesgo que se resolvió: no existe.
            if role != business_risks.NO_ROLE and not catalogs.get(catalogs.BUSINESS_ROLE, role):
                raise Http404("No existe esa función de negocio.")
            gone = business_risks.BusinessRisk(
                "" if consequence == business_risks.NO_ROLE else consequence,
                "" if role == business_risks.NO_ROLE else role,
            )
            messages.info(
                request,
                f"«{gone.title}» ya no tiene escenarios abiertos: se resolvieron o sus activos "
                "cambiaron de función.",
            )
            return HttpResponseRedirect(reverse("detection:risks"))
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            risk=self.risk,
            risks=self.risk.scenarios,
            what=business_risk_texts.context_of(self.risk, user=self.request.user),
            brief=business_risks.describe(self.risk),
            role_card=business_risks.role_card(self.risk.role, self.request.user),
            policy=self.rules,
            bulk_treatments=list(Risk._meta.get_field("treatment").choices),
            bulk_assign=BULK_ASSIGN,
            responsible_choices=responsibles.choices(),
        )
        return context


class RiskReportView(Perm, View):
    """Reporte completo del riesgo: HTML imprimible (PDF desde el navegador) o Markdown."""

    permission_required = "detection.view_risk"

    def get(self, request, pk):
        from django.http import HttpResponse
        from django.template.loader import render_to_string

        risk = get_object_or_404(
            responsibles.with_people(Risk.objects.select_related("decided_by")), pk=pk
        )
        evidence = risks.evidence(risk)
        context = {
            "risk": risk,
            "responsible": responsibles.of(risk),
            "asset": risk.asset,
            "evidence": evidence,
            "evidence_groups": group_evidence(evidence),
            "described": [row for row in evidence if row["vuln"].summary][:5],
            "intel": risks.intelligence(risk.vulnerabilities.select_related("cve")),
            "timeline": risk.events.select_related("actor").order_by("occurred_at", "id"),
            "closure": risks.closure(risk),
            "generated_at": timezone.now(),
            "generated_by": request.user,
        }
        slug = slugify(f"riesgo-{risk.asset.name}-{risk.title}")[:80]
        if request.GET.get("format") == "md":
            body = render_to_string("detection/risk_report.md", context)
            response = HttpResponse(body, content_type="text/markdown; charset=utf-8")
            response["Content-Disposition"] = f'attachment; filename="{slug}.md"'
            return response
        return render(request, "detection/risk_report.html", context)


def group_evidence(rows):
    """Evidencia del reporte agrupada por software afectado: una fila por componente con sus
    vulnerabilidades, en vez de una tabla con decenas de filas casi iguales."""
    groups = {}
    for row in rows:
        vuln = row["vuln"]
        label = vuln.component.label if vuln.component else "Sin software identificado"
        group = groups.setdefault(
            label,
            {"component": label, "rows": [], "kev": 0, "max_score": None, "sources": set()},
        )
        group["rows"].append(row)
        group["kev"] += 1 if vuln.in_kev else 0
        group["sources"].update(row["sources"])
        score = vuln.contextual_score
        if score is not None and (group["max_score"] is None or score > group["max_score"]):
            group["max_score"] = score
    out = sorted(groups.values(), key=lambda g: g["max_score"] or 0, reverse=True)
    for group in out:
        group["sources"] = sorted(group["sources"])
        group["count"] = len(group["rows"])
    return out


class RiskTreatmentView(Perm, View):
    permission_required = "detection.work_findings"

    def post(self, request, pk):
        form = RiskTreatmentForm(request.POST)
        back = _safe_next(request, reverse("detection:risk", args=[pk]))
        risk = get_object_or_404(Risk, pk=pk)
        if risk.status == "CLOSED":
            messages.error(
                request,
                "El riesgo está cerrado: no admite tratamiento. Si vuelve a sostenerse, se "
                "reabre solo y entonces podrás decidirlo.",
            )
            return HttpResponseRedirect(back)
        if not form.is_valid():
            messages.error(request, "Revisa el tratamiento: faltan datos o no son válidos.")
            return HttpResponseRedirect(back)
        try:
            risk = risks.set_treatment(pk, user=request.user, **form.cleaned_data)
            messages.success(
                request, f"Tratamiento registrado: {risk.get_treatment_display().lower()}."
            )
        except ValueError as error:
            messages.error(request, str(error))
            return HttpResponseRedirect(back)
        # En una cola de trabajo, tras decidir se pasa al siguiente riesgo (o a la lista al acabar).
        queue = (
            risk_queue(request.POST.get("cola"), pk, user=request.user)
            if request.POST.get("cola")
            else None
        )
        if queue:
            if queue["next_url"]:
                return HttpResponseRedirect(queue["next_url"])
            messages.success(request, f"Cola terminada: no quedan {queue['label']}.")
            return HttpResponseRedirect(queue["list_url"])
        return HttpResponseRedirect(back)


class RiskBulkView(Perm, View):
    """La misma decisión de tratamiento para todos los riesgos marcados.

    Sin fecha, cada riesgo recibe el plazo de la política de la organización (su nivel o CISA);
    si ese plazo ya venció no se inventa una fecha: el riesgo se deja como está y se dice por qué.
    """

    permission_required = "detection.work_findings"

    def post(self, request):
        back = _safe_next(request, reverse("detection:risks"))
        ids = request.POST.getlist("ids")
        form = RiskBulkForm(request.POST)
        if not ids:
            messages.error(request, "Marca al menos un escenario.")
            return HttpResponseRedirect(back)
        if not form.is_valid():
            messages.error(request, "Elige el tratamiento y revisa las fechas.")
            return HttpResponseRedirect(back)
        data = form.cleaned_data
        if data["treatment"] == BULK_ASSIGN:
            return self._assign(request, ids, data, back)
        rules = policy.current()
        needs_date = data["treatment"] in ("MITIGATE", "TRANSFER")
        done, failed = 0, {}
        for risk in Risk.objects.filter(pk__in=ids):
            try:
                if risk.status == "CLOSED":
                    raise ValueError("está cerrado y no admite tratamiento")
                target = data["target_date"]
                if not target and data["treatment"] != "ACCEPT":
                    # Evitar no exige fecha: si el plazo ya venció se registra sin ella.
                    target = policy.suggested_target(risk, rules)
                    if not target and needs_date:
                        raise ValueError(
                            "su plazo según la política ya venció: fija una fecha compromiso"
                        )
                risks.set_treatment(
                    risk.pk,
                    user=request.user,
                    treatment=data["treatment"],
                    # Sin elegir responsable, cada riesgo conserva el suyo.
                    responsible=data["responsible"],
                    owner=data["owner"],
                    keep_responsible=not (data["responsible"] or data["owner"]),
                    note=data["note"],
                    target_date=target,
                    review_at=data["review_at"],
                )
                done += 1
            except ValueError as error:
                failed.setdefault(str(error).rstrip("."), []).append(risk)
        label = dict(Risk._meta.get_field("treatment").choices)[data["treatment"]].lower()
        if done:
            extra = ""
            if data["responsible"] or data["owner"]:
                extra = f" · responsable: {self._responsible_label(data)}"
            if data["treatment"] != "ACCEPT":
                extra += (
                    f" · compromiso {data['target_date']:%Y-%m-%d}"
                    if data["target_date"]
                    else " · compromiso según el plazo de la política"
                )
            messages.success(
                request,
                f"{done} escenario{'s' if done != 1 else ''} → {label}{extra}, decidido por ti.",
            )
        for reason, group in failed.items():
            messages.error(
                request,
                f"{len(group)} no se {'cambiaron' if len(group) != 1 else 'cambió'}: {reason}.",
            )
        return HttpResponseRedirect(back)

    @staticmethod
    def _responsible_label(data):
        choice = data["responsible"] or (responsibles.OTHER if data["owner"] else "")
        labels = dict(responsibles.choices())
        return data["owner"] if choice == responsibles.OTHER else labels.get(choice, choice)

    def _assign(self, request, ids, data, back):
        """«Asignar responsable» en lote: no decide el tratamiento de ninguno."""
        choice = data["responsible"] or (responsibles.OTHER if data["owner"] else "")
        if not choice:
            messages.error(request, "Elige a quién asignar los escenarios marcados.")
            return HttpResponseRedirect(back)
        try:
            changed = responsibles.assign(ids, user=request.user, choice=choice, text=data["owner"])
        except ValidationError as error:
            _messages_from(request, error)
            return HttpResponseRedirect(back)
        label = self._responsible_label(data)
        if changed:
            messages.success(
                request,
                f"{changed} escenario{'s' if changed != 1 else ''} → responsable: {label}.",
            )
        else:
            messages.info(request, f"Los escenarios marcados ya tenían ese responsable ({label}).")
        return HttpResponseRedirect(back)


class RiskAssignView(Perm, View):
    """Cambia el responsable de un riesgo sin decidir su tratamiento."""

    permission_required = "detection.work_findings"

    def post(self, request, pk):
        back = _safe_next(request, reverse("detection:risk", args=[pk]) + "#tratamiento")
        get_object_or_404(Risk, pk=pk)
        form = RiskAssignForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Elige un responsable.")
            return HttpResponseRedirect(back)
        try:
            changed = responsibles.assign(
                [pk],
                user=request.user,
                choice=form.cleaned_data["responsible"],
                text=form.cleaned_data["owner"],
            )
        except ValidationError as error:
            _messages_from(request, error)
            return HttpResponseRedirect(back)
        who = responsibles.of(responsibles.with_people(Risk.objects).get(pk=pk))
        if not changed:
            messages.info(request, "El riesgo ya tenía ese responsable.")
        elif who.inherited or not who:
            messages.success(
                request,
                f"Sin responsable propio: lo hereda del activo ({who.label})."
                if who
                else "Sin responsable: ni el riesgo ni el activo tienen uno.",
            )
        else:
            messages.success(
                request,
                f"Responsable: {who.label}."
                + (" Lo verá en «a mi nombre» y recibirá el aviso." if who.has_account else ""),
            )
        return HttpResponseRedirect(back)


class RiskVerifyView(Perm, View):
    """«Ya lo corregí: comprobar»: vuelve a escanear el activo con las fuentes que vieron el
    riesgo y cierra lo que deje de observarse (``verification``)."""

    permission_required = "detection.request_evaluation"

    def post(self, request, pk):
        back = _safe_next(request, reverse("detection:risk", args=[pk]) + "#comprobacion")
        get_object_or_404(Risk, pk=pk)
        try:
            check = verification.request(pk, user=request.user)
        except ValidationError as error:
            _messages_from(request, error)
            return HttpResponseRedirect(back)
        waiting = check.actions.filter(status="PROPOSED").exists()
        messages.success(
            request,
            "Comprobación pedida: el resultado aparecerá aquí mismo."
            + (" Antes debe aprobarse en la cola de aprobación." if waiting else ""),
        )
        return HttpResponseRedirect(back)


class RiskVerificationView(Perm, View):
    """Fragmento con el avance de la comprobación; se consulta solo mientras está en curso."""

    permission_required = "detection.view_risk"

    def get(self, request, pk):
        risk = get_object_or_404(Risk.objects.select_related("asset"), pk=pk)
        return render(
            request,
            "detection/_risk_verification.html",
            {"risk": risk, "verification": verification.view(risk)},
        )


class TreatmentPolicyView(Perm, View):
    """Administración → Plazos: cuántos días tiene la organización para tratar cada nivel."""

    permission_required = "detection.view_treatmentpolicy"
    template_name = "detection/policy.html"

    def has_permission(self):
        # La consulta quien trabaja los riesgos y quien audita (la pestaña de Administración la
        # ve el Lector por su permiso de bitácora).
        user = self.request.user
        return user.has_perm(self.permission_required) or user.has_perm(
            "accounts.view_auditlogentry"
        )

    def _context(self, form=None):
        rules = policy.current()
        return {
            "policy": rules,
            "overview": policy.overview(rules),
            "form": form
            or TreatmentPolicyForm(
                initial={name: getattr(rules, name) for name in policy.EDITABLE_FIELDS}
            ),
            "can_manage": self.request.user.has_perm("detection.change_treatmentpolicy"),
        }

    def get(self, request):
        return render(request, self.template_name, self._context())

    def post(self, request):
        if not request.user.has_perm("detection.change_treatmentpolicy"):
            raise PermissionDenied
        form = TreatmentPolicyForm(request.POST)
        if form.is_valid():
            try:
                policy.update(user=request.user, fields=form.cleaned_data)
            except ValidationError as error:
                form.add_error(None, error)
            else:
                messages.success(request, "Plazos de tratamiento guardados.")
                return redirect("detection:policy")
        return render(request, self.template_name, self._context(form))


class RiskNoteView(Perm, View):
    permission_required = "detection.work_findings"

    def post(self, request, pk):
        form = NoteForm(request.POST)
        if form.is_valid():
            risks.add_note(pk, user=request.user, text=form.cleaned_data["text"])
            messages.success(request, "Nota agregada a la línea de tiempo.")
        else:
            messages.error(request, "La nota está vacía.")
        return redirect("detection:risk", pk=pk)


class ObservationsView(Perm, PaginationMixin, ListView):
    """Capa cruda: lo que cada herramienta, la reconciliación o una persona reportó."""

    permission_required = "detection.view_finding"
    template_name = "detection/observations.html"
    context_object_name = "findings"
    paginate_by = 25

    def get_queryset(self):
        qs, self.filter_form = filter_findings(self.request.GET)
        return order_findings(qs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from .models import SoftwareComponent

        cleaned = self.filter_form.cleaned_data if self.filter_form.is_valid() else {}
        # Desde la página de una corrección se llega con «comp»: la lista dice de qué software es.
        component = (
            SoftwareComponent.objects.select_related("asset").filter(pk=cleaned["comp"]).first()
            if cleaned.get("comp")
            else None
        )
        context.update(
            filter_form=self.filter_form,
            summary=findings.summary(),
            asset_id=cleaned.get("asset"),
            component=component,
            filters_active=filters_active(self.request.GET),
        )
        return context


class ObservationCreateView(Perm, TemplateView):
    permission_required = "detection.work_findings"
    template_name = "detection/observation_form.html"

    def _asset(self, request, required=True):
        from apps.assets.models import Asset

        asset_id = request.GET.get("asset") or request.POST.get("asset")
        if not asset_id and not required:
            return None
        return get_object_or_404(Asset, pk=asset_id)

    def _choices(self):
        from apps.assets.models import Asset

        return Asset.objects.filter(status__in=("ACTIVE", "STALE")).order_by("name")[:500]

    def get(self, request):
        # Desde Observaciones sin activo: se elige aquí mismo.
        asset = self._asset(request, required=False)
        return render(
            request,
            self.template_name,
            {
                "asset": asset,
                "form": ObservationForm(),
                "assets": None if asset else self._choices(),
            },
        )

    def post(self, request):
        asset = self._asset(request, required=False)
        form = ObservationForm(request.POST)
        if asset is None:
            messages.error(request, "Elige el activo donde lo viste.")
            return render(
                request,
                self.template_name,
                {"asset": None, "form": form, "assets": self._choices()},
            )
        if form.is_valid():
            try:
                finding = findings.add_manual_observation(
                    user=request.user, asset_id=asset.pk, **form.cleaned_data
                )
            except ValidationError as error:
                _messages_from(request, error)
            else:
                messages.success(
                    request,
                    "Evidencia registrada; la consolidación con IA la tomará en cuenta en breve.",
                )
                return redirect("detection:finding", pk=finding.pk)
        return render(request, self.template_name, {"asset": asset, "form": form, "assets": None})


class FindingDetailView(Perm, TemplateView):
    permission_required = "detection.view_finding"
    template_name = "detection/finding_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        finding = get_object_or_404(
            Finding.objects.select_related("asset", "cve", "component", "status_changed_by"),
            pk=kwargs["pk"],
        )
        evidence = list(finding.evidence.select_related("component"))
        context.update(
            finding=finding,
            evidence=evidence,
            external_hosts=external_evidence_hosts(finding, evidence),
            timeline=finding.events.select_related("actor").order_by("-occurred_at", "-id"),
            consolidated=finding.consolidated,
            consolidation_pending=consolidation.is_pending(finding.asset_id),
        )
        return context


def external_evidence_hosts(finding, evidence):
    """Hosts de «matched-at» que no son identificadores del activo: la plantilla coincidió en un
    tercero (RDAP, un inquilino en la nube), no en el activo. Se marcan en la evidencia."""
    from urllib.parse import urlsplit

    own = {i.value.lower() for i in finding.asset.identifiers.all()}
    own.add(finding.asset.name.lower())
    hosts = set()
    for ev in evidence:
        matched = (ev.data or {}).get("matched-at")
        if not matched:
            continue
        text = str(matched)
        host = urlsplit(text if "://" in text else f"//{text}").hostname or text
        host = host.lower().strip("[]")
        if host and host not in own and not any(host == o or host.startswith(o + ":") for o in own):
            hosts.add(host)
    return hosts


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
        show_filtered = kind == "event" and self.request.GET.get("filtered") == "1"
        context.update(
            # «Todo» agrupa: una fila por acción con sus pasos plegados. Las demás pestañas son
            # el listado plano de un solo tipo.
            threads=None if kinds else activity.threads(),
            entries=activity.recent(kinds=kinds, include_filtered=show_filtered) if kinds else [],
            kind=kind,
            show_filtered=show_filtered,
            filtered_today=DetectionEvent.objects.filter(
                status="FILTERED", created_at__date=timezone.localdate()
            ).count(),
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
        related = Finding.objects.none()
        if event.asset_id and event.cve_id:
            related = Finding.objects.filter(asset_id=event.asset_id, cve_id=event.cve_id)
        elif event.cve_id:
            related = Finding.objects.filter(cve_id=event.cve_id).select_related("asset")[:20]
        context.update(
            event=event,
            decisions=event.decisions.select_related("inference", "asset"),
            actions=event.actions.select_related("asset"),
            related_findings=related,
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
        back = _safe_next(request, reverse("assets:detail", args=[pk]))
        try:
            event, batch = events.request_evaluation(pk, user=request.user)
        except ValidationError as error:
            _messages_from(request, error)
            return HttpResponseRedirect(back)
        from .tasks import process_event_batch

        process_event_batch.delay(str(batch.pk))
        messages.success(
            request,
            "Evaluación en curso: el avance y el resultado se muestran aquí mismo, en el activo.",
        )
        return HttpResponseRedirect(back)


class AssetPipelineView(Perm, View):
    """Fragmento «Proceso del activo»: escaneo → criticidad → evaluación, con sus botones."""

    permission_required = "detection.view_detectionevent"

    def get(self, request, pk):
        from . import progress

        return render(
            request, "detection/_asset_pipeline.html", {"pipeline": progress.asset_pipeline(pk)}
        )


class EvaluationStatusView(Perm, View):
    """Fragmento «última evaluación» del activo; se consulta solo mientras hay algo en curso."""

    permission_required = "detection.view_detectionevent"

    def get(self, request, pk):
        from . import progress

        return render(
            request,
            "detection/_evaluation_status.html",
            {"asset_id": pk, "progress": progress.evaluation_progress(pk)},
        )


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
        # En la cola cada tarjeta lleva su propio campo («note_<id>»); en el detalle es «note».
        raw = request.POST.get(f"note_{pk}") or request.POST.get("note") or ""
        form = RejectForm({"note": raw.strip()})
        back = _safe_next(request, reverse("detection:queue"))
        if not form.is_valid():
            messages.error(request, "Indica el motivo del rechazo: queda en la bitácora.")
            return HttpResponseRedirect(back)
        try:
            actions.reject(pk, user=request.user, note=form.cleaned_data["note"])
            messages.success(request, "Acción rechazada.")
        except ValidationError as error:
            _messages_from(request, error)
        return HttpResponseRedirect(back)


class BulkQueueView(Perm, View):
    permission_required = "detection.approve_actions"

    def post(self, request):
        ids = request.POST.getlist("ids")
        decision = request.POST.get("decision", "approve")
        if not ids:
            messages.error(request, "Selecciona al menos una acción.")
            return redirect("detection:queue")
        if decision == "reject":
            form = RejectForm({"note": (request.POST.get("note") or "").strip()})
            if not form.is_valid():
                messages.error(request, "Indica el motivo del rechazo: se aplica a todas.")
                return redirect("detection:queue")
            done, failed = [], []
            for action_id in ids:
                try:
                    done.append(
                        actions.reject(
                            action_id,
                            user=request.user,
                            note=f"Rechazada en lote: {form.cleaned_data['note']}"[:500],
                        )
                    )
                except (ValidationError, PlannedAction.DoesNotExist) as exc:
                    failed.append((action_id, str(exc)))
            label = "rechazada" if len(done) == 1 else "rechazadas"
        else:
            done, failed = actions.approve_many(ids, user=request.user)
            label = "aprobada en lote" if len(done) == 1 else "aprobadas en lote"
        if done:
            messages.success(
                request, f"{len(done)} acci{'ón' if len(done) == 1 else 'ones'} {label}."
            )
        if failed:
            n = len(failed)
            messages.warning(
                request,
                f"{n} acci{'ón' if n == 1 else 'ones'} ya no esperaba{'' if n == 1 else 'n'} aprobación.",
            )
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
        if paused and not reason.strip():
            messages.error(request, "Indica el motivo de la pausa: queda en la bitácora.")
            return redirect("detection:automation")
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
                return redirect("organization")
        return render(request, self.template_name, self._context(form))


class DraftView(Perm, View):
    permission_required = "detection.manage_profile"

    def post(self, request):
        if request.POST.get("discard"):
            profile.discard_draft(user=request.user)
            messages.success(request, "Borrador descartado.")
            return redirect("organization")
        try:
            profile.request_draft(user=request.user)
            messages.success(
                request, "Generando el borrador con el LLM local; la página se actualizará sola."
            )
        except ValidationError as error:
            _messages_from(request, error)
        return redirect("organization")


# --------------------------------------------------------------------------
# Fuentes CTI
# --------------------------------------------------------------------------


class SourcesView(Perm, View):
    permission_required = "cti.view_ctisource"
    template_name = "detection/sources.html"

    def _context(self, forms=None):
        cti.mark_interrupted_runs()  # F10: nada se queda «en curso» para siempre
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

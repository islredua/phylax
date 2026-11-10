"""Vistas del módulo de detección. Toda modificación pasa por los servicios (re-verifican permisos)."""

from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Count, Max, Q
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.text import slugify
from django.views import View
from django.views.generic import ListView, TemplateView

from apps.assets import catalogs
from apps.core.views import PaginationMixin
from apps.cti import services as cti
from apps.cti.models import CtiSource, CtiSyncRun, SourceKind
from apps.scanners.models import ToolExecution
from apps.scoring import services as scoring

from . import (
    actions,
    activity,
    automation,
    consolidation,
    descriptions,
    events,
    findings,
    planner,
    profile,
    risks,
)
from .forms import (
    HUMAN_STATUS_LABELS,
    AutomationForm,
    FindingFilterForm,
    FindingTransitionForm,
    NoteForm,
    ObservationForm,
    PauseForm,
    ProfileForm,
    RejectForm,
    ReviewForm,
    RiskFilterForm,
    RiskTreatmentForm,
    SourceForm,
    VulnerabilityBulkForm,
    VulnerabilityFilterForm,
    VulnerabilityStatusForm,
)
from .models import (
    OPEN_STATUSES,
    VULN_OPEN_STATUSES,
    Action,
    DetectionEvent,
    Finding,
    FindingSeverity,
    PlannedAction,
    Risk,
    RiskEvent,
    RiskEventKind,
    Vulnerability,
    VulnerabilityStatus,
)

# Parámetros que no son filtros: con cualquier otro presente, la lista está filtrada y un
# resultado vacío significa «sin coincidencias», no «falta consolidar».
NON_FILTER_PARAMS = {"asset", "page", "per_page", "tab"}


def filters_active(params):
    return any(value for key, value in params.items() if key not in NON_FILTER_PARAMS)


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


def order_findings(qs):
    """Prioridad del motor de scoring si existe; si no, provisional: KEV, severidad, EPSS."""
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


# Las pestañas del activo muestran lo más urgente; el resto se ve en Detección con filtros (A1).
ASSET_TAB_LIMIT = 20


def asset_tab_context(asset, tab):
    """Datos de las pestañas Riesgos / Vulnerabilidades / Observaciones de la página del activo.

    Las tres listas viven dentro del activo para no sacar a la persona de su contexto; las
    pantallas de Detección son las mismas listas para toda la organización, con filtros.
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
        listed = list(risks.triage_order(filter_risks(params)[0]))
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
        ctx["tab_total"] = len(ordered)
        ctx["findings"] = ordered[:ASSET_TAB_LIMIT]
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
    """Panel = vulnerabilidades consolidadas, ordenadas por puntaje contextual."""

    permission_required = "detection.view_vulnerability"
    template_name = "detection/panel.html"
    context_object_name = "vulnerabilities"
    paginate_by = 25

    def get_queryset(self):
        qs, self.filter_form = filter_vulnerabilities(self.request.GET)
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        asset_id = (
            self.filter_form.cleaned_data.get("asset") if self.filter_form.is_valid() else None
        )
        context.update(
            filter_form=self.filter_form,
            summary=consolidation.summary(asset_id),
            observations_open=findings.open_findings(asset_id).count(),
            unconsolidated=consolidation.consolidable(findings.open_findings(asset_id))
            .filter(consolidated__isnull=True)
            .count(),
            asset_id=asset_id,
            consolidation_pending=consolidation.is_pending(asset_id) if asset_id else False,
            queue_size=actions.approval_queue().count(),
            automation=automation.summary(),
            filters_active=filters_active(self.request.GET),
            describing=descriptions.pending_ids([v.pk for v in context["vulnerabilities"]]),
            bulk_statuses=list(HUMAN_STATUS_LABELS.items()),
        )
        return context


class VulnerabilityBulkView(Perm, View):
    """Triaje en lote: el mismo estado (y nota) para todas las vulnerabilidades marcadas."""

    permission_required = "detection.work_findings"

    def post(self, request):
        back = _safe_next(request, reverse("detection:panel"))
        ids = request.POST.getlist("ids")
        form = VulnerabilityBulkForm(request.POST)
        if not ids:
            messages.error(request, "Marca al menos una vulnerabilidad.")
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
            messages.success(
                request,
                f"{done} vulnerabilidad{'es' if done != 1 else ''} → {label}, fijado por ti.",
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
        context.update(
            vuln=vuln,
            observations=observations,
            description_pending=description_pending,
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

        vuln = get_object_or_404(Vulnerability.objects.select_related("asset"), pk=pk)
        return render(
            request,
            "detection/_vulnerability_description.html",
            {"vuln": vuln, "description_pending": descriptions.is_pending(vuln.pk)},
        )


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
            messages.info(request, "El activo no tiene observaciones que consolidar.")
        return HttpResponseRedirect(back)


def filter_risks(params):
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
    return qs, form


class RiskRegisterView(Perm, PaginationMixin, ListView):
    """Registro de riesgos (ISO/IEC 27005) con la matriz 5×5 de los riesgos listados."""

    permission_required = "detection.view_risk"
    template_name = "detection/risks.html"
    context_object_name = "risks"
    paginate_by = 25

    def get_queryset(self):
        qs, self.filter_form = filter_risks(self.request.GET)
        return risks.triage_order(qs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        asset_id = (
            self.filter_form.cleaned_data.get("asset") if self.filter_form.is_valid() else None
        )
        listed = list(self.object_list)
        context.update(
            filter_form=self.filter_form,
            summary=risks.summary(asset_id),
            matrix=risks.matrix(listed),
            asset_id=asset_id,
            asset=listed[0].asset if asset_id and listed else None,
            consolidation_pending=consolidation.is_pending(asset_id) if asset_id else False,
            today=risks.today(asset_id),
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
            Risk.objects.select_related("asset", "decided_by"), pk=kwargs["pk"]
        )
        context.update(
            risk=risk,
            evidence=risks.evidence(risk),
            intel=risks.intelligence(risk.vulnerabilities.select_related("cve")),
            timeline=risk.events.select_related("actor").order_by("-occurred_at", "-id"),
            matrix=risks.matrix([risk]),
            closure=risks.closure(risk),
            consolidation_pending=consolidation.is_pending(risk.asset_id),
            treatment_form=RiskTreatmentForm(
                initial={
                    "treatment": risk.treatment,
                    "owner": risk.owner,
                    "residual_likelihood": risk.residual_likelihood,
                    "residual_impact": risk.residual_impact,
                }
            ),
        )
        return context


class RiskReportView(Perm, View):
    """Reporte completo del riesgo: HTML imprimible (PDF desde el navegador) o Markdown."""

    permission_required = "detection.view_risk"

    def get(self, request, pk):
        from django.http import HttpResponse
        from django.template.loader import render_to_string

        risk = get_object_or_404(Risk.objects.select_related("asset", "decided_by"), pk=pk)
        evidence = risks.evidence(risk)
        context = {
            "risk": risk,
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
        context.update(
            filter_form=self.filter_form,
            summary=findings.summary(),
            asset_id=self.filter_form.cleaned_data.get("asset")
            if self.filter_form.is_valid()
            else None,
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
            messages.error(request, "Elige el activo donde viste la observación.")
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
                    "Observación registrada; la consolidación con IA la tomará en cuenta en breve.",
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
        show_filtered = kind == "event" and self.request.GET.get("filtered") == "1"
        context.update(
            entries=activity.recent(kinds=kinds, include_filtered=show_filtered),
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

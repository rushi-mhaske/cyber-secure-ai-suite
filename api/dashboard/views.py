from __future__ import annotations

import json
import os
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.generic import TemplateView
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from . import forms
from .models import (
    BehaviorEvent,
    DocumentAnalysis,
    MalwareScan,
    ModuleType,
    PhishingScan,
    RiskLevel,
    SecurityAlert,
)
from .serializers import (
    BehaviorEventSerializer,
    DocumentAnalysisSerializer,
    MalwareScanSerializer,
    PhishingScanSerializer,
    SecurityAlertSerializer,
)
from .services import alerts as alert_service
from .services import behavior as behavior_service
from .services import document as document_service
from .services import malware as malware_service
from .services import phishing as phishing_service


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'dashboard/home.html'

    RANGE_CHOICES = {
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
        '90d': timedelta(days=90),
    }

    def get_range(self):
        key = self.request.GET.get('range', '7d')
        return key if key in self.RANGE_CHOICES else '7d'

    def get_time_bounds(self):
        end = timezone.now()
        range_key = self.get_range()
        delta = self.RANGE_CHOICES[range_key]
        return range_key, end - delta, end

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        range_key, start, end = self.get_time_bounds()
        delta = self.RANGE_CHOICES[range_key]

        alerts_qs = SecurityAlert.objects.filter(created_at__range=(start, end))
        phishing_qs = PhishingScan.objects.filter(created_at__range=(start, end))
        document_qs = DocumentAnalysis.objects.filter(created_at__range=(start, end))
        malware_qs = MalwareScan.objects.filter(created_at__range=(start, end))

        kpi_total = alerts_qs.count()
        kpi_high = alerts_qs.filter(severity__in=[RiskLevel.HIGH, RiskLevel.CRITICAL]).count()
        kpi_phishing = phishing_qs.filter(risk_level__in=[RiskLevel.HIGH, RiskLevel.CRITICAL]).count()
        kpi_malware = malware_qs.filter(verdict__in=[MalwareScan.Verdict.MALICIOUS, MalwareScan.Verdict.QUARANTINED]).count()

        prev_start = start - delta
        prev_alerts = SecurityAlert.objects.filter(created_at__range=(prev_start, start)).count()
        prev_high = SecurityAlert.objects.filter(created_at__range=(prev_start, start), severity__in=[RiskLevel.HIGH, RiskLevel.CRITICAL]).count()
        prev_phishing = PhishingScan.objects.filter(created_at__range=(prev_start, start), risk_level__in=[RiskLevel.HIGH, RiskLevel.CRITICAL]).count()
        prev_malware = MalwareScan.objects.filter(created_at__range=(prev_start, start), verdict__in=[MalwareScan.Verdict.MALICIOUS, MalwareScan.Verdict.QUARANTINED]).count()

        context.update({
            'range_key': range_key,
            'kpi_total_alerts': kpi_total,
            'kpi_high_alerts': kpi_high,
            'kpi_phishing_detected': kpi_phishing,
            'kpi_malware_blocked': kpi_malware,
            'kpi_delta_alerts': kpi_total - prev_alerts,
            'kpi_delta_high': kpi_high - prev_high,
            'kpi_delta_phishing': kpi_phishing - prev_phishing,
            'kpi_delta_malware': kpi_malware - prev_malware,
            'recent_alerts': alerts_qs.order_by('-created_at')[:5],
            'recent_phishing': phishing_qs.order_by('-created_at')[:5],
            'recent_documents': document_qs.order_by('-created_at')[:5],
            'behavior_trends': json.dumps(behavior_service.build_timeline(days=14)),
            'alert_timeline': json.dumps(self._build_alert_timeline(alerts_qs)),
            'module_distribution': json.dumps(self._module_distribution(alerts_qs)),
        })
        return context

    def _build_alert_timeline(self, alerts_qs):
        buckets = {}
        for alert in alerts_qs.order_by('created_at'):
            day_key = alert.created_at.date().isoformat()
            bucket = buckets.setdefault(day_key, {'day': day_key, 'total': 0, 'critical': 0})
            bucket['total'] += 1
            if alert.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                bucket['critical'] += 1
        return list(buckets.values())

    def _module_distribution(self, alerts_qs):
        data = (
            alerts_qs.values('module')
            .annotate(total=Count('module'))
            .order_by('-total')
        )
        return [
            {'module': ModuleType(item['module']).label, 'total': item['total']}
            for item in data
        ]


@login_required
def phishing_view(request):
    form = forms.PhishingScanForm(request.POST or None)
    latest_scan = None

    if request.method == 'POST':
        if form.is_valid():
            cleaned = form.cleaned_data
            analysis = phishing_service.analyse_scan(cleaned)
            scan = PhishingScan.objects.create(
                user=request.user,
                input_type=cleaned['input_type'],
                target_url=cleaned.get('target_url', ''),
                raw_content=cleaned.get('raw_content', ''),
                headers=cleaned.get('headers') or {},
                domain_age_days=analysis.get('domain_age_days'),
                reputation_score=analysis['reputation_score'],
                risk_score=analysis['risk_score'],
                risk_level=analysis['risk_level'],
                detections=analysis['detections'],
                recommendations=analysis['recommendations'],
                metadata=analysis['metadata'],
            )
            latest_scan = scan
            alert_service.alert_from_phishing(scan)
            messages.success(request, 'Phishing scan completed.')
            if request.headers.get('HX-Request'):
                recent_scans = PhishingScan.objects.order_by('-created_at')[:12]
                return render(request, 'dashboard/partials/phishing_result.html', {'scan': scan, 'recent_scans': recent_scans})
            return redirect('dashboard:phishing')
        if request.headers.get('HX-Request'):
            return render(request, 'dashboard/partials/phishing_form.html', {'form': form})

    scans = PhishingScan.objects.order_by('-created_at')[:12]
    context = {
        'form': form,
        'latest_scan': latest_scan or scans.first(),
        'recent_scans': scans,
    }
    if request.headers.get('HX-Request'):
        hx_target = request.headers.get('HX-Target')
        if hx_target == 'main-content':
            return render(request, 'dashboard/phishing.html', context)
        if hx_target == 'phishing-result' and request.GET.get('id'):
            scan = get_object_or_404(PhishingScan, pk=request.GET['id'])
            context.update({'scan': scan})
            return render(request, 'dashboard/partials/phishing_result.html', {'scan': scan, 'recent_scans': scans})
        return render(request, 'dashboard/partials/phishing_history.html', context)
    return render(request, 'dashboard/phishing.html', context)


@login_required
def document_view(request):
    form = forms.DocumentAnalysisForm(request.POST or None, request.FILES or None)
    latest_analysis = None

    if request.method == 'POST':
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            analysis_result = document_service.analyse_document(
                uploaded_file,
                run_ocr=form.cleaned_data.get('run_ocr', True),
                run_semantic=form.cleaned_data.get('run_semantic', True),
            )
            analysis = DocumentAnalysis.objects.create(
                user=request.user,
                uploaded_file=uploaded_file,
                **analysis_result,
            )
            latest_analysis = analysis
            alert_service.alert_from_document(analysis)
            messages.success(request, 'Document forensics completed.')
            if request.headers.get('HX-Request'):
                recent_analyses = DocumentAnalysis.objects.order_by('-created_at')[:12]
                return render(request, 'dashboard/partials/document_result.html', {'analysis': analysis, 'recent_analyses': recent_analyses})
            return redirect('dashboard:documents')
        if request.headers.get('HX-Request'):
            return render(request, 'dashboard/partials/document_form.html', {'form': form})

    analyses = DocumentAnalysis.objects.order_by('-created_at')[:12]
    context = {
        'form': form,
        'latest_analysis': latest_analysis or analyses.first(),
        'recent_analyses': analyses,
    }
    if request.headers.get('HX-Request'):
        hx_target = request.headers.get('HX-Target')
        if hx_target == 'main-content':
            return render(request, 'dashboard/documents.html', context)
        if hx_target == 'document-result' and request.GET.get('id'):
            analysis = get_object_or_404(DocumentAnalysis, pk=request.GET['id'])
            return render(request, 'dashboard/partials/document_result.html', {'analysis': analysis, 'recent_analyses': analyses})
        return render(request, 'dashboard/partials/document_history.html', context)
    return render(request, 'dashboard/documents.html', context)


@login_required
def behavior_view(request):
    form = forms.BehaviorEventForm(request.POST or None)

    if request.method == 'POST':
        if form.is_valid():
            event = form.save()
            behavior_service.detect_and_update(event)
            alert_service.alert_from_behavior(event)
            messages.success(request, 'Event captured and analysed.')
            if request.headers.get('HX-Request'):
                events = BehaviorEvent.objects.order_by('-occurred_at')[:25]
                return render(request, 'dashboard/partials/behavior_table.html', {'events': events})
            return redirect('dashboard:behavior')
        if request.headers.get('HX-Request'):
            return render(request, 'dashboard/partials/behavior_form.html', {'form': form})

    events = BehaviorEvent.objects.order_by('-occurred_at')[:25]
    context = {
        'form': form,
        'events': events,
        'timeline': json.dumps(behavior_service.build_timeline(days=21)),
    }
    if request.headers.get('HX-Request'):
        if request.headers.get('HX-Target') == 'main-content':
            return render(request, 'dashboard/behavior.html', context)
        return render(request, 'dashboard/partials/behavior_table.html', context)
    return render(request, 'dashboard/behavior.html', context)


@login_required
def malware_view(request):
    form = forms.MalwareScanForm(request.POST or None, request.FILES or None)
    latest_scan = None

    if request.method == 'POST':
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            analysis = malware_service.analyse_file(
                uploaded_file,
                enforce_policy=form.cleaned_data.get('enforce_policy', True),
            )
            scan = MalwareScan.objects.create(
                user=request.user,
                uploaded_file=uploaded_file,
                **analysis,
            )
            latest_scan = scan
            alert_service.alert_from_malware(scan)
            messages.success(request, 'Malware scan completed.')
            if request.headers.get('HX-Request'):
                scans = MalwareScan.objects.order_by('-created_at')[:12]
                return render(request, 'dashboard/partials/malware_result.html', {'scan': scan, 'recent_scans': scans})
            return redirect('dashboard:malware')
        if request.headers.get('HX-Request'):
            return render(request, 'dashboard/partials/malware_form.html', {'form': form})

    scans = MalwareScan.objects.order_by('-created_at')[:12]
    context = {
        'form': form,
        'latest_scan': latest_scan or scans.first(),
        'recent_scans': scans,
    }
    if request.headers.get('HX-Request'):
        hx_target = request.headers.get('HX-Target')
        if hx_target == 'main-content':
            return render(request, 'dashboard/malware.html', context)
        if hx_target == 'malware-result' and request.GET.get('id'):
            scan = get_object_or_404(MalwareScan, pk=request.GET['id'])
            return render(request, 'dashboard/partials/malware_result.html', {'scan': scan, 'recent_scans': scans})
        return render(request, 'dashboard/partials/malware_history.html', context)
    return render(request, 'dashboard/malware.html', context)


@login_required
def alerts_view(request):
    form = forms.AlertStatusForm(request.POST or None)

    if request.method == 'POST':
        if form.is_valid():
            alert = get_object_or_404(SecurityAlert, pk=form.cleaned_data['alert_id'])
            alert_service.uplift_alert(alert, form.cleaned_data['action'], request.user)
            messages.success(request, f'Alert {alert.pk} updated.')
            if request.headers.get('HX-Request'):
                alerts = SecurityAlert.objects.order_by('-created_at')[:50]
                form = forms.AlertStatusForm()
                return render(request, 'dashboard/partials/alerts_form.html', {'form': form, 'alerts': alerts})
            return redirect('dashboard:alerts')
        if request.headers.get('HX-Request'):
            return render(request, 'dashboard/partials/alerts_form.html', {'form': form})

    alerts = SecurityAlert.objects.order_by('-created_at')[:50]
    context = {
        'form': forms.AlertStatusForm(),
        'alerts': alerts,
        'severity_breakdown': json.dumps(_severity_breakdown(alerts)),
    }
    if request.headers.get('HX-Request'):
        hx_target = request.headers.get('HX-Target')
        if hx_target == 'main-content':
            return render(request, 'dashboard/alerts.html', context)
        if hx_target == 'alerts-form' and request.GET.get('id'):
            alert = get_object_or_404(SecurityAlert, pk=request.GET['id'])
            form = forms.AlertStatusForm(initial={'alert_id': alert.pk})
            return render(request, 'dashboard/partials/alerts_form.html', {'form': form})
        return render(request, 'dashboard/partials/alerts_table.html', context)
    return render(request, 'dashboard/alerts.html', context)


def _severity_breakdown(alerts_qs):
    counts = alerts_qs.values('severity').annotate(total=Count('severity'))
    return [
        {'severity': RiskLevel(item['severity']).label, 'total': item['total']}
        for item in counts
    ]


def manifest_view(request):
    manifest_path = os.path.join(settings.BASE_DIR, 'static', 'manifest.json')
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        manifest_data = {
            "name": "Cyber AI Dashboard",
            "short_name": "CyberAI",
            "start_url": "/",
            "display": "standalone",
            "theme_color": "#0284c7",
            "background_color": "#0f172a",
            "icons": [],
        }
    return HttpResponse(json.dumps(manifest_data, indent=2), content_type='application/manifest+json')


def offline_view(request):
    return render(request, 'dashboard/offline.html')


class PhishingScanViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = PhishingScan.objects.order_by('-created_at')
    serializer_class = PhishingScanSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['risk_level', 'input_type']
    search_fields = ['target_url', 'raw_content']
    ordering_fields = ['created_at', 'risk_score']
    ordering = ['-created_at']


class DocumentAnalysisViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DocumentAnalysis.objects.order_by('-created_at')
    serializer_class = DocumentAnalysisSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['verdict', 'risk_level']
    search_fields = ['file_name', 'sha256']
    ordering_fields = ['created_at', 'ela_score', 'semantic_score']
    ordering = ['-created_at']


class BehaviorEventViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = BehaviorEvent.objects.order_by('-occurred_at')
    serializer_class = BehaviorEventSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['event_type', 'is_anomalous']
    search_fields = ['actor_identifier']
    ordering_fields = ['occurred_at', 'risk_score']
    ordering = ['-occurred_at']


class MalwareScanViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MalwareScan.objects.order_by('-created_at')
    serializer_class = MalwareScanSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['verdict', 'risk_level']
    search_fields = ['file_name', 'sha256']
    ordering_fields = ['created_at', 'risk_score']
    ordering = ['-created_at']


class SecurityAlertViewSet(viewsets.ModelViewSet):
    queryset = SecurityAlert.objects.order_by('-created_at')
    serializer_class = SecurityAlertSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['module', 'severity', 'status']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'severity']
    ordering = ['-created_at']

    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        alert = self.get_object()
        alert.mark_acknowledged(request.user if request.user.is_authenticated else None)
        return Response({'status': 'acknowledged'})

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        alert = self.get_object()
        alert.mark_resolved(request.user if request.user.is_authenticated else None)
        return Response({'status': 'resolved'})


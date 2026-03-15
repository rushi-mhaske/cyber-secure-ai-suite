from django.contrib import admin

from .models import (
    BehaviorEvent,
    DocumentAnalysis,
    MalwareScan,
    PhishingScan,
    SecurityAlert,
)


@admin.register(PhishingScan)
class PhishingScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'target_url', 'input_type', 'risk_level', 'risk_score', 'created_at']
    list_filter = ['risk_level', 'input_type', 'created_at']
    search_fields = ['target_url', 'raw_content']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(DocumentAnalysis)
class DocumentAnalysisAdmin(admin.ModelAdmin):
    list_display = ['id', 'file_name', 'verdict', 'risk_level', 'ela_score', 'semantic_score', 'created_at']
    list_filter = ['verdict', 'risk_level', 'created_at']
    search_fields = ['file_name', 'sha256']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(BehaviorEvent)
class BehaviorEventAdmin(admin.ModelAdmin):
    list_display = ['id', 'actor_identifier', 'event_type', 'is_anomalous', 'risk_score', 'occurred_at']
    list_filter = ['event_type', 'is_anomalous', 'created_at']
    search_fields = ['actor_identifier']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'occurred_at'


@admin.register(MalwareScan)
class MalwareScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'file_name', 'verdict', 'risk_level', 'risk_score', 'created_at']
    list_filter = ['verdict', 'risk_level', 'created_at']
    search_fields = ['file_name', 'sha256']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = ['id', 'module', 'severity', 'status', 'created_at', 'resolved_at']
    list_filter = ['module', 'severity', 'status', 'created_at']
    search_fields = ['title', 'description']
    readonly_fields = ['created_at', 'updated_at', 'acknowledged_at', 'resolved_at']


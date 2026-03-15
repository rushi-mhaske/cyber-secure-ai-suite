from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import (
    BehaviorEvent,
    DocumentAnalysis,
    MalwareScan,
    PhishingScan,
    SecurityAlert,
)

User = get_user_model()


class UserSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name']


class PhishingScanSerializer(serializers.ModelSerializer):
    user = UserSummarySerializer(read_only=True)
    risk_level_display = serializers.CharField(source='get_risk_level_display', read_only=True)
    input_type_display = serializers.CharField(source='get_input_type_display', read_only=True)

    class Meta:
        model = PhishingScan
        fields = [
            'id',
            'user',
            'input_type',
            'input_type_display',
            'target_url',
            'raw_content',
            'headers',
            'domain_age_days',
            'reputation_score',
            'risk_score',
            'risk_level',
            'risk_level_display',
            'detections',
            'recommendations',
            'metadata',
            'notes',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'user',
            'detections',
            'recommendations',
            'metadata',
            'created_at',
            'updated_at',
        ]


class DocumentAnalysisSerializer(serializers.ModelSerializer):
    user = UserSummarySerializer(read_only=True)
    verdict_display = serializers.CharField(source='get_verdict_display', read_only=True)
    risk_level_display = serializers.CharField(source='get_risk_level_display', read_only=True)

    class Meta:
        model = DocumentAnalysis
        fields = [
            'id',
            'user',
            'uploaded_file',
            'file_name',
            'file_type',
            'file_size',
            'sha256',
            'ela_score',
            'text_confidence',
            'semantic_score',
            'verdict',
            'verdict_display',
            'risk_level',
            'risk_level_display',
            'findings',
            'highlighted_regions',
            'ocr_text',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'user',
            'file_name',
            'file_type',
            'file_size',
            'sha256',
            'ela_score',
            'text_confidence',
            'semantic_score',
            'verdict',
            'risk_level',
            'findings',
            'highlighted_regions',
            'ocr_text',
            'metadata',
            'created_at',
            'updated_at',
        ]


class BehaviorEventSerializer(serializers.ModelSerializer):
    risk_level = serializers.SerializerMethodField()

    class Meta:
        model = BehaviorEvent
        fields = [
            'id',
            'actor_identifier',
            'event_type',
            'occurred_at',
            'location',
            'device',
            'metadata',
            'baseline_score',
            'risk_score',
            'risk_level',
            'is_anomalous',
            'anomaly_reasons',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['created_at', 'updated_at', 'anomaly_reasons']

    def get_risk_level(self, obj: BehaviorEvent) -> str:
        if obj.risk_score >= 80:
            return 'critical'
        if obj.risk_score >= 60:
            return 'high'
        if obj.risk_score >= 40:
            return 'medium'
        return 'low'


class MalwareScanSerializer(serializers.ModelSerializer):
    user = UserSummarySerializer(read_only=True)
    verdict_display = serializers.CharField(source='get_verdict_display', read_only=True)
    risk_level_display = serializers.CharField(source='get_risk_level_display', read_only=True)

    class Meta:
        model = MalwareScan
        fields = [
            'id',
            'user',
            'uploaded_file',
            'file_name',
            'file_type',
            'file_size',
            'sha256',
            'entropy',
            'signature_hits',
            'heuristic_findings',
            'external_references',
            'risk_score',
            'risk_level',
            'risk_level_display',
            'verdict',
            'verdict_display',
            'quarantine_path',
            'policy_applied',
            'metadata',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'user',
            'file_name',
            'file_type',
            'file_size',
            'sha256',
            'entropy',
            'signature_hits',
            'heuristic_findings',
            'external_references',
            'risk_score',
            'risk_level',
            'verdict',
            'quarantine_path',
            'policy_applied',
            'metadata',
            'created_at',
            'updated_at',
        ]


class SecurityAlertSerializer(serializers.ModelSerializer):
    module_display = serializers.CharField(source='get_module_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    acknowledged_by = UserSummarySerializer(read_only=True)

    class Meta:
        model = SecurityAlert
        fields = [
            'id',
            'module',
            'module_display',
            'title',
            'description',
            'severity',
            'severity_display',
            'status',
            'status_display',
            'source_object_id',
            'source_model',
            'insight',
            'remediation',
            'acknowledged_by',
            'acknowledged_at',
            'resolved_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'acknowledged_by',
            'acknowledged_at',
            'resolved_at',
            'created_at',
            'updated_at',
        ]


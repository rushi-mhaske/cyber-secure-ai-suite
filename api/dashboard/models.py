from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone

User = get_user_model()


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ['-created_at']


class RiskLevel(models.TextChoices):
    LOW = 'low', 'Low'
    MEDIUM = 'medium', 'Medium'
    HIGH = 'high', 'High'
    CRITICAL = 'critical', 'Critical'


class ModuleType(models.TextChoices):
    PHISHING = 'phishing', 'Phishing & Scam'
    DOCUMENT = 'document', 'Document Forensics'
    BEHAVIOR = 'behavior', 'Behavioral Anomaly'
    MALWARE = 'malware', 'Malware Prevention'
    PLATFORM = 'platform', 'Unified Platform'


class PhishingScan(TimeStampedModel):
    class InputType(models.TextChoices):
        URL = 'url', 'URL'
        MESSAGE = 'message', 'Message'
        HEADERS = 'headers', 'Headers'

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='phishing_scans'
    )
    input_type = models.CharField(max_length=20, choices=InputType.choices)
    target_url = models.CharField(max_length=2048, blank=True)
    raw_content = models.TextField(blank=True)
    headers = models.JSONField(default=dict, blank=True)
    domain_age_days = models.IntegerField(null=True, blank=True)
    reputation_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text='Computed trust score between 0 and 100.'
    )
    risk_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text='Higher means more dangerous.'
    )
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.LOW)
    detections = models.JSONField(default=dict, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)

    class Meta(TimeStampedModel.Meta):
        verbose_name = 'Phishing Scan'
        verbose_name_plural = 'Phishing Scans'
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['risk_level']),
        ]

    def __str__(self) -> str:
        target = self.target_url or (self.raw_content[:48] + '...' if self.raw_content else 'Unknown target')
        return f"Phishing scan {self.pk} ({self.get_risk_level_display()}) on {target}"


def document_upload_path(instance: 'DocumentAnalysis', filename: str) -> str:
    timestamp = timezone.now().strftime('%Y/%m/%d')
    return f"document_uploads/{timestamp}/{filename}"


class DocumentAnalysis(TimeStampedModel):
    class Verdict(models.TextChoices):
        AUTHENTIC = 'authentic', 'Authentic'
        SUSPICIOUS = 'suspicious', 'Suspicious'
        FORGED = 'forged', 'Forged'

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='document_analyses'
    )
    uploaded_file = models.FileField(upload_to=document_upload_path)
    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=64, blank=True)
    file_size = models.PositiveIntegerField(help_text='Size in bytes')
    sha256 = models.CharField(max_length=64, blank=True)
    ela_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        null=True,
        blank=True
    )
    text_confidence = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        null=True,
        blank=True
    )
    semantic_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        null=True,
        blank=True
    )
    verdict = models.CharField(max_length=16, choices=Verdict.choices, default=Verdict.AUTHENTIC)
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.LOW)
    findings = models.JSONField(default=dict, blank=True)
    highlighted_regions = models.JSONField(default=list, blank=True)
    ocr_text = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta(TimeStampedModel.Meta):
        verbose_name = 'Document Analysis'
        verbose_name_plural = 'Document Analyses'

    def __str__(self) -> str:
        return f"Document analysis {self.pk} ({self.get_verdict_display()})"


class BehaviorEvent(TimeStampedModel):
    class EventType(models.TextChoices):
        LOGIN = 'login', 'Login'
        DATA_ACCESS = 'data_access', 'Data Access'
        DOWNLOAD = 'download', 'Download'
        PRIVILEGE_CHANGE = 'privilege_change', 'Privilege Change'
        CONFIG_CHANGE = 'config_change', 'Configuration Change'
        OTHER = 'other', 'Other'

    actor_identifier = models.CharField(max_length=255, help_text='Typically the user email or system account.')
    event_type = models.CharField(max_length=32, choices=EventType.choices, default=EventType.OTHER)
    occurred_at = models.DateTimeField(default=timezone.now)
    location = models.CharField(max_length=128, blank=True)
    device = models.CharField(max_length=128, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    baseline_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        null=True,
        blank=True
    )
    risk_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=0
    )
    is_anomalous = models.BooleanField(default=False)
    anomaly_reasons = models.JSONField(default=list, blank=True)

    class Meta(TimeStampedModel.Meta):
        verbose_name = 'Behavior Event'
        verbose_name_plural = 'Behavior Events'
        indexes = [
            models.Index(fields=['actor_identifier']),
            models.Index(fields=['-occurred_at']),
            models.Index(fields=['is_anomalous']),
        ]

    def __str__(self) -> str:
        return f"{self.actor_identifier} - {self.get_event_type_display()} ({'Anomaly' if self.is_anomalous else 'Normal'})"


def malware_upload_path(instance: 'MalwareScan', filename: str) -> str:
    timestamp = timezone.now().strftime('%Y/%m/%d')
    return f"malware_uploads/{timestamp}/{filename}"


class MalwareScan(TimeStampedModel):
    class Verdict(models.TextChoices):
        CLEAN = 'clean', 'Clean'
        SUSPICIOUS = 'suspicious', 'Suspicious'
        MALICIOUS = 'malicious', 'Malicious'
        QUARANTINED = 'quarantined', 'Quarantined'

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='malware_scans'
    )
    uploaded_file = models.FileField(upload_to=malware_upload_path)
    file_name = models.CharField(max_length=255)
    file_type = models.CharField(max_length=64, blank=True)
    file_size = models.PositiveIntegerField(help_text='Size in bytes')
    sha256 = models.CharField(max_length=64, blank=True)
    entropy = models.DecimalField(
        max_digits=6,
        decimal_places=3,
        validators=[MinValueValidator(0), MaxValueValidator(8)],
        null=True,
        blank=True
    )
    signature_hits = models.JSONField(default=list, blank=True)
    heuristic_findings = models.JSONField(default=list, blank=True)
    external_references = models.JSONField(default=dict, blank=True)
    risk_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=0
    )
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.LOW)
    verdict = models.CharField(max_length=16, choices=Verdict.choices, default=Verdict.CLEAN)
    quarantine_path = models.CharField(max_length=512, blank=True)
    policy_applied = models.CharField(max_length=64, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta(TimeStampedModel.Meta):
        verbose_name = 'Malware Scan'
        verbose_name_plural = 'Malware Scans'
        indexes = [
            models.Index(fields=['risk_level']),
            models.Index(fields=['verdict']),
        ]

    def __str__(self) -> str:
        return f"Malware scan {self.pk} ({self.get_verdict_display()})"


class SecurityAlert(TimeStampedModel):
    class Status(models.TextChoices):
        NEW = 'new', 'New'
        INVESTIGATING = 'investigating', 'Investigating'
        MITIGATED = 'mitigated', 'Mitigated'
        CLOSED = 'closed', 'Closed'

    module = models.CharField(max_length=24, choices=ModuleType.choices)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.MEDIUM)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    source_object_id = models.PositiveIntegerField(null=True, blank=True)
    source_model = models.CharField(max_length=64, blank=True)
    insight = models.JSONField(default=dict, blank=True)
    remediation = models.JSONField(default=list, blank=True)
    acknowledged_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acknowledged_alerts'
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta(TimeStampedModel.Meta):
        verbose_name = 'Security Alert'
        verbose_name_plural = 'Security Alerts'
        indexes = [
            models.Index(fields=['module']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
        ]

    def mark_acknowledged(self, user: User | None = None) -> None:
        self.status = self.Status.INVESTIGATING
        self.acknowledged_by = user
        self.acknowledged_at = timezone.now()
        self.save(update_fields=['status', 'acknowledged_by', 'acknowledged_at', 'updated_at'])

    def mark_resolved(self, user: User | None = None) -> None:
        self.status = self.Status.MITIGATED
        if user and self.acknowledged_by is None:
            self.acknowledged_by = user
            self.acknowledged_at = timezone.now()
        self.resolved_at = timezone.now()
        self.save(update_fields=['status', 'acknowledged_by', 'acknowledged_at', 'resolved_at', 'updated_at'])

    def __str__(self) -> str:
        return f"{self.get_module_display()} Alert #{self.pk} ({self.get_severity_display()})"


from __future__ import annotations

from typing import Any

from django.utils import timezone

from ..models import (
    ModuleType,
    RiskLevel,
    SecurityAlert,
)


def _severity_from_risk(risk_level: RiskLevel) -> RiskLevel:
    return risk_level


def create_alert(
    *,
    module: ModuleType,
    title: str,
    description: str,
    severity: RiskLevel,
    source_object_id: int | None = None,
    source_model: str | None = None,
    insight: dict[str, Any] | None = None,
    remediation: list[str] | None = None,
) -> SecurityAlert:
    return SecurityAlert.objects.create(
        module=module,
        title=title,
        description=description,
        severity=severity,
        source_object_id=source_object_id,
        source_model=source_model or '',
        insight=insight or {},
        remediation=remediation or [],
    )


def alert_from_phishing(scan) -> SecurityAlert | None:
    severity = _severity_from_risk(scan.risk_level)
    if severity == RiskLevel.LOW:
        return None

    return create_alert(
        module=ModuleType.PHISHING,
        title='Phishing attempt detected',
        description=f"A {scan.get_risk_level_display()} risk phishing indicator was found for {scan.target_url or 'submitted content'}.",
        severity=severity,
        source_object_id=scan.pk,
        source_model='PhishingScan',
        insight={
            'risk_score': float(scan.risk_score),
            'recommendations': scan.recommendations,
        },
        remediation=[
            'Block sender/domain at the email gateway.',
            'Inform affected users and security operations centre.',
        ],
    )


def alert_from_document(analysis) -> SecurityAlert | None:
    severity = _severity_from_risk(analysis.risk_level)
    if severity == RiskLevel.LOW:
        return None

    return create_alert(
        module=ModuleType.DOCUMENT,
        title='Document forgery signal detected',
        description=f"{analysis.file_name} flagged as {analysis.get_verdict_display()}.",
        severity=severity,
        source_object_id=analysis.pk,
        source_model='DocumentAnalysis',
        insight={
            'ela_score': float(analysis.ela_score or 0),
            'semantic_score': float(analysis.semantic_score or 0),
        },
        remediation=[
            'Request original document from trusted source.',
            'Perform manual forensic review.',
        ],
    )


def alert_from_malware(scan) -> SecurityAlert | None:
    severity = _severity_from_risk(scan.risk_level)
    if severity == RiskLevel.LOW:
        return None

    actions = ['Notify SOC for containment.']
    if scan.quarantine_path:
        actions.append(f'Quarantined at {scan.quarantine_path}. Review before release.')

    return create_alert(
        module=ModuleType.MALWARE,
        title='Malware signature detected',
        description=f"{scan.file_name} scored {scan.risk_score} and is classified as {scan.get_verdict_display()}.",
        severity=severity,
        source_object_id=scan.pk,
        source_model='MalwareScan',
        insight={
            'signature_hits': scan.signature_hits,
            'heuristics': scan.heuristic_findings,
        },
        remediation=actions,
    )


def alert_from_behavior(event) -> SecurityAlert | None:
    """Create an alert for anomalous behavior events."""
    if not event.is_anomalous:
        return None

    # Map behavior risk_score to severity
    risk_score = float(event.risk_score)
    if risk_score >= 80:
        severity = RiskLevel.CRITICAL
    elif risk_score >= 60:
        severity = RiskLevel.HIGH
    elif risk_score >= 35:
        severity = RiskLevel.MEDIUM
    else:
        return None

    reasons_text = '; '.join(event.anomaly_reasons[:3]) if event.anomaly_reasons else 'Statistical anomaly detected.'
    detection_mode = event.metadata.get('detection_mode', 'unknown') if isinstance(event.metadata, dict) else 'unknown'

    return create_alert(
        module=ModuleType.BEHAVIOR,
        title=f'Behavioral anomaly: {event.get_event_type_display()} by {event.actor_identifier}',
        description=(
            f'{event.actor_identifier} triggered anomaly detection ({detection_mode} mode, '
            f'score {risk_score:.0f}). Reasons: {reasons_text}'
        ),
        severity=severity,
        source_object_id=event.pk,
        source_model='BehaviorEvent',
        insight={
            'risk_score': risk_score,
            'detection_mode': detection_mode,
            'anomaly_reasons': event.anomaly_reasons,
        },
        remediation=[
            f'Review recent activity for {event.actor_identifier}.',
            'Verify identity through secondary channel if risk is high.',
            'Consider temporary access restriction pending investigation.',
        ],
    )


def uplift_alert(alert: SecurityAlert, action: str, user=None) -> SecurityAlert:
    if action == 'acknowledge':
        alert.mark_acknowledged(user)
    elif action == 'resolve':
        alert.mark_resolved(user)
    elif action == 'close':
        alert.status = SecurityAlert.Status.CLOSED
        alert.resolved_at = timezone.now()
        alert.save(update_fields=['status', 'resolved_at', 'updated_at'])
    return alert


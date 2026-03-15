"""
behavior.py — Behavioral Anomaly Detection Service

Two-mode detection engine:
  • Cold-start (< ISOLATION_THRESHOLD events): enhanced rule-based scoring
  • ML mode (>= ISOLATION_THRESHOLD events): scikit-learn IsolationForest
    trained on the actor's 30-day history, with a post-hoc explainability layer.

Model persistence: api/dashboard/ml_models/behavior_{actor_id}.pkl
Retrain trigger: every RETRAIN_EVERY new events for the actor.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, time, timedelta
from typing import Any, Iterable

import numpy as np
from django.utils import timezone

from ..models import BehaviorEvent, RiskLevel
from .ml_utils import load_model, save_model

logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────

ISOLATION_THRESHOLD = 15   # min events before switching to IsolationForest
RETRAIN_EVERY = 10         # retrain after this many new events
LOOKBACK_DAYS = 30

EVENT_TYPE_MAP = {
    BehaviorEvent.EventType.LOGIN: 0,
    BehaviorEvent.EventType.DATA_ACCESS: 1,
    BehaviorEvent.EventType.DOWNLOAD: 2,
    BehaviorEvent.EventType.PRIVILEGE_CHANGE: 3,
    BehaviorEvent.EventType.CONFIG_CHANGE: 4,
    BehaviorEvent.EventType.OTHER: 5,
}

# Higher-risk event types get a rule boost even in ML mode
HIGH_RISK_EVENT_TYPES = {
    BehaviorEvent.EventType.PRIVILEGE_CHANGE,
    BehaviorEvent.EventType.CONFIG_CHANGE,
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_off_hours(dt: datetime) -> bool:
    return time(0, 0) <= dt.time() <= time(6, 0)


def _is_weekend(dt: datetime) -> bool:
    return dt.weekday() >= 5


def _unique_ratio(values: Iterable[str]) -> float:
    vals = [v for v in values if v]
    if not vals:
        return 0.0
    return len(set(vals)) / len(vals)


def _build_feature_vector(
    event: BehaviorEvent,
    history: list[BehaviorEvent],
    recent_1h: int,
) -> list[float]:
    """
    Return a 10-element numeric feature vector for one event.

    Features:
      0  hour_of_day           (0–23)
      1  day_of_week           (0–6)
      2  is_off_hours          (0/1, 0–6 AM)
      3  is_weekend            (0/1)
      4  new_location          (0/1, location not in 30-day history)
      5  new_device            (0/1, device not in 30-day history)
      6  event_type_encoded    (0–4)
      7  recent_events_1h      (count of events in the last hour)
      8  distinct_locations_30d  (count of unique locations)
      9  distinct_devices_30d    (count of unique devices)
    """
    past_locations = {e.location for e in history if e.location}
    past_devices = {e.device for e in history if e.device}
    distinct_locations = len(past_locations)
    distinct_devices = len(past_devices)

    new_loc = int(bool(event.location) and event.location not in past_locations)
    new_dev = int(bool(event.device) and event.device not in past_devices)

    return [
        float(event.occurred_at.hour),
        float(event.occurred_at.weekday()),
        float(_is_off_hours(event.occurred_at)),
        float(_is_weekend(event.occurred_at)),
        float(new_loc),
        float(new_dev),
        float(EVENT_TYPE_MAP.get(event.event_type, 0)),
        float(recent_1h),
        float(distinct_locations),
        float(distinct_devices),
    ]


# ─── Cold-Start: Enhanced Rule-Based Scoring ──────────────────────────────────

def _rule_based_score(
    event: BehaviorEvent,
    history: list[BehaviorEvent],
) -> tuple[float, list[str]]:
    """Enhanced heuristic scoring used when not enough data for IsolationForest."""
    risk = 0.0
    reasons: list[str] = []

    if _is_off_hours(event.occurred_at):
        risk += 20
        reasons.append(f'Activity at {event.occurred_at.strftime("%H:%M")} – outside business hours (00:00–06:00).')

    if _is_weekend(event.occurred_at):
        risk += 10
        reasons.append('Activity on a weekend day.')

    past_locations = [e.location for e in history if e.location]
    if event.location and past_locations and event.location not in past_locations:
        risk += 25
        reasons.append(f'New geographic location detected: "{event.location}".')

    past_devices = [e.device for e in history if e.device]
    if event.device and past_devices and event.device not in past_devices:
        risk += 15
        reasons.append(f'Unrecognised device fingerprint: "{event.device}".')

    event_counter = Counter(e.event_type for e in history)
    if event_counter.get(event.event_type, 0) <= 1:
        risk += 15
        reasons.append(f'Rare activity type for this user: {event.event_type}.')

    ip_ratio = _unique_ratio(
        e.metadata.get('ip', '') for e in history if isinstance(e.metadata, dict)
    )
    if ip_ratio > 0.5:
        risk += 5
        reasons.append('High variance in source IP addresses recently.')

    if event.event_type in HIGH_RISK_EVENT_TYPES:
        risk += 10
        reasons.append(f'High-sensitivity action: {event.event_type}.')

    return min(risk, 100.0), reasons


# ─── ML Mode: IsolationForest ─────────────────────────────────────────────────

def _train_isolation_forest(X: np.ndarray, actor_id: str) -> tuple[Any, Any]:
    """Train IsolationForest + StandardScaler on historical feature matrix."""
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_scaled)

    save_model(f'behavior_{actor_id}', (clf, scaler))
    return clf, scaler


def _isolation_forest_score(
    current_vec: list[float],
    actor_id: str,
    history: list[BehaviorEvent],
    history_vecs: list[list[float]],
) -> float:
    """
    Compute a 0–100 anomaly risk score using IsolationForest.

    decision_function returns negative scores for anomalies.
    We map the typical range [-0.5, 0.5] → [100, 0].
    """
    X = np.array(history_vecs, dtype=float)
    loaded = load_model(f'behavior_{actor_id}')

    # Retrain if no persisted model or retrain trigger fires
    total_events = len(history)
    if loaded is None or (total_events % RETRAIN_EVERY == 0):
        clf, scaler = _train_isolation_forest(X, actor_id)
    else:
        clf, scaler = loaded

    x_scaled = scaler.transform([current_vec])
    raw_score = clf.decision_function(x_scaled)[0]   # more negative = more anomalous

    # Normalise to 0–100
    risk = max(0.0, min(100.0, (-raw_score + 0.5) * 100.0))
    return round(risk, 1)


# ─── Explainability Layer ─────────────────────────────────────────────────────

def _explain_from_features(
    current: list[float],
    history: list[BehaviorEvent],
    event: BehaviorEvent,
) -> list[str]:
    """
    Generate human-readable anomaly reasons by comparing current features
    against the actor's historical mean/std — used after IsolationForest flags.
    """
    reasons: list[str] = []

    if current[2]:  # is_off_hours
        reasons.append(f'Login at {event.occurred_at.strftime("%H:%M")} – outside normal business hours.')
    if current[3]:  # is_weekend
        reasons.append('Activity on a weekend.')
    if current[4]:  # new_location
        reasons.append(f'First-time access from location: "{event.location}".')
    if current[5]:  # new_device
        reasons.append(f'Unrecognised device: "{event.device}".')

    # Frequency anomaly: compare recent_events_1h against historical mean
    if history:
        hist_counts = []
        for e in history:
            window_start = e.occurred_at - timedelta(hours=1)
            cnt = sum(1 for h in history if window_start <= h.occurred_at <= e.occurred_at)
            hist_counts.append(cnt)
        if hist_counts:
            mean_freq = sum(hist_counts) / len(hist_counts)
            if mean_freq > 0 and current[7] > mean_freq * 3:
                reasons.append(
                    f'Activity frequency {current[7]:.0f}× in last hour '
                    f'vs baseline {mean_freq:.1f}×.'
                )

    if event.event_type in HIGH_RISK_EVENT_TYPES:
        reasons.append(f'High-sensitivity action performed: {event.event_type}.')

    if not reasons:
        reasons.append('Statistical anomaly detected by IsolationForest model.')

    return reasons


# ─── Public API ───────────────────────────────────────────────────────────────

def score_event(event: BehaviorEvent, recent_events: Iterable[BehaviorEvent]) -> dict[str, Any]:
    """
    Score a BehaviorEvent for anomaly risk.

    Automatically switches between cold-start rule-based and IsolationForest
    depending on how many historical events exist for this actor.
    """
    history = list(recent_events)

    # Count events in the last 1 hour for frequency feature
    one_hour_ago = event.occurred_at - timedelta(hours=1)
    recent_1h = sum(1 for e in history if e.occurred_at >= one_hour_ago)

    current_vec = _build_feature_vector(event, history, recent_1h)

    mode = 'ml' if len(history) >= ISOLATION_THRESHOLD else 'rule'

    if mode == 'rule':
        risk_score, reasons = _rule_based_score(event, history)
    else:
        # Build feature matrix for all historical events
        history_vecs: list[list[float]] = []
        for h in history:
            h_1h = sum(1 for e in history if e.occurred_at >= h.occurred_at - timedelta(hours=1)
                       and e.occurred_at <= h.occurred_at)
            history_vecs.append(_build_feature_vector(h, history, h_1h))

        actor_id = str(event.actor_identifier).replace(' ', '_').replace('@', '_at_')[:50]
        risk_score = _isolation_forest_score(current_vec, actor_id, history, history_vecs)

        if risk_score >= 35:
            reasons = _explain_from_features(current_vec, history, event)
        else:
            reasons = []

    risk_level = (
        RiskLevel.CRITICAL if risk_score >= 80 else
        RiskLevel.HIGH if risk_score >= 60 else
        RiskLevel.MEDIUM if risk_score >= 35 else
        RiskLevel.LOW
    )

    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'reasons': reasons,
        'detection_mode': mode,
        'history_count': len(history),
    }


def detect_and_update(event: BehaviorEvent) -> BehaviorEvent:
    """Compute anomaly score for an event and persist results to DB."""
    window_start = timezone.now() - timedelta(days=LOOKBACK_DAYS)
    history = BehaviorEvent.objects.filter(
        actor_identifier=event.actor_identifier,
        occurred_at__gte=window_start,
    ).exclude(pk=event.pk)

    result = score_event(event, history)

    event.risk_score = result['risk_score']
    event.is_anomalous = result['risk_level'] in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
    event.anomaly_reasons = result['reasons']

    # Persist detection metadata for UI display
    meta = event.metadata if isinstance(event.metadata, dict) else {}
    meta['detection_mode'] = result['detection_mode']
    meta['history_count'] = result['history_count']
    event.metadata = meta

    event.save(update_fields=['risk_score', 'is_anomalous', 'anomaly_reasons', 'metadata', 'updated_at'])
    return event


def build_timeline(days: int = 7) -> list[dict[str, Any]]:
    """Build a day-by-day summary of behavior events for dashboard charts."""
    start = timezone.now() - timedelta(days=days)
    events = BehaviorEvent.objects.filter(created_at__gte=start).order_by('created_at')
    buckets: dict[str, dict[str, Any]] = {}

    for event in events:
        day_key = event.created_at.date().isoformat()
        bucket = buckets.setdefault(day_key, {'day': day_key, 'total': 0, 'anomalies': 0})
        bucket['total'] += 1
        if event.is_anomalous:
            bucket['anomalies'] += 1

    return list(buckets.values())

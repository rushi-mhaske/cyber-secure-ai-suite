"""
ml_utils.py — Shared ML infrastructure for all security modules.

Provides:
- NLTK data bootstrapper (auto-downloads corpora on first run)
- Gemini client factory (returns None gracefully if API key absent)
- Model persistence helpers (joblib save/load for sklearn models)
- TensorFlow/Keras model persistence helpers (save/load CNN, etc.)
- HuggingFace Transformers pipeline loader (lazy, cached)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ─── Paths ────────────────────────────────────────────────────────────────────

# api/dashboard/ml_models/
ML_MODELS_DIR = Path(__file__).resolve().parent.parent / 'ml_models'
ML_MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ─── NLTK Bootstrap ───────────────────────────────────────────────────────────

_NLTK_BOOTSTRAPPED = False


def ensure_nltk_data() -> None:
    """Download required NLTK corpora on first call; silent no-op thereafter."""
    global _NLTK_BOOTSTRAPPED
    if _NLTK_BOOTSTRAPPED:
        return
    try:
        import nltk
        for pkg in ('punkt_tab', 'stopwords', 'vader_lexicon', 'wordnet', 'averaged_perceptron_tagger'):
            nltk.download(pkg, quiet=True)
        _NLTK_BOOTSTRAPPED = True
    except Exception as exc:  # pragma: no cover
        logger.warning('NLTK bootstrap failed: %s', exc)


# ─── Gemini Client ────────────────────────────────────────────────────────────

def get_gemini_client():
    """
    Return a configured google.genai.Client, or None if GEMINI_API_KEY is not set.

    All callers must handle None gracefully.
    """
    try:
        from django.conf import settings
        key: str = getattr(settings, 'GEMINI_API_KEY', '')
        if not key:
            return None
        from google import genai
        return genai.Client(api_key=key)
    except Exception as exc:  # pragma: no cover
        logger.warning('Gemini client init failed: %s', exc)
        return None


def call_gemini_json(client, prompt: str, model: str = 'gemini-2.5-flash') -> dict[str, Any]:
    """
    Send a text prompt to Gemini and parse the JSON response.

    Returns an empty dict on any error, so callers can use .get() safely.
    """
    if client is None:
        return {}
    try:
        response = client.models.generate_content(model=model, contents=prompt)
        text = response.text.strip()
        # Strip markdown code fences if present
        if text.startswith('```'):
            text = text.split('```', 2)[1]
            if text.startswith('json'):
                text = text[4:]
        return json.loads(text)
    except Exception as exc:
        logger.warning('Gemini JSON call failed: %s', exc)
        return {}


def call_gemini_vision_json(client, image_bytes: bytes, mime_type: str, prompt: str,
                             model: str = 'gemini-2.5-flash') -> dict[str, Any]:
    """
    Send an image + prompt to Gemini Vision and parse the JSON response.

    Returns an empty dict on any error.
    """
    if client is None:
        return {}
    try:
        from google.genai import types
        response = client.models.generate_content(
            model=model,
            contents=[
                types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
                prompt,
            ],
        )
        text = response.text.strip()
        if text.startswith('```'):
            text = text.split('```', 2)[1]
            if text.startswith('json'):
                text = text[4:]
        return json.loads(text)
    except Exception as exc:
        logger.warning('Gemini Vision call failed: %s', exc)
        return {}


# ─── Model Persistence ────────────────────────────────────────────────────────

def save_model(name: str, payload: Any) -> None:
    """Persist a model (or tuple of model+scaler) to disk using joblib."""
    try:
        import joblib
        path = ML_MODELS_DIR / f'{name}.pkl'
        joblib.dump(payload, path)
    except Exception as exc:  # pragma: no cover
        logger.warning('Model save failed (%s): %s', name, exc)


def load_model(name: str) -> Any:
    """Load a persisted model from disk; returns None if not found."""
    try:
        import joblib
        path = ML_MODELS_DIR / f'{name}.pkl'
        if path.exists():
            return joblib.load(path)
    except Exception as exc:  # pragma: no cover
        logger.warning('Model load failed (%s): %s', name, exc)
    return None


# ─── TensorFlow / Keras Helpers ──────────────────────────────────────────────

def save_tf_model(name: str, model: Any) -> None:
    """Save a TensorFlow/Keras model to the ml_models directory."""
    try:
        path = ML_MODELS_DIR / f'{name}.keras'
        model.save(str(path))
    except Exception as exc:  # pragma: no cover
        logger.warning('TF model save failed (%s): %s', name, exc)


def load_tf_model(name: str) -> Any:
    """Load a TensorFlow/Keras model from disk; returns None if not found."""
    try:
        import tensorflow as tf
        path = ML_MODELS_DIR / f'{name}.keras'
        if path.exists():
            return tf.keras.models.load_model(str(path))
    except Exception as exc:  # pragma: no cover
        logger.warning('TF model load failed (%s): %s', name, exc)
    return None


# ─── HuggingFace Transformers ────────────────────────────────────────────────

_TRANSFORMER_CACHE: dict[str, Any] = {}


def get_transformer_pipeline(task: str, model_name: str) -> Any:
    """
    Lazy-load and cache a HuggingFace transformers pipeline.

    Returns None if transformers/torch isn't installed or model download fails.
    Callers must handle None gracefully.
    """
    cache_key = f'{task}:{model_name}'
    if cache_key in _TRANSFORMER_CACHE:
        return _TRANSFORMER_CACHE[cache_key]

    # Require PyTorch before attempting to load a transformers pipeline
    try:
        import torch  # noqa: F401
    except ImportError:
        logger.debug('PyTorch not installed — skipping transformer pipeline (%s/%s)', task, model_name)
        _TRANSFORMER_CACHE[cache_key] = None
        return None

    try:
        from transformers import pipeline
        pipe = pipeline(task, model=model_name)
        _TRANSFORMER_CACHE[cache_key] = pipe
        return pipe
    except Exception as exc:
        logger.warning('Transformer pipeline load failed (%s/%s): %s', task, model_name, exc)
        _TRANSFORMER_CACHE[cache_key] = None
        return None


# ─── WHOIS Domain Age Helper ────────────────────────────────────────────────

_WHOIS_CACHE: dict[str, int | None] = {}


def get_domain_age_days(domain: str) -> int | None:
    """
    Look up WHOIS creation date for a domain.

    Returns age in days, or None if lookup fails.
    Caches results in-memory for the process lifetime.
    """
    if not domain:
        return None

    if domain in _WHOIS_CACHE:
        return _WHOIS_CACHE[domain]

    try:
        import whois
        from datetime import datetime, timezone as tz

        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            now = datetime.now(tz.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=tz.utc)
            age = (now - creation).days
            result = max(age, 0)
            _WHOIS_CACHE[domain] = result
            return result
    except Exception as exc:
        logger.debug('WHOIS lookup failed for %s: %s', domain, exc)

    _WHOIS_CACHE[domain] = None
    return None

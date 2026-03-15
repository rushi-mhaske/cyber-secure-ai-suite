"""
document.py — Document Forgery Detection Service

Four-technique forensic pipeline:
  1. Multi-pass ELA with regional analysis (OpenCV, 3 quality levels, 4×4 grid)
  2. EXIF metadata anomaly detection (Pillow ExifTags)
  3. Enhanced OCR confidence scoring (pytesseract per-word confidence)
  4. Gemini Vision analysis (optional, images only)

Final score = weighted combination of all active techniques.
"""
from __future__ import annotations

import hashlib
import io
import logging
import re
import statistics
import tempfile
import os
from typing import Any

import filetype
import numpy as np
from django.core.files.uploadedfile import UploadedFile

from ..models import DocumentAnalysis, RiskLevel
from .ml_utils import call_gemini_vision_json, get_gemini_client, save_tf_model, load_tf_model

logger = logging.getLogger(__name__)

try:
    from PIL import Image, ImageChops, ImageStat, ExifTags
    PIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    PIL_AVAILABLE = False

try:
    import cv2
    CV2_AVAILABLE = True
except ImportError:  # pragma: no cover
    CV2_AVAILABLE = False

try:
    import pytesseract
    from pytesseract import Output as TessOutput
    TESSERACT_AVAILABLE = True
except ImportError:  # pragma: no cover
    TESSERACT_AVAILABLE = False

try:
    import fitz as pymupdf  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYMUPDF_AVAILABLE = False

try:
    import docx as python_docx
    PYTHON_DOCX_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYTHON_DOCX_AVAILABLE = False


# ─── CNN Forgery Detector (PPT: ForgeryNet – CNN + OCR) ──────────────────────

_CNN_INPUT_SIZE = (128, 128)


def _build_forgery_cnn():
    """
    Build a CNN architecture for document forgery classification.

    Architecture mirrors the ForgeryNet paper: Conv2D layers extract
    spatial tampering features from ELA difference images.
    """
    try:
        import tensorflow as tf
        model = tf.keras.Sequential([
            tf.keras.layers.Conv2D(32, (3, 3), activation='relu',
                                   input_shape=(*_CNN_INPUT_SIZE, 3)),
            tf.keras.layers.MaxPooling2D((2, 2)),
            tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
            tf.keras.layers.MaxPooling2D((2, 2)),
            tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
            tf.keras.layers.Flatten(),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.5),
            tf.keras.layers.Dense(1, activation='sigmoid'),
        ])
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy'],
        )
        return model
    except Exception as exc:
        logger.warning('CNN model build failed: %s', exc)
        return None


def _prepare_ela_for_cnn(image: 'Image.Image') -> 'np.ndarray | None':
    """
    Generate an ELA difference image and resize/normalise for CNN input.
    Returns a (1, 128, 128, 3) numpy array or None.
    """
    if not PIL_AVAILABLE:
        return None
    try:
        buf = io.BytesIO()
        rgb = image.convert('RGB')
        rgb.save(buf, 'JPEG', quality=75)
        buf.seek(0)
        compressed = Image.open(buf).convert('RGB')
        ela_img = ImageChops.difference(rgb, compressed)

        # Resize to CNN input size
        ela_resized = ela_img.resize(_CNN_INPUT_SIZE, Image.BILINEAR)
        arr = np.array(ela_resized, dtype=np.float32) / 255.0
        return arr.reshape(1, *_CNN_INPUT_SIZE, 3)
    except Exception:
        return None


def _cnn_forgery_score(image: 'Image.Image') -> dict[str, Any]:
    """
    Run the CNN forgery detector on an image.

    If no trained model exists, trains on a small synthetic set to
    initialise the pipeline (will be retrained as data accumulates).
    """
    ela_input = _prepare_ela_for_cnn(image)
    if ela_input is None:
        return {'score': 0.0, 'available': False}

    try:
        model = load_tf_model('forgery_cnn')
        if model is None:
            # Build and save an initialised (untrained baseline) model
            model = _build_forgery_cnn()
            if model is None:
                return {'score': 0.0, 'available': False}

            # Curated synthetic ELA difference patterns
            import tensorflow as tf
            rng = np.random.RandomState(42)
            n_each = 50

            # Clean images: low uniform ELA noise (genuine compression artifacts)
            clean = np.zeros((n_each, *_CNN_INPUT_SIZE, 3), dtype=np.float32)
            for i in range(n_each):
                base_noise = rng.uniform(0.01, 0.10)
                clean[i] = rng.normal(base_noise, 0.02, (*_CNN_INPUT_SIZE, 3)).clip(0, 0.3).astype(np.float32)

            # Forged images: low bg + localised high-ELA hotspots (spliced regions)
            forged = np.zeros((n_each, *_CNN_INPUT_SIZE, 3), dtype=np.float32)
            for i in range(n_each):
                bg_noise = rng.uniform(0.01, 0.08)
                forged[i] = rng.normal(bg_noise, 0.02, (*_CNN_INPUT_SIZE, 3)).clip(0, 0.2).astype(np.float32)
                # Add 1-3 rectangular hotspot regions simulating spliced areas
                n_hotspots = rng.randint(1, 4)
                for _ in range(n_hotspots):
                    r1 = rng.randint(0, _CNN_INPUT_SIZE[0] - 20)
                    c1 = rng.randint(0, _CNN_INPUT_SIZE[1] - 20)
                    r2 = min(r1 + rng.randint(15, 50), _CNN_INPUT_SIZE[0])
                    c2 = min(c1 + rng.randint(15, 50), _CNN_INPUT_SIZE[1])
                    hotspot_val = rng.uniform(0.25, 0.70)
                    forged[i, r1:r2, c1:c2, :] = rng.normal(
                        hotspot_val, 0.08, (r2 - r1, c2 - c1, 3)
                    ).clip(0.15, 0.85).astype(np.float32)

            X = np.vstack([clean, forged])
            y = np.array([0] * n_each + [1] * n_each, dtype=np.float32)

            model.fit(X, y, epochs=8, batch_size=16, verbose=0)
            save_tf_model('forgery_cnn', model)

        prediction = float(model.predict(ela_input, verbose=0)[0][0])
        return {
            'score': round(prediction * 100, 1),
            'available': True,
        }
    except Exception as exc:
        logger.warning('CNN forgery detection failed: %s', exc)
        return {'score': 0.0, 'available': False}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _compute_sha256(file: UploadedFile) -> str:
    sha = hashlib.sha256()
    if hasattr(file, 'chunks'):
        for chunk in file.chunks():
            sha.update(chunk)
    else:
        sha.update(file.read())
    file.seek(0)
    return sha.hexdigest()


def _detect_type(file: UploadedFile) -> tuple[str | None, str | None]:
    header = file.read(261)
    file.seek(0)
    guess = filetype.guess(header)
    if guess:
        return guess.mime, guess.extension
    return None, None


# ─── PDF Text Extraction (PyMuPDF) ────────────────────────────────────────────

def _extract_pdf_text(file: UploadedFile) -> dict[str, Any]:
    """Extract text from PDF using PyMuPDF. Returns text + page count + metadata."""
    if not PYMUPDF_AVAILABLE:
        return {'text': '', 'page_count': 0, 'findings': [], 'available': False}

    try:
        file.seek(0)
        pdf_bytes = file.read()
        file.seek(0)
        doc = pymupdf.open(stream=pdf_bytes, filetype='pdf')
        pages_text = []
        for page in doc:
            pages_text.append(page.get_text())
        full_text = '\n'.join(pages_text)

        findings: list[str] = []
        metadata_dict = doc.metadata or {}

        # Check for suspicious PDF metadata
        producer = metadata_dict.get('producer', '').lower()
        creator = metadata_dict.get('creator', '').lower()
        if any(sw in producer for sw in ('photoshop', 'gimp', 'inkscape')):
            findings.append(f'PDF produced by image editor: {metadata_dict.get("producer", "")}')
        if any(sw in creator for sw in ('photoshop', 'gimp', 'inkscape')):
            findings.append(f'PDF created by image editor: {metadata_dict.get("creator", "")}')

        # Check for embedded JavaScript (malicious PDF indicator)
        raw_bytes = pdf_bytes.lower()
        if b'/javascript' in raw_bytes or b'/js ' in raw_bytes:
            findings.append('Embedded JavaScript detected in PDF — potential malicious content.')

        page_count = len(doc)
        doc.close()

        return {
            'text': full_text,
            'page_count': page_count,
            'findings': findings,
            'pdf_metadata': {k: str(v)[:200] for k, v in metadata_dict.items() if v},
            'available': True,
        }
    except Exception as exc:
        logger.warning('PDF text extraction failed: %s', exc)
        return {'text': '', 'page_count': 0, 'findings': [], 'available': False}


# ─── DOCX Text Extraction (python-docx) ──────────────────────────────────────

def _extract_docx_text(file: UploadedFile) -> dict[str, Any]:
    """Extract text from DOCX using python-docx. Returns text + metadata."""
    if not PYTHON_DOCX_AVAILABLE:
        return {'text': '', 'findings': [], 'available': False}

    try:
        file.seek(0)
        doc = python_docx.Document(file)
        paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        full_text = '\n'.join(paragraphs)

        findings: list[str] = []

        # Check core properties for editing indicators
        props = doc.core_properties
        if props.last_modified_by and props.author:
            if props.last_modified_by != props.author:
                findings.append(
                    f'Different author ("{props.author}") and last editor '
                    f'("{props.last_modified_by}") — possible tampering.'
                )
        if props.revision and int(props.revision or 0) > 50:
            findings.append(f'High revision count ({props.revision}) — heavily edited document.')

        # Check for VBA macros
        file.seek(0)
        content = file.read()
        file.seek(0)
        if b'vbaProject.bin' in content:
            findings.append('Document contains VBA macros — potential security risk.')

        return {
            'text': full_text,
            'findings': findings,
            'docx_metadata': {
                'author': str(props.author or ''),
                'last_modified_by': str(props.last_modified_by or ''),
                'revision': str(props.revision or ''),
            },
            'available': True,
        }
    except Exception as exc:
        logger.warning('DOCX text extraction failed: %s', exc)
        return {'text': '', 'findings': [], 'available': False}


# ─── Technique 1: Multi-Pass ELA with Regional Analysis ───────────────────────

def _ela_single_pass(image: 'Image.Image', quality: int) -> 'np.ndarray':
    """
    Perform one ELA pass at the given JPEG quality.
    Returns a numpy array of pixel-level absolute differences.
    """
    buf = io.BytesIO()
    rgb_image = image.convert('RGB')
    rgb_image.save(buf, 'JPEG', quality=quality)
    buf.seek(0)
    compressed = Image.open(buf).convert('RGB')

    ela_img = ImageChops.difference(rgb_image, compressed)
    return np.array(ela_img, dtype=np.float32)


def _compute_multipass_ela(image: 'Image.Image') -> dict[str, Any]:
    """
    Multi-pass ELA at qualities 65, 75, 85.
    Divides the difference map into a 4×4 grid (16 blocks).
    Flags blocks where mean difference > 2.5× global average.
    """
    if not PIL_AVAILABLE or not CV2_AVAILABLE:
        return _compute_ela_fallback(image)

    quality_weights = {65: 0.50, 75: 0.30, 85: 0.20}
    combined_diff = None

    for quality, weight in quality_weights.items():
        try:
            diff = _ela_single_pass(image, quality)
            if combined_diff is None:
                combined_diff = diff * weight
            else:
                combined_diff += diff * weight
        except Exception as exc:
            logger.debug('ELA pass q=%d failed: %s', quality, exc)

    if combined_diff is None:
        return {'ela_score': 0.0, 'hotspot_count': 0, 'regional_map': []}

    # Overall ELA score (mean of combined diff, normalised to 0-100)
    mean_diff = float(np.mean(combined_diff))
    ela_score = min(mean_diff * 2.5, 100.0)   # scale factor calibrated empirically

    # Regional 4×4 grid analysis
    h, w = combined_diff.shape[:2]
    rows, cols = 4, 4
    block_h, block_w = max(h // rows, 1), max(w // cols, 1)
    global_mean = float(np.mean(combined_diff))
    threshold = global_mean * 2.5

    hotspot_count = 0
    regional_map: list[dict[str, Any]] = []

    for r in range(rows):
        for c in range(cols):
            block = combined_diff[r * block_h:(r + 1) * block_h, c * block_w:(c + 1) * block_w]
            block_mean = float(np.mean(block))
            is_hotspot = block_mean > threshold and global_mean > 0
            if is_hotspot:
                hotspot_count += 1
            regional_map.append({
                'row': r, 'col': c,
                'mean_diff': round(block_mean, 2),
                'is_hotspot': is_hotspot,
            })

    # Boost ela_score if hotspots found
    if hotspot_count >= 3:
        ela_score = min(ela_score + hotspot_count * 5, 100.0)
    elif hotspot_count >= 1:
        ela_score = min(ela_score + hotspot_count * 2, 100.0)

    return {
        'ela_score': round(ela_score, 2),
        'hotspot_count': hotspot_count,
        'regional_map': regional_map[:8],   # store first 8 for dashboard
        'global_mean_diff': round(global_mean, 3),
    }


def _compute_ela_fallback(image: 'Image.Image') -> dict[str, Any]:
    """Pillow-only ELA at single quality 90 (original logic, fallback)."""
    if not PIL_AVAILABLE:
        return {'ela_score': 0.0, 'hotspot_count': 0, 'regional_map': []}
    try:
        buf = io.BytesIO()
        image.convert('RGB').save(buf, 'JPEG', quality=90)
        buf.seek(0)
        compressed = Image.open(buf)
        ela = ImageChops.difference(image.convert('RGB'), compressed)
        stat = ImageStat.Stat(ela)
        score = sum(stat.mean) / len(stat.mean)
        return {'ela_score': round(min(score * 2, 100.0), 2), 'hotspot_count': 0, 'regional_map': []}
    except Exception:
        return {'ela_score': 0.0, 'hotspot_count': 0, 'regional_map': []}


# ─── Technique 2: EXIF Metadata Analysis ─────────────────────────────────────

# Software known to be used for editing (not creating) images
EDITING_SOFTWARE = {
    'adobe photoshop', 'photoshop', 'gimp', 'canva', 'affinity photo',
    'paint.net', 'lightroom', 'snapseed', 'facetune', 'meitu',
    'corel paintshop', 'pixlr', 'fotor',
}


def _analyse_exif(image: 'Image.Image') -> dict[str, Any]:
    """
    Extract and analyse EXIF metadata for forgery indicators.
    Returns a score 0–40 and list of findings.
    """
    score = 0.0
    findings: list[str] = []
    exif_data: dict[str, Any] = {}

    if not PIL_AVAILABLE:
        return {'score': 0.0, 'findings': [], 'exif': {}}

    try:
        raw_exif = image._getexif()  # type: ignore[attr-defined]
        if raw_exif is None:
            # No EXIF at all on a JPEG usually means metadata was stripped
            mime_guess = getattr(image, 'format', '') or ''
            if mime_guess.upper() in ('JPEG', 'JPG'):
                score += 10
                findings.append('EXIF metadata absent on JPEG – may have been stripped after editing.')
            return {'score': score, 'findings': findings, 'exif': {}}

        # Map tag IDs to names
        for tag_id, value in raw_exif.items():
            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
            exif_data[tag_name] = str(value)[:200]   # truncate long values

    except (AttributeError, Exception):
        return {'score': 0.0, 'findings': [], 'exif': {}}

    # Check 1: Editing software
    software = exif_data.get('Software', '').lower()
    if any(sw in software for sw in EDITING_SOFTWARE):
        score += 20
        findings.append(f'Image editing software detected in EXIF: "{exif_data.get("Software", "")}".')

    # Check 2: DateTime vs DateTimeOriginal mismatch
    dt_created = exif_data.get('DateTimeOriginal', '')
    dt_modified = exif_data.get('DateTime', '')
    if dt_created and dt_modified and dt_created != dt_modified:
        score += 15
        findings.append(
            f'Timestamp mismatch – original: "{dt_created}", '
            f'modified: "{dt_modified}".'
        )

    # Check 3: Camera Make/Model present but Software also present (edited after capture)
    make = exif_data.get('Make', '').strip()
    model = exif_data.get('Model', '').strip()
    if software and not make and not model:
        score += 15
        findings.append('No camera make/model but editing software tag present.')
    elif software and make:
        score += 5
        findings.append(f'Camera image ({make} {model}) shows editing software signature.')

    # Check 4: GPS anomaly (coordinates at 0,0 = equator/prime meridian)
    gps_info = exif_data.get('GPSInfo', '')
    if gps_info and ('0/1' in gps_info or '0, 0' in gps_info):
        score += 10
        findings.append('GPS coordinates at 0,0 – possible placeholder/forged GPS data.')

    return {
        'score': min(score, 40.0),
        'findings': findings,
        'exif': {k: v for k, v in exif_data.items()
                 if k in ('Make', 'Model', 'Software', 'DateTime',
                           'DateTimeOriginal', 'ImageWidth', 'ImageLength')},
    }


# ─── Technique 3: Enhanced OCR Confidence ─────────────────────────────────────

def _enhanced_ocr(image: 'Image.Image') -> dict[str, Any]:
    """
    Use pytesseract image_to_data for per-word confidence scoring.
    Flags low-confidence regions and duplicate content.
    """
    if not TESSERACT_AVAILABLE:
        return {
            'text': '',
            'text_confidence': 0.0,
            'ocr_anomaly_score': 0.0,
            'findings': [],
        }

    try:
        data = pytesseract.image_to_data(image, output_type=TessOutput.DICT)
    except Exception as exc:
        logger.debug('OCR failed: %s', exc)
        return {'text': '', 'text_confidence': 0.0, 'ocr_anomaly_score': 0.0, 'findings': []}

    words = [w for w, c in zip(data['text'], data['conf'])
             if str(w).strip() and int(c) > -1]
    confs = [int(c) for c in data['conf'] if int(c) > -1]

    if not words:
        return {'text': '', 'text_confidence': 0.0, 'ocr_anomaly_score': 0.0, 'findings': []}

    full_text = ' '.join(words)
    valid_confs = [c for c in confs if c >= 0]
    mean_conf = sum(valid_confs) / len(valid_confs) if valid_confs else 0.0
    text_confidence = min(mean_conf, 100.0)

    score = 0.0
    findings: list[str] = []

    # Low-confidence word ratio
    low_conf_words = sum(1 for c in valid_confs if 0 <= c < 40)
    low_conf_ratio = low_conf_words / len(valid_confs) if valid_confs else 0.0

    if low_conf_ratio > 0.4:
        score += 15
        findings.append(
            f'High low-confidence OCR ratio ({low_conf_ratio:.0%}) – '
            f'text may be pasted/overlaid.'
        )
    elif low_conf_ratio > 0.2:
        score += 7

    # Duplicate paragraph detection
    lines = [line.strip() for line in full_text.splitlines() if line.strip() and len(line.strip()) > 15]
    if len(lines) != len(set(lines)):
        dupes = len(lines) - len(set(lines))
        score += min(dupes * 3, 10)
        findings.append(f'{dupes} duplicate text blocks detected – possible copy-paste tampering.')

    # Placeholder text
    if 'lorem ipsum' in full_text.lower():
        score += 15
        findings.append('Placeholder text "lorem ipsum" detected.')

    # Excessive uppercase ratio (template tampering)
    alpha_chars = [c for c in full_text if c.isalpha()]
    if alpha_chars:
        caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        if caps_ratio > 0.5 and len(words) > 10:
            score += 5
            findings.append(f'Unusually high uppercase ratio ({caps_ratio:.0%}).')

    # Very little content extracted (suspicious for a document)
    if len(words) < 5 and len(full_text) > 0:
        score += 8
        findings.append('Very little text extracted from document despite apparent content.')

    return {
        'text': full_text,
        'text_confidence': round(text_confidence, 1),
        'ocr_anomaly_score': min(score, 25.0),
        'findings': findings,
        'word_count': len(words),
        'low_conf_ratio': round(low_conf_ratio, 3),
    }


# ─── Technique 4: Semantic Consistency (retained + improved) ──────────────────

def _semantic_consistency(text: str) -> tuple[float, list[str]]:
    """Retained heuristic for textual anomalies (placeholder text, numeric outliers)."""
    findings: list[str] = []
    score = 0.0

    if not text:
        return score, findings

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 3:
        findings.append('Document contains very little textual content.')
        score += 10

    if 'lorem ipsum' not in text.lower():  # already flagged above if present
        uppercase_ratio = sum(1 for ch in text if ch.isupper()) / max(len(text), 1)
        if uppercase_ratio > 0.4:
            findings.append('High proportion of uppercase characters.')
            score += 5

    numeric_values = [
        float(part) for part in text.replace(',', '').split()
        if part.replace('.', '', 1).isdigit()
    ]
    if len(numeric_values) > 3:
        try:
            median_val = statistics.median(numeric_values)
            if median_val > 0:
                outliers = [v for v in numeric_values if abs(v - median_val) > median_val * 0.5]
                if outliers:
                    findings.append('Inconsistent numeric values (potential tampering).')
                    score += 10
        except statistics.StatisticsError:
            pass

    return min(score, 100.0), findings


# ─── Risk Level Mapping ────────────────────────────────────────────────────────

def determine_risk_level(score: float) -> RiskLevel:
    if score >= 70:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ─── Public API ───────────────────────────────────────────────────────────────

def analyse_document(file: UploadedFile, run_ocr: bool = True, run_semantic: bool = True) -> dict[str, Any]:
    mime, extension = _detect_type(file)
    sha256 = _compute_sha256(file)
    file_size = file.size

    findings: dict[str, Any] = {}
    ela_score = 0.0
    exif_score = 0.0
    ocr_anomaly_score = 0.0
    semantic_score = 0.0
    text_confidence = 0.0
    textual_content = ''
    hotspot_count = 0
    ela_details: dict[str, Any] = {}
    exif_details: dict[str, Any] = {}
    gemini_score = 0.0
    img_bytes_for_gemini: bytes | None = None
    gemini_mime: str = mime or 'image/jpeg'

    is_image = extension in {'jpg', 'jpeg', 'png'}
    cnn_score = 0.0
    cnn_available = False

    if is_image and PIL_AVAILABLE:
        try:
            image = Image.open(file)
            image.load()   # force decode before seek(0)

            # ── Technique 1: Multi-pass ELA ──────────────────────────────────
            ela_result = _compute_multipass_ela(image)
            ela_score = ela_result['ela_score']
            hotspot_count = ela_result.get('hotspot_count', 0)
            ela_details = ela_result
            findings['ela'] = (
                f'ELA score: {ela_score:.1f} | Hotspots: {hotspot_count} / 16 blocks'
            )

            # ── Technique 1b: CNN Forgery Detection (TensorFlow/Keras) ───────
            cnn_result = _cnn_forgery_score(image)
            cnn_score = cnn_result.get('score', 0.0)
            cnn_available = cnn_result.get('available', False)

            # ── Technique 2: EXIF analysis ───────────────────────────────────
            exif_result = _analyse_exif(image)
            exif_score = exif_result['score']
            exif_details = exif_result
            if exif_result['findings']:
                findings['exif'] = exif_result['findings']

            # ── Technique 3: Enhanced OCR ────────────────────────────────────
            if run_ocr:
                ocr_result = _enhanced_ocr(image)
                textual_content = ocr_result.get('text', '')
                text_confidence = ocr_result.get('text_confidence', 0.0)
                ocr_anomaly_score = ocr_result.get('ocr_anomaly_score', 0.0)
                if ocr_result.get('findings'):
                    findings['ocr'] = ocr_result['findings']
                if textual_content:
                    findings['ocr_summary'] = (
                        f'OCR extracted {ocr_result.get("word_count", 0)} words '
                        f'(mean confidence {text_confidence:.1f}%).'
                    )

            # Capture image bytes for Gemini
            buf = io.BytesIO()
            image.convert('RGB').save(buf, 'JPEG', quality=85)
            img_bytes_for_gemini = buf.getvalue()

        except Exception as exc:
            findings['error'] = f'Image forensics failed: {exc}'
        finally:
            file.seek(0)

    # ── PDF / DOCX text extraction (non-image documents) ────────────────────
    is_pdf = extension == 'pdf' or (mime and 'pdf' in mime)
    is_docx = extension in ('docx',) or (mime and 'wordprocessingml' in (mime or ''))
    is_doc = extension in ('doc',) or (mime and 'msword' in (mime or ''))

    if not is_image:
        if is_pdf:
            pdf_result = _extract_pdf_text(file)
            if pdf_result['available'] and pdf_result['text']:
                textual_content = pdf_result['text']
                text_confidence = 85.0
                if pdf_result['findings']:
                    findings['pdf_analysis'] = pdf_result['findings']
                if pdf_result.get('pdf_metadata'):
                    exif_details = {'findings': pdf_result['findings'], 'exif': pdf_result['pdf_metadata']}
                findings['extraction'] = f"Extracted {pdf_result['page_count']} pages via PyMuPDF."

        elif is_docx:
            docx_result = _extract_docx_text(file)
            if docx_result['available'] and docx_result['text']:
                textual_content = docx_result['text']
                text_confidence = 90.0
                if docx_result['findings']:
                    findings['docx_analysis'] = docx_result['findings']
                if docx_result.get('docx_metadata'):
                    exif_details = {'findings': docx_result['findings'], 'exif': docx_result['docx_metadata']}
                findings['extraction'] = 'Text extracted via python-docx.'

        elif is_doc and PYMUPDF_AVAILABLE:
            try:
                file.seek(0)
                doc_bytes = file.read()
                file.seek(0)
                doc = pymupdf.open(stream=doc_bytes, filetype='doc')
                pages_text = [page.get_text() for page in doc]
                textual_content = '\n'.join(pages_text)
                text_confidence = 75.0
                doc.close()
                findings['extraction'] = 'Text extracted from .doc via PyMuPDF (limited support).'
            except Exception as exc:
                findings['extraction'] = f'.doc extraction failed: {exc}'

    # ── Technique 4 (semantic consistency, for all file types with text) ──────
    if run_semantic and textual_content:
        semantic_score, semantic_findings = _semantic_consistency(textual_content)
        if semantic_findings:
            findings['semantic'] = semantic_findings

    # ── File-level heuristics ─────────────────────────────────────────────────
    if file_size > 5 * 1024 * 1024:
        findings['size'] = 'File larger than 5 MB – manual review recommended.'

    if mime and mime not in {
        'application/pdf', 'image/jpeg', 'image/png',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    }:
        findings['mime'] = f'Uncommon MIME type: {mime}'

    # ── Gemini Vision (optional, images only) ─────────────────────────────────
    if is_image and img_bytes_for_gemini:
        client = get_gemini_client()
        if client:
            try:
                prompt = (
                    'You are a forensic document examiner. Analyze this image for signs of '
                    'digital forgery or tampering. Return ONLY valid JSON with keys:\n'
                    '"tamper_score": integer 0-100 (0=authentic, 100=definitely forged),\n'
                    '"suspicious_areas": array of short strings describing suspicious regions,\n'
                    '"confidence": one of "low", "medium", "high",\n'
                    '"artifacts_found": boolean.\n'
                    'Look for: compression inconsistencies, clone stamps, splicing boundaries, '
                    'lighting mismatches, font inconsistencies, metadata artefacts.'
                )
                gemini_result = call_gemini_vision_json(
                    client, img_bytes_for_gemini, 'image/jpeg', prompt
                )
                gemini_score = float(gemini_result.get('tamper_score', 0))
                sus_areas = gemini_result.get('suspicious_areas', [])
                if sus_areas:
                    findings['gemini_vision'] = sus_areas
            except Exception as exc:
                logger.warning('Gemini Vision failed: %s', exc)

    # ── Final score combination ───────────────────────────────────────────────
    # Application docs get a small baseline risk (no image forensics)
    app_baseline = 10 if (mime and mime.startswith('application/')) else 0

    # CNN-enhanced ELA: blend rule-based ELA with CNN prediction
    effective_ela = (0.50 * ela_score + 0.50 * cnn_score) if cnn_available else ela_score

    base_score = (
        0.40 * effective_ela +
        0.25 * exif_score +
        0.20 * ocr_anomaly_score +
        0.15 * semantic_score +
        app_baseline
    )

    if gemini_score > 0:
        final_score = 0.70 * base_score + 0.30 * gemini_score
    else:
        final_score = base_score

    final_score = min(max(final_score, 0.0), 100.0)
    risk_level = determine_risk_level(final_score)

    verdict = (
        DocumentAnalysis.Verdict.FORGED
        if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
        else DocumentAnalysis.Verdict.SUSPICIOUS
        if risk_level == RiskLevel.MEDIUM
        else DocumentAnalysis.Verdict.AUTHENTIC
    )

    # Build Gemini findings for template
    gemini_findings_meta: dict[str, Any] = {}
    if findings.get('gemini_vision'):
        gemini_findings_meta = {
            'suspicious_areas': findings['gemini_vision'],
            'confidence': 'medium',
        }

    return {
        'file_name': file.name,
        'file_type': mime or extension or file.content_type,
        'file_size': file_size,
        'sha256': sha256,
        'ela_score': round(ela_score, 2),
        'text_confidence': round(text_confidence, 2),
        'semantic_score': round(semantic_score, 2),
        'verdict': verdict,
        'risk_level': risk_level,
        'findings': findings,
        'highlighted_regions': ela_details.get('regional_map', []),
        'ocr_text': textual_content,
        'metadata': {
            'mime': mime,
            'extension': extension,
            'exif': exif_details.get('exif', {}),
            'hotspot_count': hotspot_count,
            'exif_findings': exif_details.get('findings', []),
            'gemini_findings': gemini_findings_meta,
            'ela_details': {
                k: v for k, v in ela_details.items() if k != 'regional_map'
            },
            'scores': {
                'ela': round(ela_score, 1),
                'cnn': round(cnn_score, 1),
                'exif': round(exif_score, 1),
                'ocr_anomaly': round(ocr_anomaly_score, 1),
                'semantic': round(semantic_score, 1),
                'gemini': round(gemini_score, 1),
                'final': round(final_score, 1),
            },
            'detection_layers': {
                'multi_pass_ela': bool(ela_score > 0),
                'cnn_forgery': cnn_available,
                'exif_analysis': bool(exif_details),
                'ocr_confidence': TESSERACT_AVAILABLE,
                'semantic_consistency': bool(run_semantic),
                'gemini_vision': bool(gemini_score > 0),
            },
        },
    }

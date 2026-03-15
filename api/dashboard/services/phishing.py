"""
phishing.py — Phishing & Scam Detection Service

Three-layer detection engine:
  1. URL Feature Engineering  – 18 structural URL features via tldextract
  2. NLTK NLP Analysis        – VADER sentiment, keyword density, structural signals
  3. Gemini AI Layer          – Optional LLM analysis (requires GEMINI_API_KEY)

Final risk score = weighted combination (layer weights shift when Gemini available).
Header SPF/DKIM validation is retained from the original and added on top.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from ..models import PhishingScan, RiskLevel
from .ml_utils import (
    call_gemini_json, ensure_nltk_data, get_domain_age_days, get_gemini_client,
    get_transformer_pipeline, load_model, save_model,
)

# ─── URL Feature Tables ───────────────────────────────────────────────────────

# TLD risk scores (0 = safe, higher = riskier)
TLD_RISK: dict[str, int] = {
    '.tk': 25, '.ml': 25, '.ga': 25, '.cf': 25, '.gq': 25,
    '.zip': 20, '.ru': 15, '.xyz': 15, '.top': 15, '.pw': 15,
    '.cc': 10, '.ws': 10, '.biz': 5, '.info': 5,
    # Safe TLDs
    '.com': 0, '.org': 0, '.net': 0, '.edu': 0, '.gov': 0,
    '.io': 0, '.co': 0, '.uk': 0, '.in': 0, '.de': 0,
}

URL_SHORTENERS = {
    'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'su.pr', 'dlvr.it', 'short.ly',
    'ht.ly', 'j.mp', 'tiny.cc', 'ur.ly', 'tr.im', 'cli.gs',
    'budurl.com', 'prettylinkpro.com', 'shrinkonce.com', 'tinycc.com',
    'short.ie', 'snurl.com', 'x.co', 'rb.gy',
}

# Keywords that should NOT appear in legitimate URLs
URL_SUSPICIOUS_KEYWORDS = {
    'verify', 'secure', 'login', 'update', 'account', 'banking',
    'paypal', 'signin', 'webscr', 'ebayisapi', 'validate',
    'confirm', 'password', 'credential', 'auth',
}

# Phishing content keywords with weights
PHISHING_KEYWORDS: dict[str, int] = {
    # High urgency / threat
    'urgent': 8, 'immediately': 8, 'action required': 8, 'verify now': 8,
    'account suspended': 10, 'account locked': 10, 'account terminated': 10,
    'limited time': 6, 'expires today': 8, 'click here': 5,
    # Financial lures
    'bitcoin': 7, 'crypto': 6, 'wire transfer': 8, 'gift card': 7,
    'prize': 6, 'winner': 6, 'lottery': 7, 'inheritance': 8,
    # Credential harvesting
    'confirm your password': 10, 'verify your account': 9,
    'update your information': 7, 'validate your email': 8,
    'unusual activity': 7, 'suspicious login': 8,
    # Social engineering
    'dear customer': 5, 'dear user': 5, 'valued member': 5,
    'we have noticed': 6, 'we detected': 6,
    # Common keywords (lower weight)
    'password': 4, 'login': 3, 'account': 3, 'security': 3,
    'bank': 4, 'invoice': 4, 'suspended': 6,
}

# Known brand names used in phishing impersonation
IMPERSONATED_BRANDS = {
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
    'facebook', 'instagram', 'twitter', 'hdfc', 'sbi', 'icici',
    'wellsfargo', 'chase', 'citibank', 'bankofamerica', 'usps',
    'fedex', 'dhl', 'irs', 'walmart', 'ebay',
}


# ─── Layer 1: URL Feature Engineering ────────────────────────────────────────

def _extract_url_features(url: str, domain_age_days: int | None) -> dict[str, Any]:
    """
    Extract 18 structural features from a URL and compute a URL risk score.
    Uses tldextract for robust domain parsing.
    """
    try:
        import tldextract
        ext = tldextract.extract(url)
        registered_domain = ext.registered_domain.lower()
        subdomain = ext.subdomain.lower()
        suffix = f'.{ext.suffix}' if ext.suffix else ''
    except Exception:
        ext = None
        parsed = urlparse(url)
        registered_domain = parsed.netloc.lower()
        subdomain = ''
        suffix = ''

    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path or ''
    query = parsed.query or ''
    fragment = parsed.fragment or ''

    features: dict[str, Any] = {}
    score = 0.0
    findings: list[str] = []

    # F1: URL total length
    features['url_length'] = len(url)
    if len(url) > 100:
        score += min((len(url) - 100) / 10, 10)
        findings.append(f'Abnormally long URL ({len(url)} chars).')

    # F2: Domain length
    features['domain_length'] = len(registered_domain)
    if len(registered_domain) > 30:
        score += 5
        findings.append('Long domain name may indicate obfuscation.')

    # F3: Subdomain depth
    subdomain_parts = [p for p in subdomain.split('.') if p]
    features['subdomain_depth'] = len(subdomain_parts)
    if len(subdomain_parts) >= 3:
        score += 10
        findings.append(f'Deep subdomain nesting ({len(subdomain_parts)} levels).')
    elif len(subdomain_parts) == 2:
        score += 5

    # F4: TLD risk
    tld_score = TLD_RISK.get(suffix, 0)
    features['tld_risk'] = tld_score
    if tld_score > 0:
        score += tld_score
        findings.append(f'Suspicious TLD "{suffix}" often abused in phishing.')

    # F5: URL shortener
    features['is_shortener'] = netloc in URL_SHORTENERS
    if features['is_shortener']:
        score += 15
        findings.append('URL shortener masks real destination.')

    # F6: IP address as host
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features['has_ip_host'] = bool(re.match(ip_pattern, netloc.split(':')[0]))
    if features['has_ip_host']:
        score += 30
        findings.append('Domain is a raw IP address – bypasses brand checks.')

    # F7: @ symbol in URL
    features['has_at_symbol'] = '@' in url
    if features['has_at_symbol']:
        score += 15
        findings.append('@ symbol in URL masks real destination domain.')

    # F8: Double slash redirect
    features['has_double_slash'] = '//' in path
    if features['has_double_slash']:
        score += 10
        findings.append('Double-slash redirect in URL path.')

    # F9: Hex encoding
    features['has_hex_encoding'] = bool(re.search(r'%[0-9a-fA-F]{2}', url))
    if features['has_hex_encoding']:
        score += 8
        findings.append('URL-encoded characters may obfuscate content.')

    # F10: Digit count in domain
    digit_count = sum(c.isdigit() for c in registered_domain)
    features['domain_digit_count'] = digit_count
    if digit_count >= 4:
        score += 8
        findings.append(f'High digit count in domain ({digit_count}) – unusual.')

    # F11: Hyphen count in domain
    hyphen_count = registered_domain.count('-')
    features['domain_hyphen_count'] = hyphen_count
    if hyphen_count >= 3:
        score += 8
        findings.append(f'Multiple hyphens in domain ({hyphen_count}).')

    # F12: Special characters in path
    special_chars = len(re.findall(r'[!?#&=%@]', path + query))
    features['path_special_chars'] = special_chars
    if special_chars > 5:
        score += 5

    # F13: Unicode homoglyphs
    features['has_unicode'] = any(ord(c) > 127 for c in url)
    if features['has_unicode']:
        score += 25
        findings.append('Unicode characters in URL (possible homoglyph attack).')

    # F14: Suspicious keywords in URL
    url_lower = url.lower()
    kw_hits = [kw for kw in URL_SUSPICIOUS_KEYWORDS if kw in url_lower]
    features['url_keyword_hits'] = len(kw_hits)
    if kw_hits:
        score += len(kw_hits) * 5
        findings.append(f'Suspicious keywords in URL: {", ".join(kw_hits[:3])}.')

    # F15: Brand impersonation in domain (not the brand itself)
    brand_hits = [b for b in IMPERSONATED_BRANDS if b in registered_domain
                  and registered_domain != b + '.com']
    features['brand_in_domain'] = len(brand_hits)
    if brand_hits:
        score += 20
        findings.append(f'Brand name "{brand_hits[0]}" in domain – possible impersonation.')

    # F16: HTTP (not HTTPS)
    features['is_http'] = url.lower().startswith('http://')
    if features['is_http']:
        score += 8
        findings.append('Uses HTTP instead of HTTPS.')

    # F17: Domain age
    features['domain_age_days'] = domain_age_days
    if domain_age_days is not None and domain_age_days < 30:
        score += 20
        findings.append(f'Domain registered {domain_age_days} days ago – very new.')
    elif domain_age_days is not None and domain_age_days < 90:
        score += 10
        findings.append(f'Domain is only {domain_age_days} days old.')

    # F18: Path/query length
    features['path_length'] = len(path)
    features['query_length'] = len(query)
    if len(query) > 200:
        score += 5
        findings.append('Unusually long query string.')

    return {
        'score': min(score, 100.0),
        'features': features,
        'findings': findings,
        'domain': registered_domain,
    }


# ─── Layer 2: NLTK NLP Analysis ──────────────────────────────────────────────

def _nlp_content_score(content: str) -> dict[str, Any]:
    """
    Analyse message/email content using NLTK for phishing signals.
    Returns a score 0–50 and list of findings.
    """
    ensure_nltk_data()
    score = 0.0
    findings: list[str] = []
    content_lower = content.lower()

    # ── VADER Sentiment ──────────────────────────────────────────────────────
    try:
        from nltk.sentiment.vader import SentimentIntensityAnalyzer
        sia = SentimentIntensityAnalyzer()
        sentiment = sia.polarity_scores(content)
        # Highly negative or alarmist tone typical of phishing
        if sentiment['compound'] < -0.4:
            score += 12
            findings.append(f'Strongly negative/alarmist tone detected (VADER score: {sentiment["compound"]:.2f}).')
        elif sentiment['compound'] < -0.2:
            score += 6
    except Exception:
        pass

    # ── Phishing Keyword Density ─────────────────────────────────────────────
    try:
        from nltk.tokenize import word_tokenize
        from nltk.corpus import stopwords
        tokens = word_tokenize(content_lower)
        stop_words = set(stopwords.words('english'))
        filtered_tokens = [t for t in tokens if t.isalpha() and t not in stop_words]
        total_tokens = max(len(filtered_tokens), 1)

        keyword_score = 0.0
        matched_keywords: list[str] = []
        for phrase, weight in PHISHING_KEYWORDS.items():
            if phrase in content_lower:
                keyword_score += weight
                matched_keywords.append(phrase)

        # Normalize by document length (penalise keyword stuffing less in short texts)
        density_score = min(keyword_score * 1.5, 30)
        score += density_score
        if matched_keywords:
            findings.append(
                f'Phishing keywords detected: {", ".join(matched_keywords[:5])}.'
                + (f' (+{len(matched_keywords) - 5} more)' if len(matched_keywords) > 5 else '')
            )
    except Exception:
        # Fallback: simple keyword count without NLTK
        for phrase, weight in PHISHING_KEYWORDS.items():
            if phrase in content_lower:
                score += weight * 0.5

    # ── Structural Signals ───────────────────────────────────────────────────
    # All-caps ratio (shouting = pressure tactic)
    alpha_chars = [c for c in content if c.isalpha()]
    if alpha_chars:
        caps_ratio = sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars)
        if caps_ratio > 0.4:
            score += 8
            findings.append(f'High all-caps ratio ({caps_ratio:.0%}) – pressure tactic.')

    # Excessive punctuation
    excl_count = content.count('!')
    if excl_count >= 3:
        score += min(excl_count, 6)
        findings.append(f'{excl_count} exclamation marks detected – urgency pressure.')

    # HTTP link in content (downgrade)
    if re.search(r'http://[^\s]{5,}', content_lower):
        score += 10
        findings.append('Non-HTTPS links in message body.')

    # @ masking in URLs
    if re.search(r'https?://[^\s]+@[^\s]+', content_lower):
        score += 15
        findings.append('URL contains @ symbol masking real destination.')

    # Fake OTP/verification codes
    if re.search(r'\b\d{6}\b', content):
        score += 5
        findings.append('6-digit code detected – potential fake verification prompt.')

    # Brand impersonation in content
    brand_hits_content = [b for b in IMPERSONATED_BRANDS if b in content_lower]
    if brand_hits_content:
        combined_with_urgency = any(
            urg in content_lower for urg in ('urgent', 'immediately', 'suspended', 'locked', 'verify')
        )
        if combined_with_urgency:
            score += 15
            findings.append(
                f'Brand impersonation + urgency: "{brand_hits_content[0]}" '
                f'+ urgency language detected.'
            )

    return {
        'score': min(score, 80.0),
        'findings': findings,
    }


# ─── Layer 2b: Random Forest URL Classifier (PPT: PhishGuard) ────────────────

# Feature keys used by the RF model (must match training order)
_RF_FEATURE_KEYS = [
    'url_length', 'domain_length', 'subdomain_depth', 'tld_risk',
    'is_shortener', 'has_ip_host', 'has_at_symbol', 'has_double_slash',
    'has_hex_encoding', 'domain_digit_count', 'domain_hyphen_count',
    'path_special_chars', 'has_unicode', 'url_keyword_hits',
    'brand_in_domain', 'is_http', 'path_length', 'query_length',
]


def _ensure_rf_model():
    """
    Load or train the Random Forest URL classifier.

    On first run, trains on synthetic phishing/benign URL feature vectors.
    Returns (model, scaler) tuple or (None, None).
    """
    import logging as _log

    payload = load_model('phishing_url_rf')
    if payload is not None:
        return payload  # (model, scaler)

    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler

        rng = np.random.RandomState(42)

        # ── Curated phishing URL features (label=1) ──────────────────────────
        # Distributions based on documented phishing URL characteristics:
        # longer URLs, deeper subdomains, risky TLDs, brand impersonation
        n_phish = 400
        phish = np.column_stack([
            rng.normal(130, 35, n_phish).clip(40, 300).astype(int),   # url_length: phishing avg ~130
            rng.normal(25, 8, n_phish).clip(8, 60).astype(int),      # domain_length: longer domains
            rng.choice([0, 1, 2, 3, 4], n_phish, p=[0.10, 0.20, 0.35, 0.25, 0.10]),  # subdomain_depth
            rng.choice([0, 5, 10, 15, 20, 25], n_phish, p=[0.10, 0.10, 0.20, 0.25, 0.20, 0.15]),  # tld_risk
            rng.choice([0, 1], n_phish, p=[0.75, 0.25]),  # is_shortener: 25%
            rng.choice([0, 1], n_phish, p=[0.65, 0.35]),  # has_ip_host: 35%
            rng.choice([0, 1], n_phish, p=[0.82, 0.18]),  # has_at_symbol: 18%
            rng.choice([0, 1], n_phish, p=[0.72, 0.28]),  # has_double_slash: 28%
            rng.choice([0, 1], n_phish, p=[0.55, 0.45]),  # has_hex_encoding: 45%
            rng.normal(4.5, 2.0, n_phish).clip(0, 12).astype(int),   # domain_digit_count
            rng.normal(2.5, 1.5, n_phish).clip(0, 8).astype(int),    # domain_hyphen_count
            rng.normal(6, 3, n_phish).clip(0, 20).astype(int),       # path_special_chars
            rng.choice([0, 1], n_phish, p=[0.88, 0.12]),  # has_unicode: 12% homoglyphs
            rng.choice([0, 1, 2, 3, 4], n_phish, p=[0.15, 0.30, 0.30, 0.15, 0.10]),  # url_keyword_hits
            rng.choice([0, 1], n_phish, p=[0.55, 0.45]),  # brand_in_domain: 45%
            rng.choice([0, 1], n_phish, p=[0.40, 0.60]),  # is_http: 60% HTTP
            rng.normal(35, 15, n_phish).clip(5, 100).astype(int),    # path_length
            rng.normal(80, 50, n_phish).clip(0, 300).astype(int),    # query_length: long
        ])

        # ── Curated benign URL features (label=0) ────────────────────────────
        # Legitimate URLs: shorter, simple structure, safe TLDs, HTTPS
        n_benign = 400
        benign = np.column_stack([
            rng.normal(45, 15, n_benign).clip(15, 100).astype(int),  # url_length: avg ~45
            rng.normal(12, 4, n_benign).clip(4, 25).astype(int),     # domain_length: shorter
            rng.choice([0, 1, 2], n_benign, p=[0.60, 0.35, 0.05]),   # subdomain_depth: 0-1
            rng.choice([0, 5], n_benign, p=[0.92, 0.08]),             # tld_risk: mostly 0
            np.zeros(n_benign, dtype=int),                             # is_shortener: never
            np.zeros(n_benign, dtype=int),                             # has_ip_host: never
            np.zeros(n_benign, dtype=int),                             # has_at_symbol: never
            rng.choice([0, 1], n_benign, p=[0.97, 0.03]),             # has_double_slash: rare
            rng.choice([0, 1], n_benign, p=[0.92, 0.08]),             # has_hex_encoding: rare
            rng.normal(1.0, 1.0, n_benign).clip(0, 4).astype(int),   # domain_digit_count
            rng.choice([0, 1], n_benign, p=[0.85, 0.15]),             # domain_hyphen_count: 0-1
            rng.normal(1.5, 1.0, n_benign).clip(0, 5).astype(int),   # path_special_chars
            np.zeros(n_benign, dtype=int),                             # has_unicode: never
            np.zeros(n_benign, dtype=int),                             # url_keyword_hits: none
            np.zeros(n_benign, dtype=int),                             # brand_in_domain: no
            rng.choice([0, 1], n_benign, p=[0.92, 0.08]),             # is_http: 8% HTTP
            rng.normal(12, 6, n_benign).clip(1, 40).astype(int),     # path_length: short
            rng.normal(10, 8, n_benign).clip(0, 40).astype(int),     # query_length: short
        ])

        X = np.vstack([phish, benign]).astype(float)
        y = np.array([1] * n_phish + [0] * n_benign)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = RandomForestClassifier(
            n_estimators=100, max_depth=12, random_state=42, n_jobs=-1,
        )
        model.fit(X_scaled, y)
        save_model('phishing_url_rf', (model, scaler))
        return model, scaler

    except Exception as exc:
        _log.getLogger(__name__).warning('RF URL model training failed: %s', exc)
        return None, None


def _rf_url_score(features: dict[str, Any]) -> float:
    """Run the Random Forest classifier on extracted URL features. Returns score 0-100."""
    model, scaler = _ensure_rf_model()
    if model is None:
        return 0.0

    try:
        import numpy as np
        vec = np.array([[
            float(features.get(k, 0) or 0) for k in _RF_FEATURE_KEYS
        ]])
        vec_scaled = scaler.transform(vec)
        proba = model.predict_proba(vec_scaled)[0]
        # proba[1] = probability of phishing
        return round(float(proba[1]) * 100, 1)
    except Exception:
        return 0.0


# ─── Layer 2c: Transformer NLP (PPT: Deep Learning Transformer) ─────────────

_TRANSFORMER_MODEL = 'distilbert-base-uncased-finetuned-sst-2-english'


def _transformer_nlp_score(text: str) -> dict[str, Any]:
    """
    Use a HuggingFace DistilBERT model to classify text sentiment.

    Phishing emails typically carry strong negative/urgent sentiment.
    Maps NEGATIVE sentiment to higher phishing risk.
    Returns score 0-100 and label.
    """
    if not text or len(text.strip()) < 20:
        return {'score': 0.0, 'label': '', 'available': False}

    try:
        pipe = get_transformer_pipeline('text-classification', _TRANSFORMER_MODEL)
        if pipe is None:
            return {'score': 0.0, 'label': '', 'available': False}

        # Truncate to model's max tokens (~512 tokens ≈ first 1500 chars)
        result = pipe(text[:1500], truncation=True)[0]
        label = result['label']       # POSITIVE or NEGATIVE
        confidence = result['score']   # 0.0 - 1.0

        # Map: NEGATIVE with high confidence → high phishing score
        if label == 'NEGATIVE':
            score = confidence * 80  # up to 80
        else:
            score = (1 - confidence) * 30  # low phishing score for positive text

        return {
            'score': round(score, 1),
            'label': label,
            'confidence': round(confidence, 3),
            'available': True,
        }
    except Exception:
        return {'score': 0.0, 'label': '', 'available': False}


# ─── Header Analysis (retained from original) ────────────────────────────────

def _parse_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    header_keys = {k.lower(): v for k, v in headers.items()}
    spf = header_keys.get('received-spf', '')
    dkim = header_keys.get('dkim-signature', '')
    dmarc = header_keys.get('authentication-results', '')
    return {
        'spf_pass': 'pass' in spf.lower(),
        'dkim_present': bool(dkim),
        'dmarc_pass': 'dmarc=pass' in dmarc.lower(),
        'raw': {k.title(): v for k, v in headers.items()},
    }


def _score_headers(headers: Mapping[str, Any]) -> dict[str, Any]:
    parsed = _parse_headers(headers)
    risk = 0.0
    findings: list[str] = []

    if not parsed['spf_pass']:
        findings.append('SPF validation failed or missing.')
        risk += 15
    if not parsed['dkim_present']:
        findings.append('DKIM signature absent.')
        risk += 10
    if not parsed['dmarc_pass']:
        findings.append('DMARC policy not passed.')
        risk += 8

    return {'risk': risk, 'findings': findings, 'details': parsed['raw']}


# ─── Layer 3: Gemini AI (optional) ───────────────────────────────────────────

def _gemini_phishing_score(content_snippet: str, url: str) -> dict[str, Any]:
    """
    Ask Gemini to evaluate phishing probability. Returns score 0–100 and indicators.
    Returns zeroed result if API key absent or call fails.
    """
    client = get_gemini_client()
    if not client:
        return {'score': 0.0, 'indicators': [], 'available': False}

    subject = url if url else content_snippet[:80]
    prompt = (
        'You are a cybersecurity expert specializing in phishing detection. '
        'Analyze the following content and return ONLY valid JSON with these keys:\n'
        '"phishing_probability": integer 0-100,\n'
        '"indicators": array of short strings describing phishing signals found,\n'
        '"confidence": one of "low", "medium", "high".\n\n'
        f'URL: {url or "N/A"}\n\n'
        f'Content (first 2000 chars):\n{content_snippet[:2000]}'
    )

    result = call_gemini_json(client, prompt)
    return {
        'score': float(result.get('phishing_probability', 0)),
        'indicators': result.get('indicators', []),
        'confidence': result.get('confidence', 'low'),
        'available': True,
    }


# ─── Risk Level Mapping ───────────────────────────────────────────────────────

def calculate_risk_level(score: float) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 55:
        return RiskLevel.HIGH
    if score >= 35:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ─── Public API ───────────────────────────────────────────────────────────────

def analyse_scan(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Analyse a phishing submission through the 3-layer engine.

    payload keys: input_type, target_url, raw_content, headers, domain_age_days
    """
    input_type: str = payload.get('input_type', PhishingScan.InputType.URL)
    target_url: str = payload.get('target_url', '')
    raw_content: str = payload.get('raw_content', '')
    headers: Mapping[str, Any] = payload.get('headers') or {}
    domain_age_days: int | None = payload.get('domain_age_days')

    # If domain_age_days not provided, attempt WHOIS lookup
    if domain_age_days is None and target_url:
        try:
            import tldextract
            ext = tldextract.extract(target_url)
            if ext.registered_domain:
                domain_age_days = get_domain_age_days(ext.registered_domain)
        except Exception:
            pass

    url_result: dict[str, Any] | None = None
    content_result: dict[str, Any] | None = None
    header_result: dict[str, Any] | None = None
    gemini_result: dict[str, Any] | None = None

    # ── Layer 1: URL features (hand-crafted 18 features) ─────────────────────
    url_score = 0.0
    rf_score = 0.0
    if target_url:
        url_result = _extract_url_features(target_url, domain_age_days)
        url_score = url_result['score']
        # ── Layer 1b: Random Forest on same features ──────────────────────
        rf_score = _rf_url_score(url_result['features'])

    # ── Layer 2: NLP content analysis (NLTK VADER + keywords) ─────────────
    nlp_score = 0.0
    transformer_result: dict[str, Any] | None = None
    transformer_score = 0.0
    if input_type in {PhishingScan.InputType.MESSAGE, PhishingScan.InputType.HEADERS}:
        if raw_content:
            content_result = _nlp_content_score(raw_content)
            nlp_score = content_result['score']
    elif raw_content:
        content_result = _nlp_content_score(raw_content)
        nlp_score = content_result['score']

    # ── Layer 2b: Transformer NLP (DistilBERT) ────────────────────────────
    analysis_text = raw_content or target_url
    if analysis_text and len(analysis_text) >= 20:
        transformer_result = _transformer_nlp_score(analysis_text)
        transformer_score = transformer_result['score']

    # ── Header analysis ──────────────────────────────────────────────────────
    header_risk = 0.0
    if headers:
        header_result = _score_headers(headers)
        header_risk = header_result['risk']

    # ── Layer 3: Gemini ──────────────────────────────────────────────────────
    gemini_score = 0.0
    analysis_content = raw_content or target_url
    if analysis_content:
        gemini_result = _gemini_phishing_score(analysis_content, target_url)
        gemini_score = gemini_result['score']

    # ── Weighted final score ─────────────────────────────────────────────────
    # Now includes RF and Transformer contributions
    gemini_available = gemini_result is not None and gemini_result.get('available', False)
    transformer_available = transformer_result is not None and transformer_result.get('available', False)

    # Base: rule-based url + NLTK NLP
    base_url = 0.50 * url_score + 0.50 * rf_score if rf_score > 0 else url_score
    base_nlp = 0.50 * nlp_score + 0.50 * transformer_score if transformer_available else nlp_score

    if gemini_available:
        base_score = 0.40 * base_url + 0.35 * base_nlp
        risk_score = 0.75 * base_score + 0.25 * gemini_score
    else:
        risk_score = 0.50 * base_url + 0.50 * base_nlp

    risk_score += header_risk * 0.5
    risk_score = min(max(risk_score, 0.0), 100.0)

    risk_level = calculate_risk_level(risk_score)
    reputation = max(0.0, 100.0 - risk_score)

    # ── Recommendations ──────────────────────────────────────────────────────
    recommendations: list[str] = []
    if risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}:
        recommendations.append('Isolate the message and warn the recipient immediately.')
    if input_type == PhishingScan.InputType.URL and risk_level != RiskLevel.LOW:
        recommendations.append('Add the domain to the block/watch list at your gateway.')
    if header_result and not header_result['findings']:
        recommendations.append('Email headers contain valid SPF/DKIM/DMARC signatures.')
    if risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        recommendations.append('Report the URL/sender to abuse@domain and your SIEM.')

    detections: dict[str, Any] = {
        'domain': url_result,
        'content': content_result,
        'headers': header_result,
        'gemini': gemini_result,
    }

    metadata: dict[str, Any] = {
        'domain': url_result['domain'] if url_result else '',
        'scores': {
            'url_features': round(url_score, 1),
            'rf_classifier': round(rf_score, 1),
            'nlp_content': round(nlp_score, 1),
            'transformer_nlp': round(transformer_score, 1),
            'headers': round(header_risk, 1),
            'gemini': round(gemini_score, 1),
        },
        'indicators': gemini_result.get('indicators', []) if gemini_result else [],
        'confidence': gemini_result.get('confidence', '') if gemini_result else '',
        'detection_layers': {
            'url_engineering': bool(url_result),
            'random_forest': bool(rf_score > 0),
            'nltk_nlp': bool(content_result),
            'transformer_nlp': transformer_available,
            'header_analysis': bool(header_result),
            'gemini_ai': gemini_available,
        },
    }

    return {
        'reputation_score': round(reputation, 1),
        'risk_score': round(risk_score, 1),
        'risk_level': risk_level,
        'detections': detections,
        'recommendations': recommendations,
        'metadata': metadata,
        'domain_age_days': domain_age_days,
    }

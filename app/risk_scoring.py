RISK_CATEGORIES = {
    (0, 24): 'LOW',
    (25, 49): 'MEDIUM',
    (50, 74): 'HIGH',
    (75, 100): 'CRITICAL'
}


def get_risk_category(score: int) -> str:
    """
    Return risk category label ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') based on numeric score.
    """
    val = max(0, min(100, int(score or 0)))
    for (low, high), category in RISK_CATEGORIES.items():
        if low <= val <= high:
            return category
    return 'CRITICAL' if val >= 75 else 'LOW'


def calculate_ai_score(ai_result: dict | None = None, verdict: str | None = None, confidence: float | None = None) -> int:
    """
    Calculate AI score based on verdict and confidence.
    Accepts either an ai_result dict or explicit verdict and confidence parameters.
    verdict: PHISHING=40pts, SUSPICIOUS=25pts, LEGITIMATE=0pts, UNAVAILABLE=0pts
    Multiplied by confidence (0.0 - 1.0).
    Returns an integer from 0 to 40.
    """
    if ai_result is None and (verdict is not None or confidence is not None):
        ai_result = {
            'verdict': verdict or 'UNAVAILABLE',
            'confidence': confidence if confidence is not None else 1.0
        }

    if not ai_result or not isinstance(ai_result, dict):
        return 0

    verdict_str = str(ai_result.get('verdict', 'UNAVAILABLE')).strip().upper()
    try:
        conf_val = float(ai_result.get('confidence', 0.0))
    except (ValueError, TypeError):
        conf_val = 0.0

    conf_val = max(0.0, min(1.0, conf_val))

    verdict_points = {
        'PHISHING': 40,
        'SUSPICIOUS': 25,
        'LEGITIMATE': 0,
        'UNAVAILABLE': 0
    }

    base = verdict_points.get(verdict_str, 0)
    score = round(base * conf_val)
    return max(0, min(40, score))


def calculate_final_score(rule_score: int, ai_score: int | None = 0) -> int:
    """
    Combine clamped rule_score (0-60) and ai_score (0-40) into a composite final score (0-100).
    """
    clamped_rule = min(60, max(0, int(rule_score or 0)))
    clamped_ai = min(40, max(0, int(ai_score or 0)))
    return min(100, max(0, clamped_rule + clamped_ai))


def build_score_report(rule_findings: list | None = None, ai_result: dict | None = None, **kwargs) -> dict:
    """
    Build a comprehensive scoring report with a detailed score breakdown.
    Accepts rule_findings, ai_result or keyword arguments.
    """
    if rule_findings is None:
        rule_findings = kwargs.get('findings') or []
    if 'rule_score' in kwargs and not rule_findings:
        rule_findings = [{'points': kwargs['rule_score'], 'indicator_type': 'MANUAL_RULE'}]
    if ai_result is None and ('ai_verdict' in kwargs or 'ai_confidence' in kwargs):
        ai_result = {
            'verdict': kwargs.get('ai_verdict', 'UNAVAILABLE'),
            'confidence': kwargs.get('ai_confidence', 0.0)
        }
    findings = rule_findings or []
    raw_rule_score = sum(f.get('points', 0) for f in findings if isinstance(f, dict))
    rule_score = min(60, max(0, raw_rule_score))

    ai_score = calculate_ai_score(ai_result)
    final_score = calculate_final_score(rule_score, ai_score)
    risk_category = get_risk_category(final_score)

    # Build detailed breakdown
    breakdown_map = {
        'SUSPICIOUS_URL': {
            'name': 'Suspicious URLs & Links',
            'max_points': 15,
            'default_desc': 'URL shorteners, IP links, obfuscation, or insecure protocols.'
        },
        'URGENT_LANGUAGE': {
            'name': 'Urgent / Threatening Language',
            'max_points': 12,
            'default_desc': 'Psychological pressure, artificial deadlines, and alarmist phrases.'
        },
        'CREDENTIAL_REQUEST': {
            'name': 'Credential & Financial Requests',
            'max_points': 15,
            'default_desc': 'Solicitation of passwords, OTP tokens, PINs, or bank details.'
        },
        'SENDER_MISMATCH': {
            'name': 'Sender Domain Verification',
            'max_points': 10,
            'default_desc': 'Discrepancy between sender email domain and claimed brand identity.'
        },
        'SUSPICIOUS_ATTACHMENT': {
            'name': 'Attachment Indicators',
            'max_points': 8,
            'default_desc': 'Directives to open suspicious files, archives, or executable payloads.'
        },
        'URGENCY_FORMATTING': {
            'name': 'Typography & Punctuation Abuse',
            'max_points': 5,
            'default_desc': 'Excessive capital letters, screaming headers, and repetitive exclamation marks.'
        },
        'MISSPELLED_BRAND': {
            'name': 'Brand Typosquatting',
            'max_points': 5,
            'default_desc': 'Lookalike brand spellings designed to evade spam filters.'
        }
    }

    score_breakdown = []

    # Map rule findings to breakdown
    findings_by_type = {}
    for f in findings:
        itype = f.get('indicator_type')
        if itype:
            findings_by_type[itype] = f

    for itype, meta in breakdown_map.items():
        found = findings_by_type.get(itype)
        pts = found.get('points', 0) if found else 0
        desc = found.get('description', meta['default_desc']) if found else meta['default_desc']
        score_breakdown.append({
            'name': meta['name'],
            'points': pts,
            'max_points': meta['max_points'],
            'description': desc
        })

    # Add AI evaluation breakdown
    verdict = (ai_result or {}).get('verdict', 'UNAVAILABLE')
    confidence = (ai_result or {}).get('confidence', 0.0)
    ai_desc = f"Model verdict: {verdict} ({round(float(confidence or 0) * 100)}% confidence)"
    if verdict == 'UNAVAILABLE':
        ai_desc = 'Ollama LLM was unavailable or timed out; score defaults to 0.'

    score_breakdown.append({
        'name': 'Ollama AI Semantic Analysis',
        'points': ai_score,
        'max_points': 40,
        'description': ai_desc
    })

    return {
        'rule_score': rule_score,
        'ai_score': ai_score,
        'final_score': final_score,
        'risk_score': final_score,
        'risk_category': risk_category,
        'score_breakdown': score_breakdown
    }

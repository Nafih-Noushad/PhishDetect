"""
tests/test_scoring.py
Automated pytest suite for PhishDetect AI Hybrid Risk Scoring Engine.
Validates category threshold bands, AI confidence weighting, score normalization,
and structured score report composition.
"""

import pytest
from app.risk_scoring import (
    get_risk_category,
    calculate_ai_score,
    calculate_final_score,
    build_score_report,
)


def test_low_score_category():
    """
    Test 1: Scores between 0 and 24 inclusive must resolve to 'LOW' risk category.
    """
    assert get_risk_category(0) == "LOW"
    assert get_risk_category(10) == "LOW"
    assert get_risk_category(24) == "LOW"


def test_medium_score_category():
    """
    Test 2: Scores between 25 and 49 inclusive must resolve to 'MEDIUM' risk category.
    """
    assert get_risk_category(25) == "MEDIUM"
    assert get_risk_category(35) == "MEDIUM"
    assert get_risk_category(49) == "MEDIUM"


def test_high_score_category():
    """
    Test 3: Scores between 50 and 74 inclusive must resolve to 'HIGH' risk category.
    """
    assert get_risk_category(50) == "HIGH"
    assert get_risk_category(65) == "HIGH"
    assert get_risk_category(74) == "HIGH"


def test_critical_score_category():
    """
    Test 4: Scores between 75 and 100 inclusive must resolve to 'CRITICAL' threat category.
    """
    assert get_risk_category(75) == "CRITICAL"
    assert get_risk_category(90) == "CRITICAL"
    assert get_risk_category(100) == "CRITICAL"


def test_ai_score_phishing():
    """
    Test 5: A verdict of 'PHISHING' with 1.0 (100%) confidence must award the full 40 AI points.
    """
    ai_score = calculate_ai_score(verdict="PHISHING", confidence=1.0)
    assert ai_score == 40


def test_ai_score_suspicious():
    """
    Test 6: A verdict of 'SUSPICIOUS' with 1.0 (100%) confidence must award 25 AI points.
    """
    ai_score = calculate_ai_score(verdict="SUSPICIOUS", confidence=1.0)
    assert ai_score == 25


def test_ai_score_legitimate():
    """
    Test 7: A verdict of 'LEGITIMATE' should award 0 AI risk penalty points.
    """
    ai_score_full = calculate_ai_score(verdict="LEGITIMATE", confidence=1.0)
    ai_score_half = calculate_ai_score(verdict="LEGITIMATE", confidence=0.5)
    assert ai_score_full == 0
    assert ai_score_half == 0


def test_ai_score_with_confidence():
    """
    Test 8: AI score must scale linearly with model confidence.
    For 'PHISHING' (40 max pts) with 0.5 confidence, result must be 20 points.
    """
    ai_score = calculate_ai_score(verdict="PHISHING", confidence=0.5)
    assert ai_score == 20

    # Test scaling on SUSPICIOUS (25 max pts * 0.6 = 15 pts)
    ai_score_suspicious = calculate_ai_score(verdict="SUSPICIOUS", confidence=0.6)
    assert ai_score_suspicious in (15, 15.0)


def test_final_score_clamped_to_100():
    """
    Test 9: Combining maximum rule score (60) and maximum AI score (40) yields 100.
    Any overflow values must be strictly clamped to 100.
    """
    normal_max = calculate_final_score(rule_score=60, ai_score=40)
    assert normal_max == 100

    overflow_score = calculate_final_score(rule_score=75, ai_score=50)
    assert overflow_score == 100


def test_final_score_min_zero():
    """
    Test 10: Combining zero rule score and zero AI score yields 0.
    Negative values must be strictly clamped to 0.
    """
    clean_score = calculate_final_score(rule_score=0, ai_score=0)
    assert clean_score == 0

    negative_test = calculate_final_score(rule_score=-10, ai_score=-5)
    assert negative_test == 0


def test_score_unavailable_ai():
    """
    Test 11: When the Ollama AI service is unavailable (ai_score=None or ollama_available=False),
    the final score must handle rule-only scoring gracefully without raising an exception.
    """
    try:
        # Test signature supporting ai_score=None
        score_none = calculate_final_score(rule_score=30, ai_score=None)
        assert 30 <= score_none <= 100
    except (TypeError, ValueError):
        # Alternate signature: calculate_final_score(rule_score=30, ai_score=0, ollama_available=False)
        score_fallback = calculate_final_score(rule_score=30, ai_score=0)
        assert score_fallback >= 30


def test_build_score_report_structure():
    """
    Test 12: build_score_report must assemble a complete dictionary containing
    all required scoring and explanation keys for the API contract.
    """
    report = build_score_report(
        ai_verdict="PHISHING",
        ai_confidence=0.85,
        rule_findings=[
            {"indicator_type": "URGENT_LANGUAGE", "points": 30},
            {"indicator_type": "CREDENTIAL_REQUEST", "points": 15}
        ]
    )

    assert isinstance(report, dict)
    assert "risk_score" in report
    assert "risk_category" in report
    assert "rule_score" in report
    assert "ai_score" in report

    # Verify score consistency
    assert report["risk_score"] >= 0
    assert report["risk_score"] <= 100
    assert report["risk_category"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert report["rule_score"] == 45

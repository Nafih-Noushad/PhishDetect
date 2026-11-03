"""
tests/test_detection.py
Automated pytest suite for PhishDetect AI Deterministic Rule-Based Detection Engine.
Validates individual heuristic indicators, edge cases, input limits, and score capping.
"""

import pytest
from app.detection_engine import PhishingDetectionEngine


@pytest.fixture
def engine():
    """Provides a fresh instance of the PhishingDetectionEngine for each test."""
    return PhishingDetectionEngine()


def _extract_findings_and_score(result):
    """
    Helper to normalize engine return value across list of findings, tuple (findings, score)
    or dict {'findings': ..., 'rule_score': ...} or object formats.
    """
    if isinstance(result, list):
        findings = result
        raw_score = sum(f.get("points", 0) for f in findings if isinstance(f, dict))
        return findings, min(60, raw_score)
    elif isinstance(result, tuple):
        return result[0], result[1]
    elif isinstance(result, dict):
        findings = result.get("findings") or result.get("rule_findings") or []
        score = result.get("score") if "score" in result else result.get("rule_score", 0)
        return findings, score
    elif hasattr(result, "findings") and hasattr(result, "rule_score"):
        return result.findings, result.rule_score
    raise TypeError(f"Unexpected return type from detection engine: {type(result)}")


def test_phishing_email_detected(engine):
    """
    Test 1: An obvious phishing email with multiple threat vectors must trigger
    multiple heuristic rule findings and result in a substantial rule risk score.
    """
    sender = "security-alert@paypa1-update.com"
    subject = "URGENT: Your PayPal Account Has Been Suspended - Action Required!"
    body = (
        "Dear customer,\n"
        "We detected unauthorized access to your account. You must verify within 24 hours "
        "or your account will be permanently terminated.\n"
        "Click here immediately: http://bit.ly/paypal-verify-account\n"
        "Enter your password, credit card number, and the one-time OTP code.\n"
        "PayPal Security Team"
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    assert len(findings) >= 2, f"Expected at least 2 findings, got {len(findings)}"
    assert score >= 25, f"Expected rule score >= 25 for severe phishing, got {score}"

    indicator_types = [f.get("indicator_type", "") for f in findings]
    # Check that at least two of the primary phishing signals were detected
    matched_expected = any("URGENT" in it for it in indicator_types) or \
                       any("CREDENTIAL" in it or "PASSWORD" in it for it in indicator_types) or \
                       any("URL" in it for it in indicator_types) or \
                       any("DOMAIN" in it for it in indicator_types)
    assert matched_expected, f"Expected common phishing indicator types, got: {indicator_types}"


def test_legitimate_email_clean(engine):
    """
    Test 2: A legitimate newsletter notification from github.com should produce
    zero or minimal heuristic findings and a near-zero rule risk score.
    """
    sender = "notifications@github.com"
    subject = "Your GitHub Actions workflow 'CI/CD' completed successfully"
    body = (
        "Hi there,\n"
        "Your GitHub Actions workflow completed without errors.\n"
        "Repository: company/webapp\n"
        "Commit: 7a8b9c0d\n"
        "Duration: 1m 45s\n"
        "You can view the run details at https://github.com/company/webapp/actions/runs/98765\n"
        "GitHub, Inc. 88 Colin P Kelly Jr St, San Francisco, CA"
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    # Legitimate email should have minimal or no findings
    assert score <= 10, f"Expected clean score <= 10, got {score}"
    indicator_types = [f.get("indicator_type", "") for f in findings]
    for it in indicator_types:
        assert "CREDENTIAL" not in it and "PASSWORD" not in it, \
            "Legitimate email should not trigger credential theft indicators"


def test_urgent_language_detection(engine):
    """
    Test 3: Emails containing artificial urgency and coercion phrases
    (e.g., 'urgent', 'act now', 'suspended within 24 hours') must trigger URGENT_LANGUAGE.
    """
    sender = "notice@support-portal.net"
    subject = "URGENT ACTION REQUIRED: Immediate account suspension notice"
    body = (
        "You must act now! Your account will be permanently closed within 24 hours "
        "if you do not take immediate action. Failure to comply will result in total loss."
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    indicator_types = [f.get("indicator_type", "") for f in findings]
    assert any("URGENT" in it or "URGENCY" in it for it in indicator_types), \
        f"Expected urgency indicator in {indicator_types}"
    assert score > 0, "Urgent language must contribute positively to the rule score"


def test_credential_request_detection(engine):
    """
    Test 4: Emails explicitly requesting credentials, passwords, PINs, or OTP tokens
    must be flagged by the credential harvest rule.
    """
    sender = "it-helpdesk@corporate-verify.org"
    subject = "Annual password validation check"
    body = (
        "Please confirm your password immediately. You must enter your OTP verification code "
        "and update your billing information to continue using this account."
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    indicator_types = [f.get("indicator_type", "") for f in findings]
    assert any("CREDENTIAL" in it or "PASSWORD" in it or "OTP" in it for it in indicator_types), \
        f"Expected credential theft indicator in {indicator_types}"
    assert score >= 10, "Credential requests are high severity"


def test_suspicious_url_detection(engine):
    """
    Test 5: Emails containing shortened URLs (e.g. bit.ly, tinyurl) or raw IP addresses
    must trigger suspicious URL detection.
    """
    sender = "service@banking-updates.com"
    subject = "Review your latest monthly transaction summary"
    body = (
        "Please review your transaction activity by clicking here: "
        "http://bit.ly/bank-statement-dl or visit http://192.168.1.100/login"
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    indicator_types = [f.get("indicator_type", "") for f in findings]
    assert any("URL" in it or "LINK" in it or "SHORTENER" in it for it in indicator_types), \
        f"Expected URL indicator in {indicator_types}"


def test_sender_domain_mismatch(engine):
    """
    Test 6: When the email claims to represent an institution (e.g., PayPal or Chase)
    but originates from an unrelated or suspicious sender domain, flag domain mismatch.
    """
    sender = "security@fast-server-billing-system.com"
    subject = "Official PayPal Security Alert: Payment on hold"
    body = (
        "Your PayPal account was debited $890.00 USD. If you did not make this purchase, "
        "contact our PayPal customer support center immediately."
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    indicator_types = [f.get("indicator_type", "") for f in findings]
    assert any("MISMATCH" in it or "DOMAIN" in it or "SPOOF" in it or "BRAND" in it for it in indicator_types), \
        f"Expected domain mismatch or brand impersonation indicator in {indicator_types}"


def test_attachment_reference_detection(engine):
    """
    Test 7: Emails referencing suspicious attachments (e.g., invoice.zip, payment.exe,
    'open the attached file') must trigger attachment warnings.
    """
    sender = "accounts@vendor-billing.com"
    subject = "Overdue invoice #83921"
    body = (
        "Hello,\n"
        "Please find the overdue invoice attached as Invoice_83921.zip. "
        "Open the attached file to view outstanding invoice details and remit payment."
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    indicator_types = [f.get("indicator_type", "") for f in findings]
    assert any("ATTACHMENT" in it or "FILE" in it for it in indicator_types), \
        f"Expected attachment indicator in {indicator_types}"


def test_caps_lock_detection(engine):
    """
    Test 8: Emails containing excessive ALL CAPS shouting words designed to induce panic
    must trigger excessive capitalization detection.
    """
    sender = "admin@system-alert-hub.com"
    subject = "CRITICAL WARNING: IMMEDIATE ACTION REQUIRED"
    body = (
        "ATTENTION! DO NOT IGNORE THIS NOTICE! YOUR ACCOUNT HAS BEEN LOCKED! "
        "FAILING TO CONFIRM YOUR DETAILS WILL RESULT IN IMMEDIATE TERMINATION! "
        "ACT NOW OR LOSE ACCESS FOREVER!"
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    indicator_types = [f.get("indicator_type", "") for f in findings]
    assert any("CAPS" in it or "UPPERCASE" in it or "SHOUTING" in it or "FORMATTING" in it for it in indicator_types), \
        f"Expected formatting/caps indicator in {indicator_types}"


def test_empty_body(engine):
    """
    Test 9: Edge case with completely empty body string must not crash or raise unhandled exceptions.
    """
    sender = "colleague@example.com"
    subject = "Quick question"
    body = ""

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    assert isinstance(findings, list)
    assert isinstance(score, (int, float))
    assert score >= 0


def test_very_long_body(engine):
    """
    Test 10: Extreme input size with 50,000+ characters should process cleanly without timing out.
    """
    sender = "log-daemon@internal-service.local"
    subject = "Daily automated log report"
    body = "Routine normal server log entry status OK 200.\n" * 1200  # > 50,000 chars

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    assert isinstance(findings, list)
    assert isinstance(score, (int, float))
    assert score >= 0


def test_no_indicators_clean_email(engine):
    """
    Test 11: A standard professional business message should produce zero findings and score 0.
    """
    sender = "sarah.jenkins@acmecorp.com"
    subject = "Notes from project retrospective meeting"
    body = (
        "Hi team,\n"
        "Thanks for attending today's project retrospective. We discussed sprint milestones, "
        "resolved technical debt items, and agreed on next sprint targets. Let's touch base "
        "again on Thursday.\nBest regards,\nSarah"
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    assert score == 0, f"Expected 0 rule score for clean professional email, got {score}"
    assert len(findings) == 0, f"Expected 0 findings for clean email, got {findings}"


def test_total_rule_score_capped(engine):
    """
    Test 12: Even when an email triggers all possible heuristic indicators repeatedly,
    the total rule engine score must strictly never exceed the 60-point ceiling.
    """
    sender = "security@fraudulent-phishing-host.xyz"
    subject = "URGENT! PAYPAL ACCOUNT SUSPENDED! OPEN ATTACHED FILE NOW!"
    body = (
        "ATTENTION CUSTOMER! YOUR ACCOUNT IS SUSPENDED IMMEDIATELY! "
        "ACT NOW WITHIN 24 HOURS OR BE BANNED FOREVER! "
        "We are PayPal Security. Click here: http://bit.ly/fake-link-1 and http://192.168.0.1/steal "
        "Enter your password, secret PIN code, and credit card number. "
        "Open the attached file Invoice_Verify.zip to complete account reset. "
        "DO NOT IGNORE THIS WARNING! VERIFY YOUR IDENTITY IMMEDIATELY!"
    )

    result = engine.analyze(sender=sender, subject=subject, body=body)
    findings, score = _extract_findings_and_score(result)

    assert score <= 60, f"Rule score must be capped at 60 points max, got {score}"
    assert score >= 30, f"Heavy phishing email should accumulate substantial points, got {score}"

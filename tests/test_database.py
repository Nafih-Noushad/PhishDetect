"""
tests/test_database.py
Automated pytest suite for PhishDetect AI SQLite persistence layer.
Validates scan record persistence, pagination, search filtering, category filtering,
parameterized SQL injection defense, statistics aggregation, and cascading deletes.
"""

import json
import pytest
from app import create_app, db
from app.models import ScanResult, ScanFinding, AppSettings, Scan, Finding, Setting
from app.database import (
    get_scan_by_id, get_all_scans, delete_scan, clear_all_scans,
    get_stats, get_setting, set_setting
)


@pytest.fixture
def app():
    """Configures an isolated in-memory SQLite Flask application context for testing."""
    test_config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-phishdetect-secret"
    }
    app_instance = create_app(test_config)

    with app_instance.app_context():
        db.create_all()
        yield app_instance
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Provides an authenticated Flask test client."""
    c = app.test_client()
    with c.session_transaction() as sess:
        sess['logged_in'] = True
        sess['email'] = 'admin@phishdetect.ai'
    return c


@pytest.fixture
def session(app):
    """Provides direct SQLAlchemy database session."""
    return db.session


def test_save_scan_result(app, session):
    """
    Test 1: Save a scan record with rule score and AI findings and verify retrieval.
    """
    scan = Scan(
        sender="attacker@spoofed.com",
        subject="Action Required: Immediate Verification",
        body_preview="Please verify your account immediately...",
        risk_score=85,
        risk_category="CRITICAL",
        rule_score=50,
        ai_score=35,
        ai_verdict="PHISHING",
        ai_confidence=0.95,
        ai_uncertainty="low",
        model_used="llama3.2"
    )
    session.add(scan)
    session.commit()

    retrieved = session.query(Scan).filter_by(id=scan.id).first()
    assert retrieved is not None
    assert retrieved.sender == "attacker@spoofed.com"
    assert retrieved.risk_score == 85
    assert retrieved.risk_category == "CRITICAL"
    assert retrieved.ai_verdict == "PHISHING"


def test_get_scan_by_id(app, session):
    """
    Test 2: Retrieve a specific scan record by its primary unique id.
    """
    scan = Scan(
        sender="hr@company.internal",
        subject="Benefits Enrollment",
        risk_score=10,
        risk_category="LOW",
        ai_verdict="LEGITIMATE"
    )
    session.add(scan)
    session.commit()

    found = get_scan_by_id(scan.id)
    assert found is not None
    assert found.subject == "Benefits Enrollment"

    # Non-existent ID lookup returns None
    missing = get_scan_by_id(999999)
    assert missing is None


def test_get_all_scans_pagination(app, session, client):
    """
    Test 3: Verify pagination limits and page offsets over a batch of scan records.
    """
    # Insert 15 scan records
    for i in range(15):
        scan = Scan(
            sender=f"user{i}@domain.com",
            subject=f"Subject test notification {i}",
            risk_score=i * 5,
            risk_category="LOW" if i < 5 else "MEDIUM"
        )
        session.add(scan)
    session.commit()

    # Query via API endpoint
    res_page1 = client.get("/api/history?page=1&per_page=10")
    assert res_page1.status_code == 200
    data1 = res_page1.get_json()
    assert len(data1["scans"]) == 10
    assert data1["total"] == 15
    assert data1["pages"] == 2

    res_page2 = client.get("/api/history?page=2&per_page=10")
    assert res_page2.status_code == 200
    data2 = res_page2.get_json()
    assert len(data2["scans"]) == 5


def test_search_filter(app, session, client):
    """
    Test 4: Verify case-insensitive text search matches across sender and subject fields.
    """
    session.add(Scan(sender="security@paypal.com", subject="Receipt #1234", risk_score=15))
    session.add(Scan(sender="billing@paypa1-fake.com", subject="URGENT SUSPENDED", risk_score=90))
    session.add(Scan(sender="newsletter@github.com", subject="New release notes", risk_score=0))
    session.commit()

    # Search for 'paypal'
    res = client.get("/api/history?search=paypal")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total"] == 1

    # Search for 'URGENT'
    res_urgent = client.get("/api/history?search=urgent")
    assert res_urgent.status_code == 200
    data_urgent = res_urgent.get_json()
    assert data_urgent["total"] == 1
    assert "paypa1-fake" in data_urgent["scans"][0]["sender"]


def test_category_filter(app, session, client):
    """
    Test 5: Filter scans by specific risk category (e.g. CRITICAL, LOW).
    """
    session.add(Scan(sender="a@test.com", subject="A", risk_score=10, risk_category="LOW"))
    session.add(Scan(sender="b@test.com", subject="B", risk_score=85, risk_category="CRITICAL"))
    session.add(Scan(sender="c@test.com", subject="C", risk_score=95, risk_category="CRITICAL"))
    session.commit()

    res_crit = client.get("/api/history?category=CRITICAL")
    assert res_crit.status_code == 200
    data_crit = res_crit.get_json()
    assert data_crit["total"] == 2
    for s in data_crit["scans"]:
        assert s["risk_category"] == "CRITICAL"


def test_delete_scan(app, session, client):
    """
    Test 6: Verify deletion of a specific scan record and ensure it cannot be found afterwards.
    """
    scan = Scan(sender="del@test.com", subject="To be deleted", risk_score=20)
    session.add(scan)
    session.commit()
    target_id = scan.id

    res = client.delete(f"/api/history/{target_id}")
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Check persistence
    assert get_scan_by_id(target_id) is None


def test_clear_all_scans(app, session, client):
    """
    Test 7: Verify clearing all scan records removes all rows and reports deleted count.
    """
    for i in range(5):
        session.add(Scan(sender=f"test{i}@test.com", subject=f"Sub {i}", risk_score=20))
    session.commit()

    res = client.delete("/api/history")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["deleted"] == 5

    assert session.query(Scan).count() == 0


def test_get_stats_empty(app, client):
    """
    Test 8: Telemetry stats endpoint returns clean zero metrics on an unpopulated database.
    """
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    stats = data.get("stats") or data
    assert stats["total_scans"] == 0
    assert stats["phishing_count"] == 0
    assert stats["safe_count"] == 0
    assert stats["critical_count"] == 0


def test_get_stats_with_data(app, session, client):
    """
    Test 9: Telemetry stats endpoint accurately computes phishing, safe, and critical aggregates.
    """
    session.add(Scan(sender="s1@ok.com", subject="S1", risk_score=5, risk_category="LOW", ai_verdict="LEGITIMATE"))
    session.add(Scan(sender="s2@ok.com", subject="S2", risk_score=15, risk_category="LOW", ai_verdict="LEGITIMATE"))
    session.add(Scan(sender="m1@mid.com", subject="M1", risk_score=40, risk_category="MEDIUM", ai_verdict="SUSPICIOUS"))
    session.add(Scan(sender="p1@bad.com", subject="P1", risk_score=70, risk_category="HIGH", ai_verdict="PHISHING"))
    session.add(Scan(sender="p2@bad.com", subject="P2", risk_score=90, risk_category="CRITICAL", ai_verdict="PHISHING"))
    session.commit()

    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    stats = data.get("stats") or data
    assert stats["total_scans"] == 5
    assert stats["safe_count"] == 2
    assert stats["critical_count"] == 1
    assert stats["phishing_count"] >= 2


def test_parameterized_queries(app, session, client):
    """
    Test 10: SQL injection payload strings in search and filter inputs must be safely
    escaped and treated as literal string values, preventing SQL injection exploits.
    """
    session.add(Scan(sender="legit@corp.com", subject="Safe Report", risk_score=5))
    session.commit()

    # SQL Injection attempt in search param
    injection_payload = "' OR '1'='1' --"
    res = client.get(f"/api/history?search={injection_payload}")
    assert res.status_code == 200
    data = res.get_json()
    # Must not return rows via SQL tautology
    assert data["total"] == 0

    # Malicious DROP TABLE payload
    drop_payload = "test'; DROP TABLE scan_results; --"
    res_drop = client.get(f"/api/history?search={drop_payload}")
    assert res_drop.status_code == 200

    # Verify table remains intact
    assert session.query(Scan).count() == 1


def test_settings_get_set(app, session, client):
    """
    Test 11: Get and update application settings key-value entries in database.
    """
    # Set setting
    res_post = client.post("/api/settings", json={
        "ollama_url": "http://127.0.0.1:11434",
        "ollama_model": "llama3.2"
    })
    assert res_post.status_code == 200
    data_post = res_post.get_json()
    assert data_post["success"] is True

    # Retrieve setting
    res_get = client.get("/api/settings")
    assert res_get.status_code == 200
    data_get = res_get.get_json()
    assert data_get["ollama_url"] == "http://127.0.0.1:11434"
    assert data_get["ollama_model"] == "llama3.2"


def test_cascading_delete(app, session):
    """
    Test 12: Deleting a Scan entity must automatically cascade and remove all
    associated child Finding records from the database.
    """
    scan = Scan(
        sender="attacker@domain.com",
        subject="Credential Request",
        risk_score=75,
        risk_category="CRITICAL"
    )
    session.add(scan)
    session.flush()

    finding1 = Finding(
        scan_id=scan.id,
        indicator_type="CREDENTIAL_REQUEST",
        description="Requests password and OTP code",
        points=25,
        evidence=json.dumps(["enter your password"])
    )
    finding2 = Finding(
        scan_id=scan.id,
        indicator_type="URGENT_LANGUAGE",
        description="24 hour ultimatum",
        points=15,
        evidence=json.dumps(["within 24 hours"])
    )
    session.add_all([finding1, finding2])
    session.commit()

    assert session.query(Finding).filter_by(scan_id=scan.id).count() == 2

    # Delete parent scan
    session.delete(scan)
    session.commit()

    # Verify children are deleted by cascade
    assert session.query(Scan).filter_by(id=scan.id).first() is None
    assert session.query(Finding).filter_by(scan_id=scan.id).count() == 0

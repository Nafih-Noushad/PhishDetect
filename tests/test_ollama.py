"""
tests/test_ollama.py
Automated pytest suite for PhishDetect AI Ollama Service Integration.
Validates HTTP resilience, model discovery, JSON response sanitization,
timeout management, markdown code block stripping, and output schema verification.
"""

import json
import pytest
from unittest.mock import patch, MagicMock
import requests
from app.ollama_service import OllamaService


@pytest.fixture
def ollama():
    """Provides an initialized OllamaService pointing to a test URL."""
    return OllamaService(base_url="http://localhost:11434", model="llama3.2")


def test_check_connection_success(ollama):
    """
    Test 1: When /api/tags returns HTTP 200, check_connection must return connected=True.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [{"name": "llama3.2:latest"}, {"name": "mistral:latest"}]
    }

    with patch("requests.get", return_value=mock_resp):
        result = ollama.check_connection()
        if isinstance(result, tuple):
            connected, error = result
            assert connected is True
            assert error is None
        elif isinstance(result, dict):
            assert result.get("connected") is True
        else:
            assert result is True


def test_check_connection_failure(ollama):
    """
    Test 2: When Ollama daemon is offline or throws a ConnectionError,
    check_connection must handle it gracefully and report connected=False.
    """
    with patch("requests.get", side_effect=requests.ConnectionError("Connection refused")):
        result = ollama.check_connection()
        if isinstance(result, tuple):
            connected, error = result
            assert connected is False
            assert error is not None
        elif isinstance(result, dict):
            assert result.get("connected") is False
        else:
            assert result is False


def test_list_models_success(ollama):
    """
    Test 3: Model listing must parse the /api/tags payload and return clean model names.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [
            {"name": "llama3.2:latest"},
            {"name": "llama3.2:3b"},
            {"name": "phi3:mini"}
        ]
    }

    with patch("requests.get", return_value=mock_resp):
        models = ollama.list_models()
        assert isinstance(models, list)
        assert len(models) == 3
        assert "llama3.2:latest" in models
        assert "phi3:mini" in models


def test_analyze_email_success(ollama):
    """
    Test 4: When Ollama returns well-formed JSON, analyze_email parses all fields accurately.
    """
    expected_payload = {
        "verdict": "PHISHING",
        "confidence": 0.95,
        "uncertainty": "low",
        "reasons": ["Urgent threat of account closure", "Misleading domain link"],
        "evidence": ["verify within 24 hours", "http://bit.ly/paypal"],
        "recommended_actions": ["Do not click the link", "Report to security"]
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": json.dumps(expected_payload)
    }

    with patch("requests.post", return_value=mock_resp):
        res = ollama.analyze_email(
            sender="admin@paypa1.com",
            subject="Urgent",
            body="Verify immediately"
        )
        assert res.get("success") is True
        result = res.get("result") or res
        assert result["verdict"] == "PHISHING"
        assert result["confidence"] == 0.95
        assert len(result["reasons"]) == 2
        assert len(result["evidence"]) == 2


def test_analyze_email_invalid_json(ollama):
    """
    Test 5: When the model responds with non-JSON unstructured text,
    analyze_email must report success=False and an error without crashing.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": "I think this email looks like phishing because it asks for a password."
    }

    with patch("requests.post", return_value=mock_resp):
        res = ollama.analyze_email(
            sender="test@evil.com",
            subject="Test",
            body="Test body"
        )
        assert isinstance(res, dict)
        assert res.get("success") is False
        assert res.get("result") is None
        assert res.get("error") is not None


def test_analyze_email_timeout(ollama):
    """
    Test 6: When Ollama API times out, analyze_email must return success=False
    and capture the error cleanly.
    """
    with patch("requests.post", side_effect=requests.Timeout("Request timed out after 30s")):
        res = ollama.analyze_email(
            sender="test@evil.com",
            subject="Test",
            body="Test body"
        )
        assert isinstance(res, dict)
        assert res.get("success") is False
        assert res.get("result") is None
        assert "timed out" in str(res.get("error")).lower()


def test_analyze_email_missing_fields(ollama):
    """
    Test 7: When Ollama returns JSON missing required schema keys (e.g. 'verdict'),
    the parser normalizes and defaults missing fields.
    """
    incomplete_payload = {
        "confidence": 0.8,
        "reasons": ["suspicious wording"]
        # Missing 'verdict'
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": json.dumps(incomplete_payload)
    }

    with patch("requests.post", return_value=mock_resp):
        res = ollama.analyze_email(
            sender="test@evil.com",
            subject="Test",
            body="Test body"
        )
        assert res.get("success") is True
        result = res.get("result") or res
        assert "verdict" in result


def test_invalid_verdict_value(ollama):
    """
    Test 8: An unauthorized verdict string like 'MAYBE' or 'UNSURE' must be normalized
    to one of PHISHING, SUSPICIOUS, or LEGITIMATE.
    """
    invalid_verdict_payload = {
        "verdict": "MAYBE",
        "confidence": 0.5,
        "reasons": ["uncertain"],
        "evidence": [],
        "recommended_actions": []
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": json.dumps(invalid_verdict_payload)
    }

    with patch("requests.post", return_value=mock_resp):
        res = ollama.analyze_email(
            sender="test@evil.com",
            subject="Test",
            body="Test body"
        )
        assert res.get("success") is True
        result = res.get("result") or res
        assert result["verdict"] in ["PHISHING", "SUSPICIOUS", "LEGITIMATE"]


def test_confidence_out_of_range(ollama):
    """
    Test 9: Confidence values outside 0.0 to 1.0 (e.g., 1.5) must be clamped to 1.0.
    """
    out_of_range_payload = {
        "verdict": "PHISHING",
        "confidence": 1.5,
        "uncertainty": "low",
        "reasons": ["fake reason"],
        "evidence": [],
        "recommended_actions": []
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": json.dumps(out_of_range_payload)
    }

    with patch("requests.post", return_value=mock_resp):
        res = ollama.analyze_email(
            sender="test@evil.com",
            subject="Test",
            body="Test body"
        )
        assert res.get("success") is True
        result = res.get("result") or res
        assert 0.0 <= result["confidence"] <= 1.0


def test_extract_json_from_markdown(ollama):
    """
    Test 10: Ollama models frequently enclose JSON output in markdown blocks (```json ... ```).
    The service must extract and parse the JSON block correctly.
    """
    clean_json = {
        "verdict": "LEGITIMATE",
        "confidence": 0.98,
        "uncertainty": "low",
        "reasons": ["Standard automated CI report", "Verified domain sender"],
        "evidence": [],
        "recommended_actions": ["No action needed"]
    }

    markdown_response = f"""Here is my analysis in JSON:
```json
{json.dumps(clean_json, indent=2)}
```
Hope this helps!"""

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": markdown_response
    }

    with patch("requests.post", return_value=mock_resp):
        res = ollama.analyze_email(
            sender="ci@github.com",
            subject="Build success",
            body="Tests passed"
        )
        assert res.get("success") is True
        result = res.get("result") or res
        assert result["verdict"] == "LEGITIMATE"
        assert result["confidence"] == 0.98
        assert len(result["reasons"]) == 2

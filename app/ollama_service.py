import json
import logging
import re
import requests

logger = logging.getLogger(__name__)


class OllamaService:
    def __init__(self, base_url: str = 'http://localhost:11434', model: str = 'llama3.2', timeout: int = 60):
        self.base_url = (base_url or 'http://localhost:11434').rstrip('/')
        self.model = model or 'llama3.2'
        self.timeout = timeout

    def check_connection(self) -> dict:
        """
        Verify connection to the Ollama service and return available models.
        Returns: {'connected': bool, 'error': str | None, 'models': list}
        """
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get('name') for m in data.get('models', []) if m.get('name')]
                return {
                    'connected': True,
                    'error': None,
                    'models': models
                }
            return {
                'connected': False,
                'error': f"Ollama returned HTTP status {resp.status_code}",
                'models': []
            }
        except requests.exceptions.ConnectionError:
            return {
                'connected': False,
                'error': f"Connection refused at {self.base_url}. Ensure Ollama is running.",
                'models': []
            }
        except requests.exceptions.Timeout:
            return {
                'connected': False,
                'error': f"Connection timed out after 5 seconds at {self.base_url}.",
                'models': []
            }
        except Exception as e:
            logger.exception("Error checking Ollama connection")
            return {
                'connected': False,
                'error': str(e),
                'models': []
            }

    def list_models(self) -> list:
        """
        Query Ollama tags endpoint and return list of model names.
        """
        conn_info = self.check_connection()
        return conn_info.get('models', [])

    def analyze_email(self, sender: str, subject: str, body: str) -> dict:
        """
        Analyze an email for phishing intent using Ollama LLM.
        Returns:
            {
                'success': bool,
                'result': dict | None,
                'error': str | None,
                'raw_response': str | None
            }
        """
        prompt = self._build_prompt(sender, subject, body)
        endpoint = f"{self.base_url}/api/generate"

        payload = {
            'model': self.model,
            'prompt': prompt,
            'stream': False,
            'format': 'json',
            'options': {
                'temperature': 0.1,
                'top_p': 0.9
            }
        }

        try:
            resp = requests.post(endpoint, json=payload, timeout=self.timeout)
            if resp.status_code != 200:
                err_msg = f"Ollama HTTP error {resp.status_code}: {resp.text[:200]}"
                logger.warning(err_msg)
                return {
                    'success': False,
                    'result': None,
                    'error': err_msg,
                    'raw_response': resp.text
                }

            response_data = resp.json()
            raw_text = response_data.get('response', '')
            parsed_result = self._parse_ai_response(raw_text)

            return {
                'success': True,
                'result': parsed_result,
                'error': None,
                'raw_response': raw_text
            }

        except requests.exceptions.RequestException as e:
            logger.warning(f"Ollama request failed: {e}")
            return {
                'success': False,
                'result': None,
                'error': f"Ollama connection error: {str(e)}",
                'raw_response': None
            }
        except Exception as e:
            logger.exception(f"Unexpected error parsing Ollama response: {e}")
            return {
                'success': False,
                'result': None,
                'error': str(e),
                'raw_response': locals().get('raw_text', None)
            }

    def _build_prompt(self, sender: str, subject: str, body: str) -> str:
        """
        Construct a strict prompt directing Ollama to output JSON phishing analysis.
        Truncates body to 3000 characters to prevent context window overflow.
        """
        truncated_body = (body or '').strip()[:3000]

        return f"""You are an elite cybersecurity specialist specializing in email security and phishing detection.
Carefully examine the following email for phishing indicators, social engineering, credential harvesting, spoofing, and malicious intent.

Email Details:
- Sender: {sender}
- Subject: {subject}
- Body:
{truncated_body}

Respond ONLY with a valid JSON object matching this EXACT schema:
{{
  "verdict": "PHISHING" | "SUSPICIOUS" | "LEGITIMATE",
  "reasons": ["detailed technical reason 1", "detailed technical reason 2"],
  "evidence": ["exact text snippet or indicator from email"],
  "confidence": 0.85,
  "uncertainty": "low" | "medium" | "high",
  "recommended_actions": ["recommended defensive action 1", "action 2"]
}}

Instructions:
1. "verdict" must be one of: "PHISHING", "SUSPICIOUS", or "LEGITIMATE".
2. "confidence" must be a float between 0.0 and 1.0.
3. "uncertainty" must be "low", "medium", or "high".
4. "reasons", "evidence", and "recommended_actions" must each be a non-empty list of strings.
5. Provide NO conversational filler, markdown commentary, or introductory text. Return only the JSON object."""

    def _extract_json(self, text: str) -> dict:
        """
        Extract and parse a JSON dictionary from text that may contain markdown or surrounding text.
        """
        if not text or not isinstance(text, str):
            raise ValueError("Empty or invalid response from Ollama")

        cleaned = text.strip()

        # Handle ```json ... ``` or ``` ... ```
        fence_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        else:
            # Fallback to finding the first { and the last }
            brace_match = re.search(r'(\{.*\})', cleaned, re.DOTALL)
            if brace_match:
                cleaned = brace_match.group(1).strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON: {e}")

    def _parse_ai_response(self, raw_text: str) -> dict:
        """
        Extract JSON from response and validate required fields:
        verdict, reasons, evidence, confidence, uncertainty, recommended_actions.
        """
        data = self._extract_json(raw_text)

        raw_verdict = str(data.get('verdict', '')).strip().upper()
        if raw_verdict not in {'PHISHING', 'SUSPICIOUS', 'LEGITIMATE'}:
            if 'PHISH' in raw_verdict:
                raw_verdict = 'PHISHING'
            elif 'SUSPIC' in raw_verdict:
                raw_verdict = 'SUSPICIOUS'
            elif 'LEGIT' in raw_verdict or 'SAFE' in raw_verdict:
                raw_verdict = 'LEGITIMATE'
            else:
                raw_verdict = 'SUSPICIOUS'

        # Validate confidence
        try:
            confidence = float(data.get('confidence', 0.5))
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.5

        # Validate uncertainty
        raw_uncertainty = str(data.get('uncertainty', 'medium')).strip().lower()
        if raw_uncertainty not in {'low', 'medium', 'high'}:
            raw_uncertainty = 'medium'

        # Validate reasons
        reasons = data.get('reasons', [])
        if isinstance(reasons, str):
            reasons = [reasons]
        elif not isinstance(reasons, list):
            reasons = []

        # Validate evidence
        evidence = data.get('evidence', [])
        if isinstance(evidence, str):
            evidence = [evidence]
        elif not isinstance(evidence, list):
            evidence = []

        # Validate recommended_actions
        recommended_actions = data.get('recommended_actions', [])
        if isinstance(recommended_actions, str):
            recommended_actions = [recommended_actions]
        elif not isinstance(recommended_actions, list):
            recommended_actions = []

        if not recommended_actions:
            if raw_verdict == 'PHISHING':
                recommended_actions = [
                    "Do not click any links or download attachments.",
                    "Report this email to your organization's IT security team.",
                    "Permanently delete this email from your inbox and trash."
                ]
            elif raw_verdict == 'SUSPICIOUS':
                recommended_actions = [
                    "Verify the sender's identity through an independent, trusted channel.",
                    "Avoid submitting sensitive credentials or financial details.",
                    "Check URL destinations carefully before clicking."
                ]
            else:
                recommended_actions = [
                    "Email appears legitimate; remain vigilant for unexpected requests."
                ]

        return {
            'verdict': raw_verdict,
            'reasons': [str(r).strip() for r in reasons if str(r).strip()],
            'evidence': [str(e).strip() for e in evidence if str(e).strip()],
            'confidence': round(confidence, 2),
            'uncertainty': raw_uncertainty,
            'recommended_actions': [str(a).strip() for a in recommended_actions if str(a).strip()]
        }


def get_ollama_service() -> OllamaService:
    """
    Factory function to retrieve an OllamaService instance using current database settings
    or environment variable fallbacks. Avoids circular imports.
    """
    import os
    from app.database import get_setting

    ollama_url = get_setting('ollama_url', os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'))
    ollama_model = get_setting('ollama_model', os.getenv('OLLAMA_MODEL', 'llama3.2'))

    return OllamaService(base_url=ollama_url, model=ollama_model)

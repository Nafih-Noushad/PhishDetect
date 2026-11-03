import re
from urllib.parse import urlparse


def sanitize_string(s, max_length=None):
    """
    Strip leading/trailing whitespace, collapse internal whitespace runs to a single space,
    and optionally truncate to max_length.
    """
    if s is None:
        return ''
    cleaned = re.sub(r'\s+', ' ', str(s)).strip()
    if max_length is not None and max_length > 0:
        cleaned = cleaned[:max_length]
    return cleaned


def is_valid_url_string(url_string):
    """
    Basic URL format check ensuring valid scheme and network location.
    """
    if not url_string or not isinstance(url_string, str):
        return False
    try:
        parsed = urlparse(url_string.strip())
        return parsed.scheme.lower() in {'http', 'https'} and bool(parsed.netloc)
    except Exception:
        return False


def validate_email_input(sender, subject, body):
    """
    Validate email analysis inputs.
    - Required fields check
    - sender max 500 chars, must contain @
    - subject max 1000 chars
    - body max 50000 chars
    - Strip whitespace
    Returns (is_valid: bool, cleaned_data: dict | None, error_message: str | None)
    """
    if sender is None or not str(sender).strip():
        return False, None, 'Sender email address is required.'

    if subject is None or not str(subject).strip():
        return False, None, 'Email subject is required.'

    if body is None or not str(body).strip():
        return False, None, 'Email body is required.'

    sender_clean = str(sender).strip()
    subject_clean = str(subject).strip()
    body_clean = str(body).strip()

    if len(sender_clean) > 500:
        return False, None, 'Sender address exceeds maximum limit of 500 characters.'

    if '@' not in sender_clean:
        return False, None, 'Sender must contain a valid email address with "@".'

    # Check for basic email structure or Name <email@domain>
    email_pattern = r'[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}'
    if not re.search(email_pattern, sender_clean):
        return False, None, 'Sender must include a valid email domain (e.g., user@example.com).'

    if len(subject_clean) > 1000:
        return False, None, 'Email subject exceeds maximum limit of 1000 characters.'

    if len(body_clean) > 50000:
        return False, None, 'Email body exceeds maximum limit of 50,000 characters.'

    return True, {
        'sender': sender_clean,
        'subject': subject_clean,
        'body': body_clean
    }, None


def validate_settings_input(ollama_url, ollama_model):
    """
    Validate Ollama connection settings:
    - ollama_url must start with http:// or https://
    - ollama_model max 100 chars
    Returns (is_valid: bool, cleaned_data: dict | None, error_message: str | None)
    """
    if ollama_url is None or not str(ollama_url).strip():
        return False, None, 'Ollama base URL is required.'

    url_clean = str(ollama_url).strip()
    if not (url_clean.startswith('http://') or url_clean.startswith('https://')):
        return False, None, 'Ollama base URL must begin with "http://" or "https://".'

    if ollama_model is None or not str(ollama_model).strip():
        return False, None, 'Ollama model identifier is required.'

    model_clean = str(ollama_model).strip()
    if len(model_clean) > 100:
        return False, None, 'Ollama model name cannot exceed 100 characters.'

    return True, {
        'ollama_url': url_clean,
        'ollama_model': model_clean
    }, None

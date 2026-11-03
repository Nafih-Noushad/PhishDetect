import re
from urllib.parse import urlparse


class PhishingDetectionEngine:
    """
    Rule-based Phishing Detection Engine.
    Analyzes sender, subject, and body for 7 heuristic indicators of email phishing.
    """

    SHORTENER_DOMAINS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'rb.gy',
        'is.gd', 'short.link', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rebrand.ly'
    }

    URGENT_PATTERNS = [
        'urgent', 'act now', 'immediately', 'account suspended',
        'account will be closed', 'verify now', 'confirm now', 'action required',
        'limited time', 'expires today', 'expires in 24', 'last chance',
        'final notice', 'warning:', 'alert:', 'security alert',
        'unusual activity', 'unauthorized access', 'suspicious activity'
    ]

    CREDENTIAL_PATTERNS = [
        'enter your password', 'confirm your password', 'reset your password',
        'enter otp', 'enter your otp', 'one-time password', 'verification code',
        'enter your pin', 'credit card', 'debit card', 'billing information',
        'payment details', 'bank account', 'routing number', 'social security',
        'date of birth', "mother's maiden", 'click here to verify',
        'verify your account', 'update your account'
    ]

    ATTACHMENT_PATTERNS = [
        'download the attachment', 'open the attached', 'see attachment',
        'attached file', 'attached document', '.exe', '.zip file',
        '.pdf attached', 'invoice attached', 'please find attached'
    ]

    KNOWN_BRANDS = {
        'paypal': ['paypal.com'],
        'amazon': ['amazon.com'],
        'google': ['google.com', 'gmail.com'],
        'microsoft': ['microsoft.com', 'office.com', 'live.com', 'outlook.com'],
        'apple': ['apple.com', 'icloud.com'],
        'netflix': ['netflix.com'],
        'bank': [],
        'fedex': ['fedex.com'],
        'ups': ['ups.com'],
        'dhl': ['dhl.com'],
        'irs': ['irs.gov'],
        'ssa': ['ssa.gov'],
        'facebook': ['facebook.com', 'fb.com'],
        'instagram': ['instagram.com'],
        'twitter': ['twitter.com', 'x.com'],
        'linkedin': ['linkedin.com']
    }

    LOOKALIKE_DOMAINS = ['paypa1', 'arnazon', 'microssoft', 'g00gle', 'app1e']

    LOOKALIKE_BRANDS = [
        'paypa1', 'arnazon', 'microssoft', 'g00gle',
        'app1e', 'faceb00k', 'netfl1x', 'ins7agram'
    ]

    def analyze(self, sender: str, subject: str, body: str) -> list:
        """
        Run all heuristic indicator analyzers on the email inputs.
        Returns a list of finding dictionaries.
        """
        findings = []

        # 1. Suspicious URLs
        url_finding = self._check_suspicious_urls(subject, body)
        if url_finding:
            findings.append(url_finding)

        # 2. Urgent / Threatening Language
        urgency_finding = self._check_urgent_language(subject, body)
        if urgency_finding:
            findings.append(urgency_finding)

        # 3. Credential / OTP / Payment Requests
        credential_finding = self._check_credential_requests(subject, body)
        if credential_finding:
            findings.append(credential_finding)

        # 4. Sender Domain Mismatch
        sender_finding = self._check_sender_mismatch(sender, subject, body)
        if sender_finding:
            findings.append(sender_finding)

        # 5. Suspicious Attachment References
        attachment_finding = self._check_attachment_references(subject, body)
        if attachment_finding:
            findings.append(attachment_finding)

        # 6. Excessive Urgency Formatting
        formatting_finding = self._check_urgency_formatting(subject, body)
        if formatting_finding:
            findings.append(formatting_finding)

        # 7. Misspelled Brand Names
        misspell_finding = self._check_misspelled_brands(subject, body)
        if misspell_finding:
            findings.append(misspell_finding)

        return findings

    def _extract_urls(self, text: str) -> list:
        url_regex = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        return re.findall(url_regex, text or '')

    def _check_suspicious_urls(self, subject: str, body: str) -> dict | None:
        urls = self._extract_urls(f"{subject}\n{body}")
        if not urls:
            return None

        evidence = []
        points = 0

        # Pattern for IP-based URLs: http://192.168.1.1
        ip_pattern = re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?')

        for raw_url in urls:
            normalized_url = raw_url if raw_url.startswith(('http://', 'https://')) else f'http://{raw_url}'
            try:
                parsed = urlparse(normalized_url)
                netloc = (parsed.netloc or '').lower()
                hostname = parsed.hostname or ''
            except Exception:
                continue

            # Shortener match
            for shortener in self.SHORTENER_DOMAINS:
                if hostname == shortener or hostname.endswith(f".{shortener}"):
                    evidence.append(f"Shortened URL detected: {raw_url}")
                    points += 5
                    break

            # IP address host
            if ip_pattern.match(raw_url) or re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname):
                evidence.append(f"Direct IP-based URL detected: {raw_url}")
                points += 5

            # Insecure HTTP on banking/financial brand names
            sensitive_keywords = ['paypal', 'amazon', 'bank', 'chase', 'wellsfargo', 'apple', 'netflix', 'login', 'account']
            if raw_url.lower().startswith('http://'):
                if any(k in netloc for k in sensitive_keywords):
                    evidence.append(f"Unencrypted HTTP link referencing sensitive keyword: {raw_url}")
                    points += 5

            # Long obfuscated URLs
            if len(raw_url) > 120 or len(re.findall(r'%[0-9a-fA-F]{2}', raw_url)) >= 3:
                evidence.append(f"Obfuscated or excessively long URL parameter string: {raw_url[:80]}...")
                points += 4

        if evidence:
            capped_points = min(15, points)
            return {
                'indicator_type': 'SUSPICIOUS_URL',
                'description': 'Detected suspicious or obfuscated links, URL shorteners, or insecure protocols.',
                'evidence': list(dict.fromkeys(evidence)),  # deduplicate
                'points': capped_points
            }
        return None

    def _check_urgent_language(self, subject: str, body: str) -> dict | None:
        combined = f"{subject} {body}".lower()
        matched = []

        for phrase in self.URGENT_PATTERNS:
            if phrase in combined:
                matched.append(phrase)

        if matched:
            points = min(12, len(matched) * 3)
            return {
                'indicator_type': 'URGENT_LANGUAGE',
                'description': 'Email contains threatening, high-pressure, or artificial urgency language.',
                'evidence': [f"Detected urgency phrase: '{m}'" for m in matched],
                'points': points
            }
        return None

    def _check_credential_requests(self, subject: str, body: str) -> dict | None:
        combined = f"{subject} {body}".lower()
        matched = []

        for phrase in self.CREDENTIAL_PATTERNS:
            if phrase in combined:
                matched.append(phrase)

        if matched:
            points = min(15, len(matched) * 4)
            return {
                'indicator_type': 'CREDENTIAL_REQUEST',
                'description': 'Requests sensitive authentication credentials, passwords, OTP codes, or financial details.',
                'evidence': [f"Detected credential trigger: '{m}'" for m in matched],
                'points': points
            }
        return None

    def _check_sender_mismatch(self, sender: str, subject: str, body: str) -> dict | None:
        evidence = []
        points = 0

        sender_str = str(sender or '').strip()
        display_name = ''
        email_addr = sender_str

        # Parse 'Brand Name <email@domain.com>'
        match = re.match(r'^(.*?)\s*<([^>]+)>$', sender_str)
        if match:
            display_name = match.group(1).strip()
            email_addr = match.group(2).strip()

        domain = ''
        if '@' in email_addr:
            domain = email_addr.split('@')[-1].lower()

        content_lower = f"{subject} {body} {display_name}".lower()

        # Check lookalike domain in sender domain
        for lookalike in self.LOOKALIKE_DOMAINS:
            if lookalike in domain:
                evidence.append(f"Sender domain '{domain}' uses spoofed/lookalike pattern '{lookalike}'")
                points += 5
                break

        # Check brand name mentions vs sender domain
        for brand, legitimate_domains in self.KNOWN_BRANDS.items():
            # Brand mentioned in content or display name
            pattern = rf'\b{re.escape(brand)}\b'
            if re.search(pattern, content_lower):
                if legitimate_domains:
                    is_legit = any(
                        domain == legit or domain.endswith(f".{legit}")
                        for legit in legitimate_domains
                    )
                    if not is_legit and domain:
                        evidence.append(
                            f"Email claims to represent '{brand.title()}' but was sent from non-official domain '{domain}'"
                        )
                        points += 8
                        break
                elif brand == 'bank':
                    # Generic bank reference with free webmail
                    free_webmails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
                    if domain in free_webmails:
                        evidence.append(f"Banking notice sent from free webmail provider '{domain}'")
                        points += 8
                        break

        if evidence:
            capped_points = min(10, points)
            return {
                'indicator_type': 'SENDER_MISMATCH',
                'description': 'Sender domain does not match claimed brand identity or uses typosquatted domain.',
                'evidence': evidence,
                'points': capped_points
            }
        return None

    def _check_attachment_references(self, subject: str, body: str) -> dict | None:
        combined = f"{subject} {body}".lower()
        matched = []

        for phrase in self.ATTACHMENT_PATTERNS:
            if phrase in combined:
                matched.append(phrase)

        if matched:
            points = min(8, len(matched) * 4)
            return {
                'indicator_type': 'SUSPICIOUS_ATTACHMENT',
                'description': 'Directs recipient to open unsolicited file attachments, macros, or dangerous extensions.',
                'evidence': [f"Attachment cue found: '{m}'" for m in matched],
                'points': points
            }
        return None

    def _check_urgency_formatting(self, subject: str, body: str) -> dict | None:
        evidence = []
        points = 0

        # Count ALL CAPS words of 3+ letters in subject and body
        text = f"{subject} {body}"
        caps_words = re.findall(r'\b[A-Z]{3,}\b', text)
        # Filter out common benign abbreviations
        filtered_caps = [w for w in caps_words if w not in {'THE', 'AND', 'FOR', 'NOT', 'YOU', 'URL', 'SSL', 'TLS', 'API', 'HTML', 'HTTP', 'HTTPS'}]

        if len(filtered_caps) >= 5:
            evidence.append(f"Excessive ALL CAPS text detected ({len(filtered_caps)} words: {', '.join(filtered_caps[:5])}...)")
            points += 3

        # Count exclamation marks
        exclamation_count = text.count('!')
        if exclamation_count >= 3:
            evidence.append(f"High frequency of exclamation marks ({exclamation_count} instances)")
            points += 2

        if evidence:
            return {
                'indicator_type': 'URGENCY_FORMATTING',
                'description': 'Aggressive typography, excessive capitalization, and exclamation formatting.',
                'evidence': evidence,
                'points': min(5, points)
            }
        return None

    def _check_misspelled_brands(self, subject: str, body: str) -> dict | None:
        combined = f"{subject} {body}".lower()
        matched = []

        for lookalike in self.LOOKALIKE_BRANDS:
            if lookalike in combined:
                matched.append(lookalike)

        if matched:
            return {
                'indicator_type': 'MISSPELLED_BRAND',
                'description': 'Commonly typosquatted or deliberately misspelled brand names identified.',
                'evidence': [f"Misspelled brand keyword: '{m}'" for m in matched],
                'points': 5
            }
        return None


def get_total_rule_score(findings: list) -> int:
    """
    Sum the point values across all rule findings, clamped between 0 and 60.
    """
    if not findings:
        return 0
    total = sum(f.get('points', 0) for f in findings if isinstance(f, dict))
    return min(60, max(0, total))

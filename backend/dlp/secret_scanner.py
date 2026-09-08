"""
Project Mathra - High-Performance Secret & Token Regex Scanner
Uses TruffleHog-inspired enterprise regex signatures to detect and mask API keys,
passwords, cryptographic private keys, and cloud credentials before LLM ingestion.
"""

import re
from typing import List, Tuple
from backend.core.security import SecretMatch


# Compiled enterprise regex patterns
SECRET_PATTERNS = [
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "AKIA[REDACTED_AWS_KEY]"
    ),
    (
        "AWS_SECRET_KEY",
        re.compile(r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "aws_secret_access_key=[REDACTED_AWS_SECRET]"
    ),
    (
        "GITHUB_PAT",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        "ghp_[REDACTED_GITHUB_TOKEN]"
    ),
    (
        "GITHUB_FINE_GRAINED_PAT",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b"),
        "github_pat_[REDACTED_PAT]"
    ),
    (
        "OPENAI_API_KEY",
        re.compile(r"\b(sk-[a-zA-Z0-9]{32,48}|sk-proj-[a-zA-Z0-9_\-]{40,})\b"),
        "sk-[REDACTED_OPENAI_KEY]"
    ),
    (
        "SLACK_WEBHOOK",
        re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        "https://hooks.slack.com/services/T[REDACTED_SLACK_WEBHOOK]"
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY_BLOCK]\n-----END PRIVATE KEY-----"
    ),
    (
        "GENERIC_BEARER_TOKEN",
        re.compile(r"\bBearer\s+([a-zA-Z0-9_\-\.]{32,})\b", re.IGNORECASE),
        "Bearer [REDACTED_BEARER_TOKEN]"
    ),
    (
        "DATABASE_URI",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+:[0-9]+(?:/[a-zA-Z0-9_\-\.]*)?\b", re.IGNORECASE),
        "[REDACTED_DATABASE_CONNECTION_URI]"
    ),
]


class SecretScanner:
    """Enterprise secret scanner that detects and masks high-entropy credentials."""

    def __init__(self):
        self.patterns = SECRET_PATTERNS

    def scan(self, text: str) -> List[SecretMatch]:
        """Scans text and returns all detected secret matches."""
        matches: List[SecretMatch] = []
        if not text:
            return matches

        for secret_type, regex, _ in self.patterns:
            for match in regex.finditer(text):
                matched_str = match.group(0)
                # Mask the snippet for safe logging/reporting
                if len(matched_str) > 8:
                    masked = f"{matched_str[:4]}...{matched_str[-4:]}"
                else:
                    masked = "***"
                matches.append(SecretMatch(secret_type=secret_type, match_snippet=masked))

        return matches

    def mask(self, text: str) -> Tuple[str, List[SecretMatch]]:
        """Scans and masks all credentials in the text, returning sanitized text and matches."""
        if not text:
            return text, []

        detected_secrets = self.scan(text)
        sanitized_text = text

        for secret_type, regex, replacement in self.patterns:
            sanitized_text = regex.sub(replacement, sanitized_text)

        return sanitized_text, detected_secrets


# Global instance
secret_scanner = SecretScanner()

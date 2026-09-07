"""
PROJECT MATHRA - Sanitized Enterprise Logging
CWE-209 Mitigation: Never leak raw stack traces or internal secrets to users.
Provides structured logging, correlation IDs, and secret masking in log outputs.
"""

import logging                      # logging is used to log messages
import re                           # re is used to regular expressions
import sys                          # sys is used to get the system
import uuid                         # uuid is used to generate unique identifiers
from typing import Any, Dict        # Any and Dict are used to type hints

# Pre-compile patterns to strip known secret formats from server log records
LOG_SECRET_MASKS = [
    (re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE), "sk-***REDACTED***"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA***REDACTED***"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "ghp_***REDACTED***"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{24,}", re.IGNORECASE), "Bearer ***REDACTED***"),
    (re.compile(r"(password|secret|token)[\"']?\s*[:=]\s*[\"']?([^\s\"',]+)", re.IGNORECASE), r"\1=***REDACTED***"),
]

class SanitizedFormatter(logging.Formatter):
    """Logging formatter that scrubs accidental credentials and formats cleanly."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        sanitized = original
        for pattern, replacement in LOG_SECRET_MASKS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized


def generate_incident_id() -> str:
    """Generate a unique tracking ID for error correlation and incident auditing."""
    return f"MATHRA-INCIDENT-{uuid.uuid4().hex[:8].upper()}"


def setup_logger(name: str = "mathra", level: str = "INFO") -> logging.Logger:
    """Configures and returns a sanitized application logger."""
    logger = logging.getLogger(name)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(numeric_level)
        formatter = SanitizedFormatter(
            fmt="%(asctime)s [%(levelname)s] [MATHRA-CORE] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

# Global default logger
logger = setup_logger()
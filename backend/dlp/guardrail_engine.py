"""
Project Mathra - Guardrail & Adversarial Injection Engine
Detects direct prompt injections, jailbreaks, DAN role-play escapes,
and system prompt extraction attempts (OWASP LLM01 & LLM07).
"""

import re
from typing import Tuple
from backend.core.security import GuardrailAssessment


ADVERSARIAL_RULES = [
    (
        "PROMPT_INJECTION",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|above|system|safety|initial|\s)*(?:instructions|prompts|rules|guidelines|directives)\b"
        ),
        0.95,
        "Direct instruction override attempt detected."
    ),
    (
        "SYSTEM_OVERRIDE_DIRECTIVE",
        re.compile(
            r"(?i)\b(?:system\s+override|admin\s+override|root\s+override|clear\s+conversation\s+history)\b"
        ),
        0.95,
        "Administrative override directive detected."
    ),
    (
        "JAILBREAK_ATTEMPT",
        re.compile(
            r"(?i)\b(?:you\s+are\s+(?:now\s+)?(?:DAN|in\s+developer\s+mode|unrestricted|an\s+unconstrained)|do\s+anything\s+now|jailbreak\s+mode|unfiltered\s+mode|developer\s+mode\s+enabled|evil\s+twin)\b"
        ),
        0.90,
        "Known jailbreak framing pattern (DAN / Developer Mode) detected."
    ),
    (
        "SYSTEM_PROMPT_EXTRACTION",
        re.compile(
            r"(?i)\b(?:reveal|print|show|output|repeat|disclose|what\s+is|what\s+was|tell\s+me)\s+(?:your\s+)?(?:system\s+(?:prompt|message)|initial\s+(?:instructions|prompt|directives|system\s+message)|internal\s+(?:directives|guidelines|rules|instructions)|developer\s+(?:directives|instructions|rules|mode\s+prompt))\b"
        ),
        0.85,
        "System prompt exfiltration attempt detected."
    ),
    (
        "DELIMITER_SMUGGLING",
        re.compile(
            r"(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>>)"
        ),
        0.90,
        "Chat template control token smuggling detected."
    ),
    (
        "BASE64_OBFUSCATION_ATTEMPT",
        re.compile(
            r"(?i)\b(?:decode\s+this\s+base64|execute\s+base64|base64:)\s*[A-Za-z0-9+/=]{40,}"
        ),
        0.75,
        "Potential payload obfuscation via Base64 detected."
    ),
]


class GuardrailEngine:
    """Evaluates prompt payloads for adversarial patterns and jailbreaks."""

    def evaluate(self, text: str) -> GuardrailAssessment:
        if not text:
            return GuardrailAssessment(is_safe=True, threat_score=0.0)

        highest_score = 0.0
        primary_threat = None
        primary_reason = None

        for threat_type, pattern, score, reason in ADVERSARIAL_RULES:
            if pattern.search(text):
                if score > highest_score:
                    highest_score = score
                    primary_threat = threat_type
                    primary_reason = reason

        is_safe = highest_score < 0.60
        return GuardrailAssessment(
            is_safe=is_safe,
            threat_score=highest_score,
            threat_type=primary_threat if not is_safe else None,
            reason=primary_reason if not is_safe else None
        )


# Global instance
guardrail_engine = GuardrailEngine()

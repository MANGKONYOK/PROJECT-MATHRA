"""
Project Mathra - Resilient PII/PHI DLP Engine
Integrates Microsoft Presidio Analyzer/Anonymizer with an automated high-speed
regex fallback to ensure sub-400ms latency and 100% uptime even if spaCy weights are absent.
"""

import re
from typing import List, Tuple, Optional
from backend.core.logging import logger
from backend.core.security import DlpEntityMatch

# High-speed fallback regex patterns for standard PII/PHI entities
FALLBACK_PII_PATTERNS = [
    (
        "EMAIL_ADDRESS",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        0.95
    ),
    (
        "PHONE_NUMBER",
        re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        0.85
    ),
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        0.90
    ),
    (
        "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        0.90
    ),
    (
        "US_SSN",
        re.compile(r"\b(?!000)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        0.95
    ),
    (
        "MEDICAL_RECORD_NUMBER",
        re.compile(r"\b(?:MRN|MEDREC|PATIENT)[#:\s]+([A-Za-z0-9]{6,12})\b", re.IGNORECASE),
        0.80
    ),
]


class RegexFallbackDlpEngine:
    """Ultra-fast regex-based PII analyzer and anonymizer."""

    def analyze(self, text: str) -> List[DlpEntityMatch]:
        matches: List[DlpEntityMatch] = []
        if not text:
            return matches

        for entity_type, pattern, score in FALLBACK_PII_PATTERNS:
            for m in pattern.finditer(text):
                val = m.group(0)
                masked_val = val[:2] + "***" + val[-2:] if len(val) > 4 else "***"
                matches.append(
                    DlpEntityMatch(
                        entity_type=entity_type,
                        start=m.start(),
                        end=m.end(),
                        score=score,
                        text_snippet=masked_val
                    )
                )
        return matches

    def anonymize(self, text: str, matches: Optional[List[DlpEntityMatch]] = None) -> Tuple[str, List[DlpEntityMatch]]:
        if not text:
            return text, []

        if matches is None:
            matches = self.analyze(text)

        # Sort matches in reverse order by start index to prevent offset shifting
        sorted_matches = sorted(matches, key=lambda x: x.start, reverse=True)
        anonymized = text

        for m in sorted_matches:
            tag = f"<REDACTED_PII:{m.entity_type}>"
            anonymized = anonymized[:m.start] + tag + anonymized[m.end:]

        return anonymized, matches


class PresidioEngineWrapper:
    """Wrapper coordinating Presidio Analyzer with automatic regex fallback."""

    def __init__(self):
        self.analyzer = None
        self.anonymizer = None
        self.fallback = RegexFallbackDlpEngine()
        self.mode = "fallback"
        self._initialize()

    def _initialize(self):
        """Attempts to initialize Microsoft Presidio; gracefully falls back if spaCy weights missing."""
        try:
            import spacy
            if spacy.util.is_package("en_core_web_sm"):
                from presidio_analyzer import AnalyzerEngine
                from presidio_anonymizer import AnonymizerEngine
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
                self.mode = "presidio"
                logger.info("Presidio NLP Engine initialized successfully with 'en_core_web_sm'.")
            else:
                self.mode = "fallback"
                logger.warning(
                    "spaCy model 'en_core_web_sm' not installed. "
                    "Engaging Presidio Resilient Regex Fallback Engine."
                )
        except Exception as e:
            self.mode = "fallback"
            logger.warning(
                f"Could not load Presidio Analyzer: {e}. "
                "Engaging Presidio Resilient Regex Fallback Engine."
            )

    def analyze(self, text: str) -> List[DlpEntityMatch]:
        """Analyzes text for PII/PHI entities."""
        if not text:
            return []

        if self.mode == "presidio" and self.analyzer:
            try:
                results = self.analyzer.analyze(text=text, entities=[], language="en")
                matches = []
                for r in results:
                    val = text[r.start:r.end]
                    masked_val = val[:2] + "***" + val[-2:] if len(val) > 4 else "***"
                    matches.append(
                        DlpEntityMatch(
                            entity_type=r.entity_type,
                            start=r.start,
                            end=r.end,
                            score=r.score,
                            text_snippet=masked_val
                        )
                    )
                return matches
            except Exception as e:
                logger.error(f"Presidio analyze error: {e}. Falling back to regex.")
                return self.fallback.analyze(text)
        else:
            return self.fallback.analyze(text)

    def anonymize(self, text: str) -> Tuple[str, List[DlpEntityMatch]]:
        """Redacts and sanitizes detected PII/PHI in text."""
        if not text:
            return text, []

        matches = self.analyze(text)

        if self.mode == "presidio" and self.anonymizer and self.analyzer:
            try:
                from presidio_analyzer import RecognizerResult
                presidio_results = [
                    RecognizerResult(entity_type=m.entity_type, start=m.start, end=m.end, score=m.score)
                    for m in matches
                ]
                res = self.anonymizer.anonymize(text=text, analyzer_results=presidio_results)
                return res.text, matches
            except Exception as e:
                logger.error(f"Presidio anonymize error: {e}. Falling back to regex.")
                return self.fallback.anonymize(text, matches)
        else:
            return self.fallback.anonymize(text, matches)


# Global instance
presidio_engine = PresidioEngineWrapper()

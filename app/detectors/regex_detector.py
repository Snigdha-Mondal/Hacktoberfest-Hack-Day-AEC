"""Deterministic regex detector for secrets, credentials, and personal identifiers (PII)."""
import re
from typing import List, Dict, Any, Optional, Tuple
from app.model.schemas import Finding, SensitiveCategory, RiskLevel, RecommendedAction, mask_secret


def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate credit card number using the Luhn algorithm to prevent false positives."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else (doubled - 9)
        else:
            checksum += digit
    return checksum % 10 == 0


def spans_overlap(span1: Tuple[int, int], span2: Tuple[int, int]) -> bool:
    """Return True if two character spans overlap."""
    return max(span1[0], span2[0]) < min(span1[1], span2[1])


class RegexRule:
    def __init__(
        self,
        name: str,
        category: SensitiveCategory,
        pattern: str,
        risk: RiskLevel,
        reason: str,
        confidence: float = 0.95,
        validator: Optional[Any] = None,
    ):
        self.name = name
        self.category = category
        self.regex = re.compile(pattern)
        self.risk = risk
        self.reason = reason
        self.confidence = confidence
        self.validator = validator


class RegexDetector:
    """Detects credentials, keys, and PII using deterministic regular expressions."""

    def __init__(self):
        self.rules: List[RegexRule] = [
            # --- AI & Cloud API Keys (Order specific patterns first) ---
            RegexRule(
                name="Anthropic API Key",
                category=SensitiveCategory.API_KEY,
                pattern=r"\bsk-ant-[A-Za-z0-9_-]{32,120}\b",
                risk=RiskLevel.CRITICAL,
                reason="Anthropic credential. Grants access to Claude models and workspace API credits.",
                confidence=0.99,
            ),
            RegexRule(
                name="OpenAI API Key",
                category=SensitiveCategory.API_KEY,
                pattern=r"\bsk-(?!ant-)(?:proj-|admin-|svcacct-)?[A-Za-z0-9_-]{32,150}\b",
                risk=RiskLevel.CRITICAL,
                reason="Active OpenAI credential. Grants direct access to AI models and account balance.",
                confidence=0.99,
            ),
            RegexRule(
                name="Google AI Key",
                category=SensitiveCategory.API_KEY,
                pattern=r"\bAIza[0-9A-Za-z_-]{35}\b",
                risk=RiskLevel.CRITICAL,
                reason="Google API key. Grants access to Gemini and Google Cloud project APIs.",
                confidence=0.98,
            ),
            RegexRule(
                name="GitHub Personal Access Token",
                category=SensitiveCategory.API_KEY,
                pattern=r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
                risk=RiskLevel.CRITICAL,
                reason="GitHub personal token. Grants direct read/write access to code repositories.",
                confidence=0.99,
            ),
            RegexRule(
                name="AWS Access Key ID",
                category=SensitiveCategory.API_KEY,
                pattern=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
                risk=RiskLevel.CRITICAL,
                reason="Amazon Web Services access key ID. May allow remote infrastructure access.",
                confidence=0.95,
            ),
            RegexRule(
                name="Slack Token",
                category=SensitiveCategory.API_KEY,
                pattern=r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
                risk=RiskLevel.CRITICAL,
                reason="Slack authentication token. Allows reading channel messages and workspace data.",
                confidence=0.98,
            ),
            RegexRule(
                name="JSON Web Token (JWT)",
                category=SensitiveCategory.API_KEY,
                pattern=r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
                risk=RiskLevel.HIGH,
                reason="Cryptographic bearer token. May contain user identity or session authorization.",
                confidence=0.92,
            ),
            RegexRule(
                name="Private Key Header",
                category=SensitiveCategory.PASSWORD,
                pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                risk=RiskLevel.CRITICAL,
                reason="Cryptographic private key file header. Extreme risk of identity and server compromise.",
                confidence=0.99,
            ),

            # --- Personal Identifiable Information (PII) ---
            RegexRule(
                name="US Social Security Number",
                category=SensitiveCategory.GOVERNMENT_ID,
                pattern=r"\b\d{3}-\d{2}-\d{4}\b",
                risk=RiskLevel.CRITICAL,
                reason="National identification number. High risk of identity theft and fraud.",
                confidence=0.96,
            ),
            RegexRule(
                name="Credit Card Number",
                category=SensitiveCategory.BANK_DATA,
                pattern=r"\b(?:\d[ -]*?){13,19}\b",
                risk=RiskLevel.CRITICAL,
                reason="Payment card number validated by Luhn algorithm. Risk of financial fraud.",
                confidence=0.98,
                validator=luhn_checksum_valid,
            ),
            RegexRule(
                name="Email Address",
                category=SensitiveCategory.EMAIL,
                pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                risk=RiskLevel.CRITICAL,
                reason="Direct personal contact identifier. Critical risk of spear-phishing, credential stuffing, and identity harvesting.",
                confidence=0.95,
            ),
            RegexRule(
                name="Phone Number",
                category=SensitiveCategory.PHONE,
                pattern=r"(?:(?:\+|00)[1-9]\d{0,3}[-.\s]?(?:\d[-.\s]?){7,12}\d|(?:^|(?<=[^\d]))[6-9]\d{4}[-.\s]?\d{5}(?=[^\d]|$)|(?:^|(?<=[^\d]))[6-9]\d{9}(?=[^\d]|$)|(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})",
                risk=RiskLevel.CRITICAL,
                reason="Direct personal contact identifier. Critical risk of SMS phishing, SIM swapping, and harassment.",
                confidence=0.95,
            ),
        ]

    def scan_text(self, text: str) -> List[Finding]:
        """Scan a string of text and return all detected sensitive findings."""
        findings: List[Finding] = []
        if not text:
            return findings

        claimed_spans: List[Tuple[int, int]] = []

        for rule in self.rules:
            for match in rule.regex.finditer(text):
                raw_match = match.group(0).strip()
                span = match.span()

                # If this span overlaps with any previously claimed higher-priority finding, skip it
                if any(spans_overlap(span, existing) for existing in claimed_spans):
                    continue

                # Run custom validator if configured (e.g. Luhn algorithm for cards)
                if rule.validator and not rule.validator(raw_match):
                    continue

                claimed_spans.append(span)
                masked = mask_secret(raw_match)

                finding = Finding(
                    category=rule.category,
                    label=rule.name,
                    confidence=rule.confidence,
                    risk=rule.risk,
                    reason=rule.reason,
                    masked_evidence=masked,
                    recommended_action=RecommendedAction.BLACKOUT,
                    detector_source="deterministic:regex",
                )
                findings.append(finding)

        return findings

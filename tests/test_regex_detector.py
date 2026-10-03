"""Tests for SafeDrop deterministic regex detector."""
import pytest
from app.detectors.regex_detector import RegexDetector, luhn_checksum_valid
from app.model.schemas import RiskLevel, SensitiveCategory


@pytest.fixture
def detector():
    return RegexDetector()


def test_openai_key_detection(detector):
    text = "Here is my key: sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
    findings = detector.scan_text(text)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == SensitiveCategory.API_KEY
    assert f.label == "OpenAI API Key"
    assert f.risk == RiskLevel.CRITICAL
    assert "sk-pro" in f.masked_evidence
    assert "•" in f.masked_evidence
    assert "a1b2c3d4e5f6" not in f.masked_evidence


def test_anthropic_key_detection(detector):
    text = "export ANTHROPIC_API_KEY=sk-ant-api03-abcdef1234567890abcdef1234567890"
    findings = detector.scan_text(text)
    assert len(findings) == 1
    assert findings[0].label == "Anthropic API Key"
    assert findings[0].risk == RiskLevel.CRITICAL


def test_google_key_detection(detector):
    text = "const apiKey = 'AIzaSyA1234567890abcdef1234567890abcdef';"
    findings = detector.scan_text(text)
    assert len(findings) == 1
    assert findings[0].label == "Google AI Key"
    assert findings[0].risk == RiskLevel.CRITICAL


def test_github_token_detection(detector):
    text = "git remote set-url origin https://ghp_111122223333444455556666777788889999@github.com/repo.git"
    findings = detector.scan_text(text)
    # Token matches and overlapping email match on URL authority is cleanly resolved
    assert len(findings) == 1
    assert findings[0].label == "GitHub Personal Access Token"
    assert "•" in findings[0].masked_evidence


def test_aws_key_detection(detector):
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings = detector.scan_text(text)
    assert len(findings) == 1
    assert findings[0].label == "AWS Access Key ID"


def test_jwt_detection(detector):
    text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = detector.scan_text(text)
    assert len(findings) == 1
    assert findings[0].label == "JSON Web Token (JWT)"
    assert findings[0].risk == RiskLevel.HIGH


def test_email_detection(detector):
    text = "Please reach out to support@antigravity.dev for issues."
    findings = detector.scan_text(text)
    assert len(findings) == 1
    assert findings[0].category == SensitiveCategory.EMAIL
    assert findings[0].risk == RiskLevel.LOW


def test_ssn_detection(detector):
    text = "Candidate SSN on file: 123-45-6789"
    findings = detector.scan_text(text)
    assert len(findings) == 1
    assert findings[0].category == SensitiveCategory.GOVERNMENT_ID
    assert findings[0].risk == RiskLevel.CRITICAL


def test_credit_card_luhn_validation(detector):
    # Valid Visa card number passing Luhn checksum
    valid_card = "4532 0150 1234 5671"
    assert luhn_checksum_valid(valid_card) is True

    findings = detector.scan_text(f"Paid with: {valid_card}")
    assert len(findings) == 1
    assert findings[0].category == SensitiveCategory.BANK_DATA
    assert findings[0].label == "Credit Card Number"

    # Invalid sequence of 16 digits (fails Luhn)
    invalid_digits = "1234 5678 1234 5678"
    assert luhn_checksum_valid(invalid_digits) is False

    findings_invalid = detector.scan_text(f"Order ID: {invalid_digits}")
    assert len(findings_invalid) == 0


def test_multiple_findings_in_env_file(detector):
    env_content = """
    OPENAI_API_KEY=sk-proj-99887766554433221100aabbccddeeffgghh
    ADMIN_EMAIL=security@safedrop.local
    SUPPORT_PHONE=+1-555-867-5309
    """
    findings = detector.scan_text(env_content)
    assert len(findings) == 3
    categories = {f.category for f in findings}
    assert SensitiveCategory.API_KEY in categories
    assert SensitiveCategory.EMAIL in categories
    assert SensitiveCategory.PHONE in categories


def test_no_secrets_leaked_in_evidence(detector):
    raw_key = "sk-proj-secretsecretsecretsecretsecretsecret1234"
    findings = detector.scan_text(f"KEY={raw_key}")
    assert len(findings) == 1
    evidence = findings[0].masked_evidence
    # Crucial security guarantee: raw key must never be equal to masked evidence
    assert evidence != raw_key
    assert "•" in evidence
    assert "secretsecretsecret" not in evidence


def test_clean_text_no_findings(detector):
    clean = "This is a public announcement about our new open-source documentation. No credentials here."
    findings = detector.scan_text(clean)
    assert len(findings) == 0

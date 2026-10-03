"""Unit tests for SafeDrop Pydantic schemas and masking utilities."""
import pytest
from pydantic import ValidationError
from app.model.schemas import (
    BoundingBox,
    Finding,
    RecommendedAction,
    RiskLevel,
    RiskReport,
    SensitiveCategory,
    mask_secret,
)


def test_mask_secret_standard_token():
    raw = "sk-live-51NxABCDEF1234567890XYZ"
    masked = mask_secret(raw)
    assert "sk-liv" in masked
    assert "XYZ" in masked
    assert "•" in masked
    assert "51NxABCDEF" not in masked


def test_mask_secret_short_string():
    short = "12345"
    masked = mask_secret(short)
    assert masked == "••••••"


def test_bounding_box_geometry():
    box = BoundingBox(x=10, y=20, width=100, height=50)
    assert box.x2 == 110
    assert box.y2 == 70
    assert box.to_tuple() == (10, 20, 110, 70)


def test_bounding_box_invalid_dimensions():
    with pytest.raises(ValidationError):
        BoundingBox(x=-1, y=0, width=10, height=10)

    with pytest.raises(ValidationError):
        BoundingBox(x=0, y=0, width=0, height=10)


def test_finding_defensive_auto_mask():
    # If a long raw secret without mask is passed, the validator defensively masks it
    raw_secret = "ghp_111122223333444455556666777788889999"
    finding = Finding(
        category=SensitiveCategory.API_KEY,
        label="GitHub Personal Access Token",
        confidence=0.98,
        risk=RiskLevel.CRITICAL,
        reason="Exposes GitHub account access token.",
        masked_evidence=raw_secret,
        location=BoundingBox(x=5, y=5, width=200, height=20),
        recommended_action=RecommendedAction.BLACKOUT,
    )
    assert "•" in finding.masked_evidence
    assert raw_secret not in finding.masked_evidence


def test_finding_invalid_confidence():
    with pytest.raises(ValidationError):
        Finding(
            category=SensitiveCategory.PASSWORD,
            label="Root Password",
            confidence=1.5,  # > 1.0 invalid
            risk=RiskLevel.CRITICAL,
            reason="Unchecked password",
            masked_evidence="••••••",
        )


def test_risk_report_properties_and_serialization():
    finding1 = Finding(
        category=SensitiveCategory.API_KEY,
        label="OpenAI Secret Key",
        confidence=0.99,
        risk=RiskLevel.CRITICAL,
        reason="Full API access",
        masked_evidence="sk-proj-••••••••••••xyz",
        location=BoundingBox(x=10, y=10, width=50, height=15),
    )
    finding2 = Finding(
        category=SensitiveCategory.EMAIL,
        label="Personal Email",
        confidence=0.90,
        risk=RiskLevel.LOW,
        reason="Personal contact detail",
        masked_evidence="user••••@example.com",
    )

    report = RiskReport(
        document_type="terminal_screenshot",
        overall_risk=RiskLevel.CRITICAL,
        findings=[finding1, finding2],
        uncertainty_flags=[],
        safe_to_share_without_changes=False,
        original_file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )

    assert report.finding_count == 2
    assert report.critical_count == 1
    assert report.has_critical_findings is True

    # Test serialization to dict and JSON
    json_data = report.model_dump_json()
    assert "terminal_screenshot" in json_data
    assert "sk-proj-" in json_data
    assert "user••••@example.com" in json_data

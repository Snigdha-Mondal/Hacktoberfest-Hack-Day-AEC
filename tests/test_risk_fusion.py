"""Tests for SafeDrop Risk Fusion Layer and policy calculation."""
import pytest
from app.model.schemas import (
    BoundingBox,
    Finding,
    RecommendedAction,
    RiskLevel,
    RiskReport,
    SensitiveCategory,
)
from app.risk.fusion import (
    calculate_iou,
    boxes_overlap,
    merge_findings,
    fuse_findings,
)
from app.risk.policy import (
    compute_finding_risk,
    CATEGORY_SENSITIVITY,
)


def test_category_sensitivity_definitions():
    assert CATEGORY_SENSITIVITY[SensitiveCategory.API_KEY] == 1.0
    assert CATEGORY_SENSITIVITY[SensitiveCategory.PASSWORD] == 1.0
    assert CATEGORY_SENSITIVITY[SensitiveCategory.BANK_DATA] >= 0.9
    assert CATEGORY_SENSITIVITY[SensitiveCategory.FACE] >= 0.6


def test_compute_finding_risk():
    # Critical API key
    risk_level, score = compute_finding_risk(
        category=SensitiveCategory.API_KEY,
        confidence=1.0,
        exposure=1.0,
    )
    assert risk_level == RiskLevel.CRITICAL
    assert score >= 0.75

    # Phone number with medium confidence
    risk_level, score = compute_finding_risk(
        category=SensitiveCategory.PHONE,
        confidence=0.7,
        exposure=1.0,
    )
    assert risk_level in (RiskLevel.MEDIUM, RiskLevel.LOW)


def test_calculate_iou_and_overlap():
    box1 = BoundingBox(x=10, y=10, width=50, height=50)  # (10, 10, 60, 60)
    box2 = BoundingBox(x=20, y=20, width=50, height=50)  # (20, 20, 70, 70)
    # Intersection: (20, 20, 60, 60) -> 40 x 40 = 1600
    # Area1 = 2500, Area2 = 2500, Union = 5000 - 1600 = 3400
    # IoU = 1600 / 3400 = 0.4705...
    iou = calculate_iou(box1, box2)
    assert 0.46 < iou < 0.48
    assert boxes_overlap(box1, box2, threshold=0.4) is True

    # Disjoint boxes
    box3 = BoundingBox(x=100, y=100, width=50, height=50)
    assert calculate_iou(box1, box3) == 0.0
    assert boxes_overlap(box1, box3) is False


def test_merge_overlapping_findings():
    # Deterministic QR detection
    det_finding = Finding(
        category=SensitiveCategory.QR_CODE,
        label="Wi-Fi QR Code",
        confidence=1.0,
        risk=RiskLevel.HIGH,
        reason="Detected Wi-Fi network credential QR code.",
        masked_evidence="WIFI:S:MyNetwork;P:••••••••;;",
        location=BoundingBox(x=50, y=50, width=100, height=100),
        recommended_action=RecommendedAction.BLACKOUT,
        detector_source="deterministic",
    )

    # Gemma 4 vision finding covering roughly same region
    gemma_finding = Finding(
        category=SensitiveCategory.QR_CODE,
        label="Scannable QR Code",
        confidence=0.92,
        risk=RiskLevel.HIGH,
        reason="Visible QR code in center of card may expose direct access.",
        masked_evidence="[QR CODE]",
        location=BoundingBox(x=48, y=52, width=105, height=98),
        recommended_action=RecommendedAction.BLACKOUT,
        detector_source="gemma4",
    )

    merged = merge_findings(det_finding, gemma_finding)
    assert merged.detector_source == "fused"
    # Keeps the richer deterministic evidence
    assert "WIFI:S:MyNetwork" in merged.masked_evidence
    # Keeps high confidence
    assert merged.confidence == 1.0
    # Merges or preserves the reasoning
    assert "credential" in merged.reason or "access" in merged.reason


def test_fuse_findings_full_pipeline():
    det_findings = [
        Finding(
            category=SensitiveCategory.API_KEY,
            label="OpenAI Secret Key",
            confidence=1.0,
            risk=RiskLevel.CRITICAL,
            reason="High-entropy OpenAI key pattern detected.",
            masked_evidence="sk-proj-••••••••••••abc",
            location=BoundingBox(x=10, y=10, width=200, height=30),
            detector_source="deterministic",
        )
    ]

    model_findings = [
        Finding(
            category=SensitiveCategory.FACE,
            label="Employee Portrait",
            confidence=0.94,
            risk=RiskLevel.MEDIUM,
            reason="Biometric identity visible in badge photo.",
            masked_evidence="[FACE DETECTED]",
            location=BoundingBox(x=300, y=50, width=120, height=150),
            recommended_action=RecommendedAction.BLUR,
            detector_source="gemma4",
        )
    ]

    report = fuse_findings(
        deterministic_findings=det_findings,
        model_findings=model_findings,
        uncertainty_flags=["Low contrast background"],
        original_file_hash="dummyhash12345",
    )

    assert isinstance(report, RiskReport)
    assert report.finding_count == 2
    assert report.overall_risk == RiskLevel.CRITICAL
    assert report.has_critical_findings is True
    assert report.safe_to_share_without_changes is False
    assert len(report.uncertainty_flags) == 1


def test_fuse_findings_empty_is_safe():
    report = fuse_findings(
        deterministic_findings=[],
        model_findings=[],
        uncertainty_flags=[],
        original_file_hash="clean12345",
    )
    assert report.overall_risk == RiskLevel.LOW
    assert report.finding_count == 0
    assert report.safe_to_share_without_changes is True

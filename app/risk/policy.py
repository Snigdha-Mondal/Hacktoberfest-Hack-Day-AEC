"""Risk scoring policy based on sensitivity, exposure, and confidence."""
from __future__ import annotations

from typing import Dict, List, Tuple

from app.model.schemas import Finding, RiskLevel, SensitiveCategory

CATEGORY_SENSITIVITY: Dict[SensitiveCategory, float] = {
    SensitiveCategory.API_KEY: 1.0,
    SensitiveCategory.PASSWORD: 1.0,
    SensitiveCategory.BANK_DATA: 0.95,
    SensitiveCategory.GOVERNMENT_ID: 0.90,
    SensitiveCategory.MEDICAL: 0.85,
    SensitiveCategory.SIGNATURE: 0.80,
    SensitiveCategory.QR_CODE: 0.75,
    SensitiveCategory.EMAIL: 0.90,
    SensitiveCategory.PHONE: 0.90,
    SensitiveCategory.FACE: 0.65,
    SensitiveCategory.ADDRESS: 0.60,
    SensitiveCategory.PRIVATE_TEXT: 0.50,
    SensitiveCategory.OTHER: 0.40,
}

_RISK_ORDER = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 1,
    RiskLevel.UNKNOWN: 0,
}


def compute_finding_risk(
    category: SensitiveCategory,
    confidence: float = 1.0,
    exposure: float = 1.0,
) -> Tuple[RiskLevel, float]:
    """Calculate composite risk score = sensitivity × exposure × confidence.

    Returns:
        (RiskLevel, score) where score is between 0.0 and 1.0
    """
    sensitivity = CATEGORY_SENSITIVITY.get(category, 0.5)
    clamped_conf = max(0.0, min(1.0, float(confidence)))
    clamped_exp = max(0.0, min(1.0, float(exposure)))

    score = round(sensitivity * clamped_exp * clamped_conf, 4)

    if score >= 0.75:
        level = RiskLevel.CRITICAL
    elif score >= 0.50:
        level = RiskLevel.HIGH
    elif score >= 0.30:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    return level, score


def determine_overall_risk(findings: List[Finding]) -> RiskLevel:
    """Determine the highest composite risk level across all findings."""
    if not findings:
        return RiskLevel.LOW

    max_level = RiskLevel.LOW
    for f in findings:
        if _RISK_ORDER.get(f.risk, 0) > _RISK_ORDER.get(max_level, 0):
            max_level = f.risk

    return max_level

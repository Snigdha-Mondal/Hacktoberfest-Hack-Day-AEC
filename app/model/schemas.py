"""SafeDrop data models and validation schemas."""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


def mask_secret(value: str, visible_prefix: int = 6, visible_suffix: int = 3, mask_char: str = "•") -> str:
    """Mask the middle of a sensitive value so raw credentials never appear in evidence.

    Example:
        sk-live-abcdef123456789xyz -> sk-liv••••••••••••xyz
    """
    clean = value.strip()
    if len(clean) <= (visible_prefix + visible_suffix):
        # Short strings get standard 6-bullet mask
        return mask_char * 6

    prefix = clean[:visible_prefix]
    suffix = clean[-visible_suffix:]
    bullets = mask_char * max(6, len(clean) - visible_prefix - visible_suffix)
    return f"{prefix}{bullets}{suffix}"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class SensitiveCategory(str, Enum):
    API_KEY = "api_key"
    PASSWORD = "password"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    GOVERNMENT_ID = "government_id"
    BANK_DATA = "bank_data"
    FACE = "face"
    SIGNATURE = "signature"
    QR_CODE = "qr_code"
    MEDICAL = "medical"
    PRIVATE_TEXT = "private_text"
    OTHER = "other"


class RecommendedAction(str, Enum):
    BLACKOUT = "blackout"
    BLUR = "blur"
    PIXELATE = "pixelate"
    CROP = "crop"
    REVIEW = "review"
    NONE = "none"


class BoundingBox(BaseModel):
    x: int = Field(..., ge=0, description="Top-left X coordinate in pixels")
    y: int = Field(..., ge=0, description="Top-left Y coordinate in pixels")
    width: int = Field(..., gt=0, description="Width in pixels")
    height: int = Field(..., gt=0, description="Height in pixels")

    @property
    def x2(self) -> int:
        return self.x + self.width

    @property
    def y2(self) -> int:
        return self.y + self.height

    def to_tuple(self) -> tuple[int, int, int, int]:
        return (self.x, self.y, self.x2, self.y2)


class Finding(BaseModel):
    category: SensitiveCategory
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk: RiskLevel
    reason: str
    masked_evidence: str = Field(..., description="Masked snippet. Never raw secret!")
    location: Optional[BoundingBox] = None
    recommended_action: RecommendedAction = RecommendedAction.BLACKOUT
    detector_source: str = Field(default="deterministic", description="deterministic, gemma4, or fused")

    @field_validator("masked_evidence")
    @classmethod
    def validate_masked_evidence(cls, v: str) -> str:
        # Enforce that raw credentials aren't passed without some masking if lengthy
        if len(v) > 20 and "•" not in v and "*" not in v and "..." not in v:
            # Auto-mask defensively if caller forgot to mask
            return mask_secret(v)
        return v


class RiskReport(BaseModel):
    document_type: str = "image"
    overall_risk: RiskLevel
    findings: List[Finding] = Field(default_factory=list)
    uncertainty_flags: List[str] = Field(default_factory=list)
    safe_to_share_without_changes: bool = False
    original_file_hash: str

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.CRITICAL)

    @property
    def has_critical_findings(self) -> bool:
        return self.critical_count > 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

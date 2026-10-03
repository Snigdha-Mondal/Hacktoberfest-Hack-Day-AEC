"""Tests for SafeExportPipeline: full non-destructive redaction, EXIF stripping, and export."""
import pathlib
import pytest
from PIL import Image
import piexif

from app.model.schemas import (
    BoundingBox,
    Finding,
    RecommendedAction,
    RiskLevel,
    SensitiveCategory,
)
from app.privacy.file_guard import compute_file_hash, FileOverwriteError
from app.redaction.export import SafeExportPipeline, ExportResult


@pytest.fixture
def mock_document_image(tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a temporary image with EXIF metadata and mock visual content."""
    img_path = tmp_path / "employee_badge.jpg"
    img = Image.new("RGB", (300, 200), color=(240, 240, 240))

    # Add EXIF GPS
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: "N",
        piexif.GPSIFD.GPSLatitude: ((28, 1), (36, 1), (1200, 100)),
        piexif.GPSIFD.GPSLongitudeRef: "E",
        piexif.GPSIFD.GPSLongitude: ((77, 1), (12, 1), (3400, 100)),
    }
    exif_bytes = piexif.dump({"0th": {}, "GPS": gps_ifd, "Exif": {}, "1st": {}, "thumbnail": None})
    img.save(img_path, format="JPEG", exif=exif_bytes)
    return img_path


def test_safe_export_end_to_end(mock_document_image: pathlib.Path):
    pipeline = SafeExportPipeline()
    orig_hash_before = compute_file_hash(mock_document_image)

    findings = [
        Finding(
            category=SensitiveCategory.API_KEY,
            label="OpenAI Secret Key",
            confidence=1.0,
            risk=RiskLevel.CRITICAL,
            reason="Exposed secret token",
            masked_evidence="sk-••••••",
            location=BoundingBox(x=20, y=30, width=150, height=25),
            recommended_action=RecommendedAction.BLACKOUT,
        ),
        Finding(
            category=SensitiveCategory.FACE,
            label="Employee Portrait",
            confidence=0.92,
            risk=RiskLevel.MEDIUM,
            reason="Biometric face",
            masked_evidence="[FACE]",
            location=BoundingBox(x=200, y=50, width=80, height=100),
            recommended_action=RecommendedAction.BLUR,
        ),
    ]

    result: ExportResult = pipeline.export(
        input_path=mock_document_image,
        findings=findings,
    )

    # 1. Output path follows non-destructive naming
    assert result.exported_path.name == "employee_badge-safedrop.jpg"
    assert result.exported_path.exists()
    assert result.exported_path != mock_document_image

    # 2. Original file immutability guaranteed
    assert result.original_hash == orig_hash_before
    assert compute_file_hash(mock_document_image) == orig_hash_before
    assert result.immutable_verified is True

    # 3. Redactions applied and metadata stripped
    assert result.redacted_count == 2
    assert result.metadata_stripped is True

    # 4. Verify output image has no EXIF
    with Image.open(result.exported_path) as exported_img:
        assert exported_img._getexif() is None
        assert exported_img.size == (300, 200)


def test_safe_export_blocks_overwriting_original(mock_document_image: pathlib.Path):
    pipeline = SafeExportPipeline()

    with pytest.raises(FileOverwriteError) as exc_info:
        pipeline.export(
            input_path=mock_document_image,
            findings=[],
            destination_path=mock_document_image,  # Deliberate illegal attempt
        )
    assert "forbidden" in str(exc_info.value).lower()


def test_safe_export_with_action_override(mock_document_image: pathlib.Path):
    pipeline = SafeExportPipeline()

    findings = [
        Finding(
            category=SensitiveCategory.FACE,
            label="Face",
            confidence=0.9,
            risk=RiskLevel.MEDIUM,
            reason="Biometric face",
            masked_evidence="[FACE]",
            location=BoundingBox(x=50, y=50, width=50, height=50),
            recommended_action=RecommendedAction.BLUR,
        )
    ]

    # User overrides finding 0 from BLUR to BLACKOUT
    result = pipeline.export(
        input_path=mock_document_image,
        findings=findings,
        action_overrides={0: RecommendedAction.BLACKOUT},
    )
    assert result.exported_path.exists()

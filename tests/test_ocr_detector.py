"""Unit tests for deterministic OCR detector."""
import tempfile
from pathlib import Path
from PIL import Image, ImageDraw

from app.detectors.ocr_detector import OCRDetector
from app.model.schemas import RiskLevel, SensitiveCategory


def test_ocr_detector_initialization():
    detector = OCRDetector()
    assert detector is not None


def test_ocr_detector_detects_credentials_in_image():
    # Create synthetic image with rendered text
    img = Image.new("RGB", (600, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), "Contact: +1-555-867-5309", fill=(0, 0, 0))
    draw.text((20, 100), "Email: dev@safedrop.io", fill=(0, 0, 0))

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        tmp_path = tmp.name
    img.save(tmp_path)

    try:
        detector = OCRDetector()
        findings = detector.scan_image(tmp_path, 600, 200)

        categories = {f.category for f in findings}
        # RapidOCR should extract either or both phone and email
        assert len(findings) >= 1
        assert any(f.risk == RiskLevel.CRITICAL for f in findings)
        for f in findings:
            assert f.location is not None
            assert f.location.width > 0
            assert f.location.height > 0
            assert f.detector_source == "deterministic_ocr"
    finally:
        if Path(tmp_path).exists():
            Path(tmp_path).unlink()

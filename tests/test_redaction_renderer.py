"""Tests for RedactionRenderer: Solid Blackout, Gaussian Blur, Pixelation, and Crop."""
import pytest
from PIL import Image, ImageDraw
import numpy as np

from app.model.schemas import (
    BoundingBox,
    Finding,
    RecommendedAction,
    RiskLevel,
    SensitiveCategory,
)
from app.redaction.renderer import RedactionRenderer


@pytest.fixture
def test_canvas() -> Image.Image:
    """Create a 200x200 pure white canvas with a black square at (50, 50, 50, 50)."""
    img = Image.new("RGB", (200, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.rectangle([50, 50, 100, 100], fill=(0, 0, 0))
    return img


def test_solid_blackout(test_canvas):
    renderer = RedactionRenderer()
    box = BoundingBox(x=10, y=10, width=30, height=30)
    
    redacted = renderer.apply_action(test_canvas, box, RecommendedAction.BLACKOUT)

    # Check that pixels inside the box are (0, 0, 0)
    arr = np.array(redacted)
    box_region = arr[10:40, 10:40]
    assert np.all(box_region == 0)

    # Check that pixel outside the box is untouched (255, 255, 255)
    assert tuple(arr[5, 5]) == (255, 255, 255)


def test_gaussian_blur(test_canvas):
    renderer = RedactionRenderer()
    # The box covers the boundary between white canvas and black square
    box = BoundingBox(x=40, y=40, width=40, height=40)
    
    original_arr = np.array(test_canvas)[40:80, 40:80]
    redacted = renderer.apply_action(test_canvas, box, RecommendedAction.BLUR, radius=12)
    blurred_arr = np.array(redacted)[40:80, 40:80]

    # Blur smooths the sharp edge so intermediate pixel values appear
    assert not np.array_equal(original_arr, blurred_arr)
    # Unaffected pixel outside box remains untouched
    assert tuple(np.array(redacted)[5, 5]) == (255, 255, 255)


def test_pixelation(test_canvas):
    renderer = RedactionRenderer()
    box = BoundingBox(x=40, y=40, width=40, height=40)

    original_arr = np.array(test_canvas)[40:80, 40:80]
    redacted = renderer.apply_action(test_canvas, box, RecommendedAction.PIXELATE, pixel_size=8)
    pixelated_arr = np.array(redacted)[40:80, 40:80]

    assert not np.array_equal(original_arr, pixelated_arr)
    # Check that pixel outside box is untouched
    assert tuple(np.array(redacted)[5, 5]) == (255, 255, 255)


def test_original_image_not_mutated(test_canvas):
    renderer = RedactionRenderer()
    box = BoundingBox(x=10, y=10, width=20, height=20)
    original_copy = test_canvas.copy()

    redacted = renderer.apply_action(test_canvas, box, RecommendedAction.BLACKOUT)

    # test_canvas must NOT have changed
    assert np.array_equal(np.array(test_canvas), np.array(original_copy))
    # redacted image must be different
    assert not np.array_equal(np.array(redacted), np.array(original_copy))


def test_apply_findings_batch(test_canvas):
    renderer = RedactionRenderer()
    findings = [
        Finding(
            category=SensitiveCategory.API_KEY,
            label="API Key",
            confidence=1.0,
            risk=RiskLevel.CRITICAL,
            reason="Exposed token",
            masked_evidence="sk-••••••",
            location=BoundingBox(x=10, y=10, width=30, height=20),
            recommended_action=RecommendedAction.BLACKOUT,
        ),
        Finding(
            category=SensitiveCategory.FACE,
            label="Face",
            confidence=0.9,
            risk=RiskLevel.MEDIUM,
            reason="Biometric face",
            masked_evidence="[FACE]",
            location=BoundingBox(x=120, y=120, width=40, height=40),
            recommended_action=RecommendedAction.BLUR,
        ),
    ]

    redacted = renderer.apply_findings(test_canvas, findings)

    arr = np.array(redacted)
    # Box 1 is blacked out
    assert np.all(arr[10:30, 10:40] == 0)
    # Canvas dimension preserved
    assert redacted.size == test_canvas.size

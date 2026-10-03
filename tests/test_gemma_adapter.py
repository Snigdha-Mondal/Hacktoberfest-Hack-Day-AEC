"""Unit tests for GemmaVisionAdapter."""
import os
import tempfile
from unittest.mock import MagicMock, patch
import pytest
from PIL import Image

from app.model.gemma_adapter import GemmaVisionAdapter
from app.model.schemas import Finding, SensitiveCategory, RiskLevel, RecommendedAction


@pytest.fixture
def sample_image():
    """Create a temporary 200x100 test image."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        path = tmp.name

    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    img.save(path, format="PNG")
    yield path

    if os.path.exists(path):
        os.remove(path)


def test_adapter_initialization():
    adapter = GemmaVisionAdapter(
        base_url="http://localhost:11434",
        model="gemma4:e4b",
        timeout=30.0,
    )
    assert adapter.base_url == "http://localhost:11434"
    assert adapter.model == "gemma4:e4b"
    assert adapter.timeout == 30.0


def test_adapter_analyze_image_success(sample_image):
    adapter = GemmaVisionAdapter()

    mock_response_json = {
        "message": {
            "role": "assistant",
            "content": """```json
{
  "findings": [
    {
      "category": "face",
      "label": "Passport Face",
      "confidence": 0.98,
      "risk": "high",
      "reason": "Visible biometric portrait on ID document.",
      "masked_evidence": "[FACE DETECTED]",
      "box_2d": [100, 100, 900, 900],
      "uncertainty_flag": false,
      "recommended_action": "blur"
    }
  ],
  "uncertainty_flags": [],
  "summary": "1 face found"
}
```""",
        }
    }

    mock_res = MagicMock()
    mock_res.status_code = 200
    mock_res.json.return_value = mock_response_json

    with patch("httpx.Client.post", return_value=mock_res) as mock_post:
        findings, flags, summary = adapter.analyze_image(sample_image, context_hint="Passport")

        assert len(findings) == 1
        f = findings[0]
        assert f.category == SensitiveCategory.FACE
        assert f.risk == RiskLevel.HIGH
        assert f.recommended_action == RecommendedAction.BLUR
        assert f.detector_source == "gemma4"
        # BoundingBox should be scaled to 200x100
        assert f.location is not None
        assert f.location.width > 0
        assert f.location.height > 0
        assert summary == "1 face found"

        # Verify POST payload
        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs["json"]
        assert payload["model"] == "gemma4:e4b"
        assert len(payload["messages"]) == 2
        assert len(payload["messages"][1]["images"]) == 1


def test_adapter_ollama_connection_error_graceful_degrade(sample_image):
    adapter = GemmaVisionAdapter()

    import httpx
    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
        findings, flags, summary = adapter.analyze_image(sample_image)

        assert len(findings) == 0
        assert len(flags) >= 1
        assert any("Ollama connection failed" in flag for flag in flags)
        assert "degraded" in summary.lower() or "offline" in summary.lower() or "unavailable" in summary.lower()


def test_adapter_ollama_http_error(sample_image):
    adapter = GemmaVisionAdapter()

    mock_res = MagicMock()
    mock_res.status_code = 500
    mock_res.text = "Internal Server Error"

    with patch("httpx.Client.post", return_value=mock_res):
        findings, flags, summary = adapter.analyze_image(sample_image)

        assert len(findings) == 0
        assert len(flags) >= 1
        assert any("HTTP 500" in flag for flag in flags)


def test_adapter_nonexistent_file():
    adapter = GemmaVisionAdapter()
    findings, flags, summary = adapter.analyze_image("non_existent_file_12345.png")
    assert len(findings) == 0
    assert len(flags) >= 1
    assert any("File not found" in flag for flag in flags)

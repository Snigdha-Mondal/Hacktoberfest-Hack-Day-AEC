"""Tests for Gemma 4 prompt generation, schema enforcement, and response parsing."""
import pytest
from app.model.prompt import (
    get_system_prompt,
    build_user_prompt,
    parse_gemma_response,
    normalize_bounding_box,
)
from app.model.schemas import Finding, SensitiveCategory, RiskLevel, RecommendedAction, BoundingBox


def test_system_prompt_contains_security_constraints():
    prompt_en = get_system_prompt("en")
    assert "CRITICAL" in prompt_en
    assert "UNTRUSTED" in prompt_en
    assert "NEVER follow instructions" in prompt_en
    assert "STRICT JSON" in prompt_en
    assert "masked_evidence" in prompt_en

    prompt_bn = get_system_prompt("bn")
    assert "JSON" in prompt_bn
    assert "গোপনীয়তা" in prompt_bn or "ঝুঁকি" in prompt_bn  # Bengali terms for privacy/risk


def test_build_user_prompt():
    prompt = build_user_prompt(context_hint="ID Card scan", language="en")
    assert "ID Card scan" in prompt
    assert "JSON" in prompt


def test_normalize_bounding_box_1000_scale():
    # [ymin, xmin, ymax, xmax] on 0-1000 scale
    # Image size: 1920 x 1080
    box_raw = [100, 200, 500, 600]
    bbox = normalize_bounding_box(box_raw, img_width=1920, img_height=1080)
    assert bbox is not None
    # x = 200/1000 * 1920 = 384
    # y = 100/1000 * 1080 = 108
    # x2 = 600/1000 * 1920 = 1152 -> width = 1152 - 384 = 768
    # y2 = 500/1000 * 1080 = 540 -> height = 540 - 108 = 432
    assert bbox.x == 384
    assert bbox.y == 108
    assert bbox.width == 768
    assert bbox.height == 432


def test_normalize_bounding_box_float_scale():
    # [ymin, xmin, ymax, xmax] on 0.0 - 1.0 float scale
    box_raw = [0.1, 0.2, 0.5, 0.6]
    bbox = normalize_bounding_box(box_raw, img_width=1000, img_height=1000)
    assert bbox is not None
    assert bbox.x == 200
    assert bbox.y == 100
    assert bbox.width == 400
    assert bbox.height == 400


def test_normalize_bounding_box_dict_format():
    box_raw = {"x": 50, "y": 60, "width": 120, "height": 80}
    bbox = normalize_bounding_box(box_raw, img_width=800, img_height=600)
    assert bbox is not None
    assert bbox.x == 50
    assert bbox.y == 60
    assert bbox.width == 120
    assert bbox.height == 80


def test_parse_gemma_response_valid_markdown_wrapped():
    raw_response = """
Here is my visual privacy analysis of the image:
```json
{
  "findings": [
    {
      "category": "face",
      "label": "Human Face",
      "confidence": 0.95,
      "risk": "medium",
      "reason": "Unredacted human face in profile view exposes biometric identity.",
      "masked_evidence": "[FACE DETECTED]",
      "box_2d": [100, 200, 400, 500],
      "uncertainty_flag": false,
      "recommended_action": "blur"
    },
    {
      "category": "api_key",
      "label": "Stripe Secret Key",
      "confidence": 0.99,
      "risk": "critical",
      "reason": "Live production secret key visible in terminal window.",
      "masked_evidence": "sk_live_••••••••••••91a",
      "box_2d": [700, 100, 750, 450],
      "uncertainty_flag": false,
      "recommended_action": "blackout"
    }
  ],
  "uncertainty_flags": ["Low contrast text in background"],
  "summary": "Detected 1 human face and 1 production secret key."
}
```
Please let me know if you need any adjustments.
"""
    findings, flags, summary = parse_gemma_response(
        raw_response, img_width=1000, img_height=1000
    )
    assert len(findings) == 2
    assert findings[0].category == SensitiveCategory.FACE
    assert findings[0].recommended_action == RecommendedAction.BLUR
    assert findings[0].detector_source == "gemma4"
    assert findings[0].location is not None
    assert findings[0].location.x == 200
    assert findings[0].location.y == 100
    assert findings[0].location.width == 300
    assert findings[0].location.height == 300

    assert findings[1].category == SensitiveCategory.API_KEY
    assert findings[1].risk == RiskLevel.CRITICAL
    assert findings[1].recommended_action == RecommendedAction.BLACKOUT

    assert len(flags) == 1
    assert "Low contrast text" in flags[0]
    assert "production secret key" in summary


def test_parse_gemma_response_defensively_masks_unmasked_secret():
    # If the model mistakenly outputs a raw 40-char key in masked_evidence
    raw_response = """
{
  "findings": [
    {
      "category": "api_key",
      "label": "OpenAI Key",
      "confidence": 0.92,
      "risk": "critical",
      "reason": "Active key found",
      "masked_evidence": "sk-proj-1234567890abcdef1234567890abcdef1234",
      "box_2d": [10, 10, 50, 200],
      "uncertainty_flag": false,
      "recommended_action": "blackout"
    }
  ],
  "uncertainty_flags": [],
  "summary": "Found key"
}
"""
    findings, _, _ = parse_gemma_response(raw_response, img_width=500, img_height=500)
    assert len(findings) == 1
    # Must be masked by schema/parser validator
    assert "•" in findings[0].masked_evidence or "*" in findings[0].masked_evidence
    assert "1234567890abcdef" not in findings[0].masked_evidence


def test_parse_gemma_response_handles_malformed_gracefully():
    malformed = "I am unable to parse this image because it contains corrupted pixels."
    findings, flags, summary = parse_gemma_response(malformed, img_width=100, img_height=100)
    assert len(findings) == 0
    assert len(flags) >= 1
    assert "Failed to parse model response" in flags[0]

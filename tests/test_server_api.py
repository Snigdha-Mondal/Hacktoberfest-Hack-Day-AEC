"""Tests for SafeDrop FastAPI backend server and preflight endpoints."""
import io
import pathlib
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.server import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_test_image_bytes() -> bytes:
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_server_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "SafeDrop" in data["engine"]


def test_server_index_serves_html(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SafeDrop" in res.text


def test_server_scan_and_preview_flow(client, sample_test_image_bytes):
    from unittest.mock import patch
    from app.model.schemas import Finding, SensitiveCategory, RiskLevel, RecommendedAction, BoundingBox

    mock_finding = Finding(
        category=SensitiveCategory.API_KEY,
        label="Test API Key",
        confidence=1.0,
        risk=RiskLevel.CRITICAL,
        reason="Found test token",
        masked_evidence="sk-test••••••",
        location=BoundingBox(x=10, y=10, width=50, height=20),
        recommended_action=RecommendedAction.BLACKOUT,
    )

    with patch("app.model.gemma_adapter.GemmaVisionAdapter.analyze_image", return_value=([mock_finding], [], "Found 1 key")):
        # 1. Upload & Scan
        files = {"file": ("test_card.png", sample_test_image_bytes, "image/png")}
        scan_res = client.post("/api/scan", files=files)
        assert scan_res.status_code == 200
        data = scan_res.json()

        assert "file_id" in data
        assert data["file_name"] == "test_card.png"
        assert "report" in data
        assert "image_data" in data
        file_id = data["file_id"]

        # 2. Preview Redaction
        preview_res = client.post(
            "/api/preview",
            json={"file_id": file_id, "action_overrides": {}},
        )
        assert preview_res.status_code == 200
        preview_data = preview_res.json()
        assert "preview_data" in preview_data
        assert preview_data["preview_data"].startswith("data:image/png;base64,")

        # 3. Export Safe Copy
        export_res = client.post(
            "/api/export",
            json={"file_id": file_id, "action_overrides": {}},
        )
        assert export_res.status_code == 200
        assert "test_card-safedrop.png" in export_res.headers.get("content-disposition", "")
        assert len(export_res.content) > 0


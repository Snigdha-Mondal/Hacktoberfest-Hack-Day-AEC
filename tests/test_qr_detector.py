"""Tests for QR code detector and payload risk evaluation."""
import io
import qrcode
from PIL import Image
from app.detectors.qr_detector import QRDetector
from app.model.schemas import RiskLevel, SensitiveCategory


def create_qr_image(payload: str) -> bytes:
    """Helper to generate an in-memory PNG containing a QR code."""
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    output = io.BytesIO()
    img.save(output, format="PNG")
    return output.getvalue()


def test_qr_detection_wifi_credentials():
    detector = QRDetector()
    wifi_payload = "WIFI:S:MyGuestNetwork;T:WPA;P:SuperSecretPass123;;"
    img_bytes = create_qr_image(wifi_payload)

    findings = detector.scan_image(img_bytes)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == SensitiveCategory.QR_CODE
    assert f.risk == RiskLevel.HIGH
    assert "Wi-Fi" in f.reason
    assert f.location is not None
    assert f.location.width > 20
    assert f.location.height > 20
    # Ensure payload is masked in evidence
    assert "SuperSecretPass123" not in f.masked_evidence
    assert "•" in f.masked_evidence or "*" in f.masked_evidence


def test_qr_detection_otpauth_2fa_secret():
    detector = QRDetector()
    otp_payload = "otpauth://totp/Acme:user@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Acme"
    img_bytes = create_qr_image(otp_payload)

    findings = detector.scan_image(img_bytes)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == SensitiveCategory.QR_CODE
    assert f.risk == RiskLevel.CRITICAL
    assert "2-Factor" in f.reason
    assert "HXDMVJECJJW" not in f.masked_evidence


def test_qr_detection_clean_image():
    detector = QRDetector()
    # Plain white image
    img = Image.new("RGB", (200, 200), color="white")
    output = io.BytesIO()
    img.save(output, format="PNG")

    findings = detector.scan_image(output.getvalue())
    assert len(findings) == 0

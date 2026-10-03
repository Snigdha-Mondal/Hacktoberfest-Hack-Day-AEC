"""QR Code and 2D barcode detector with payload risk classification."""
import io
import cv2
import numpy as np
from typing import List, Any, Optional
from PIL import Image
from app.model.schemas import Finding, SensitiveCategory, RiskLevel, RecommendedAction, BoundingBox, mask_secret


class QRDetector:
    """Detects QR codes in images, decodes their payload, extracts bounding boxes, and assesses risk."""

    def __init__(self):
        self.cv_detector = cv2.QRCodeDetector()

    def scan_image(self, image_input: Any) -> List[Finding]:
        """Scan an image for QR codes and return findings with exact bounding boxes."""
        findings: List[Finding] = []

        try:
            # Convert various inputs to BGR OpenCV image
            cv_img: Optional[np.ndarray] = None
            if isinstance(image_input, str):
                cv_img = cv2.imread(image_input)
            elif isinstance(image_input, bytes):
                nparr = np.frombuffer(image_input, np.uint8)
                cv_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            elif isinstance(image_input, io.BytesIO):
                nparr = np.frombuffer(image_input.getvalue(), np.uint8)
                cv_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            elif isinstance(image_input, Image.Image):
                rgb_img = image_input.convert("RGB")
                cv_img = cv2.cvtColor(np.array(rgb_img), cv2.COLOR_RGB2BGR)
            elif isinstance(image_input, np.ndarray):
                cv_img = image_input

            if cv_img is None:
                return findings

            # Detect multiple QR codes if present
            success, decoded_info, points, _ = self.cv_detector.detectAndDecodeMulti(cv_img)
            if not success or points is None or len(points) == 0:
                # Try single code fallback
                text, points_single, _ = self.cv_detector.detectAndDecode(cv_img)
                if points_single is not None and len(points_single) > 0 and text:
                    decoded_info = [text]
                    points = [points_single[0]]
                else:
                    return findings

            for i, payload in enumerate(decoded_info):
                if not payload:
                    continue

                # Compute bounding box from corners
                pts = points[i]
                x_coords = pts[:, 0]
                y_coords = pts[:, 1]
                x_min = max(0, int(np.min(x_coords)))
                y_min = max(0, int(np.min(y_coords)))
                x_max = int(np.max(x_coords))
                y_max = int(np.max(y_coords))
                w = max(1, x_max - x_min)
                h = max(1, y_max - y_min)

                bbox = BoundingBox(x=x_min, y=y_min, width=w, height=h)

                # Classify payload sensitivity
                payload_lower = payload.lower()
                risk = RiskLevel.MEDIUM
                reason = "QR code contains encoded text or URL which may expose hidden information."

                if "otpauth://" in payload_lower or "secret=" in payload_lower:
                    risk = RiskLevel.CRITICAL
                    reason = "2-Factor Authentication (TOTP) seed or security credential."
                elif "wifi:" in payload_lower or "wpa" in payload_lower:
                    risk = RiskLevel.HIGH
                    reason = "Wi-Fi network configuration or security passphrase."
                elif "token=" in payload_lower or "api_key=" in payload_lower or "auth" in payload_lower:
                    risk = RiskLevel.CRITICAL
                    reason = "Authentication token or session parameter embedded in QR code."
                elif payload_lower.startswith("http://") or payload_lower.startswith("https://"):
                    risk = RiskLevel.MEDIUM
                    reason = "Web destination URL."

                # Mask payload for evidence
                masked_payload = mask_secret(payload)

                findings.append(
                    Finding(
                        category=SensitiveCategory.QR_CODE,
                        label="Scannable QR Code",
                        confidence=0.98,
                        risk=risk,
                        reason=reason,
                        masked_evidence=f"Payload: {masked_payload}",
                        location=bbox,
                        recommended_action=RecommendedAction.BLACKOUT,
                        detector_source="deterministic:qr",
                    )
                )

        except Exception:
            # Corrupted image or processing error degrades safely
            pass

        return findings

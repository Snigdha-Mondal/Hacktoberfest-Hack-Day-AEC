"""Deterministic OCR detector for text, credentials, and PII found in images."""
from pathlib import Path
from typing import List, Union

from app.detectors.regex_detector import RegexDetector
from app.model.schemas import (
    BoundingBox,
    Finding,
    RecommendedAction,
    RiskLevel,
    SensitiveCategory,
)


_SHARED_ENGINE = None


class OCRDetector:
    """Extracts text regions from images using local ONNX RapidOCR and evaluates findings via RegexDetector."""

    def __init__(self):
        self._regex_detector = RegexDetector()

    def _get_engine(self):
        global _SHARED_ENGINE
        if _SHARED_ENGINE is None:
            try:
                from rapidocr_onnxruntime import RapidOCR

                _SHARED_ENGINE = RapidOCR()
            except Exception:
                _SHARED_ENGINE = False
        return _SHARED_ENGINE if _SHARED_ENGINE is not False else None

    def scan_image(
        self, image_path: Union[str, Path], img_width: int, img_height: int
    ) -> List[Finding]:
        """Scan an image file with local OCR and extract sensitive findings with exact pixel bounding boxes."""
        findings: List[Finding] = []
        engine = self._get_engine()
        if not engine:
            return findings

        try:
            results, _ = engine(str(image_path))
        except Exception:
            return findings

        if not results:
            return findings

        for item in results:
            box_points, text, score = item
            if not text or not str(text).strip():
                continue

            # Run regex detector on the OCR text line
            text_findings = self._regex_detector.scan_text(str(text))
            if not text_findings:
                continue

            # Convert box_points: [[x1, y1], [x2, y2], [x3, y3], [x4, y4]] to integer pixel BoundingBox
            xs = [p[0] for p in box_points]
            ys = [p[1] for p in box_points]
            bx = max(0, int(min(xs)))
            by = max(0, int(min(ys)))
            bw = max(1, min(img_width - bx, int(max(xs) - min(xs))))
            bh = max(1, min(img_height - by, int(max(ys) - min(ys))))

            pixel_box = BoundingBox(x=bx, y=by, width=bw, height=bh)

            conf_val = 0.95
            if isinstance(score, (int, float)):
                conf_val = float(score)
            elif isinstance(score, str):
                try:
                    conf_val = float(score)
                except ValueError:
                    conf_val = 0.95

            for tf in text_findings:
                f = Finding(
                    category=tf.category,
                    label=tf.label,
                    confidence=round(min(conf_val, tf.confidence), 2),
                    risk=tf.risk,
                    recommended_action=tf.recommended_action,
                    reason=f"OCR extracted {tf.category.value}: {tf.reason}",
                    masked_evidence=tf.masked_evidence,
                    location=pixel_box,
                    detector_source="deterministic_ocr",
                )
                findings.append(f)

        return findings

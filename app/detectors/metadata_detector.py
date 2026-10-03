"""Detector for EXIF, GPS, and device metadata embedded in image files."""
import io
from typing import List, Dict, Any, Optional
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from app.model.schemas import Finding, SensitiveCategory, RiskLevel, RecommendedAction, mask_secret


def _convert_to_degrees(value) -> float:
    """Helper function to convert GPS coordinates stored as IFD rationals to decimal degrees."""
    try:
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return 0.0


def mask_gps_coord(coord: float) -> str:
    """Mask decimal coordinates to preserve broad area while hiding precise location."""
    coord_str = f"{coord:.6f}"
    parts = coord_str.split(".")
    if len(parts) == 2:
        return f"{parts[0]}.{parts[1][:2]}****"
    return f"{coord_str[:4]}****"


class MetadataDetector:
    """Extracts and evaluates privacy risks from image EXIF/GPS metadata."""

    def scan_image(self, image_input: Any) -> List[Finding]:
        """Scan an image file path, file-like object, or PIL Image for sensitive metadata."""
        findings: List[Finding] = []
        img: Optional[Image.Image] = None

        try:
            if isinstance(image_input, (str, bytes, io.BytesIO)):
                if isinstance(image_input, bytes):
                    image_input = io.BytesIO(image_input)
                img = Image.open(image_input)
            elif isinstance(image_input, Image.Image):
                img = image_input
            else:
                return findings

            exif_raw = img.getexif()
            if not exif_raw:
                return findings

            # 1. Check for GPS Info
            # In PIL, IFD 0x8825 (34853) is GPSInfo
            gps_ifd = exif_raw.get_ifd(0x8825)
            if gps_ifd:
                gps_data = {}
                for tag_id, value in gps_ifd.items():
                    tag_name = GPSTAGS.get(tag_id, str(tag_id))
                    gps_data[tag_name] = value

                lat = gps_data.get("GPSLatitude")
                lat_ref = gps_data.get("GPSLatitudeRef", "N")
                lon = gps_data.get("GPSLongitude")
                lon_ref = gps_data.get("GPSLongitudeRef", "E")

                if lat and lon:
                    lat_deg = _convert_to_degrees(lat)
                    if str(lat_ref).upper() == "S":
                        lat_deg = -lat_deg

                    lon_deg = _convert_to_degrees(lon)
                    if str(lon_ref).upper() == "W":
                        lon_deg = -lon_deg

                    masked_lat = mask_gps_coord(lat_deg)
                    masked_lon = mask_gps_coord(lon_deg)
                    findings.append(
                        Finding(
                            category=SensitiveCategory.ADDRESS,
                            label="EXIF GPS Coordinates",
                            confidence=1.0,
                            risk=RiskLevel.HIGH,
                            reason="Precise GPS coordinates embedded in image metadata reveal physical location.",
                            masked_evidence=f"Lat: {masked_lat}, Lon: {masked_lon}",
                            recommended_action=RecommendedAction.REVIEW,
                            detector_source="deterministic:exif_gps",
                        )
                    )

            # 2. Check for Device & Author Metadata
            device_info = []
            author_info = []

            for tag_id, value in exif_raw.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                val_str = str(value).strip()
                if not val_str:
                    continue

                if tag_name in ("Make", "Model"):
                    device_info.append(f"{tag_name}: {val_str}")
                elif tag_name in ("BodySerialNumber", "LensSerialNumber"):
                    device_info.append(f"Serial: {mask_secret(val_str)}")
                elif tag_name in ("Artist", "Copyright", "XPAuthor"):
                    author_info.append(f"{tag_name}: {mask_secret(val_str)}")

            if device_info:
                findings.append(
                    Finding(
                        category=SensitiveCategory.OTHER,
                        label="Camera / Device Metadata",
                        confidence=0.95,
                        risk=RiskLevel.LOW,
                        reason="Hardware and software metadata can be used to fingerprint your personal devices.",
                        masked_evidence="; ".join(device_info),
                        recommended_action=RecommendedAction.REVIEW,
                        detector_source="deterministic:exif_device",
                    )
                )

            if author_info:
                findings.append(
                    Finding(
                        category=SensitiveCategory.OTHER,
                        label="Author / Copyright Metadata",
                        confidence=0.95,
                        risk=RiskLevel.LOW,
                        reason="Creator or owner identity embedded in image file properties.",
                        masked_evidence="; ".join(author_info),
                        recommended_action=RecommendedAction.REVIEW,
                        detector_source="deterministic:exif_author",
                    )
                )

        except Exception:
            # Corrupted or unreadable EXIF should degrade gracefully
            pass

        return findings

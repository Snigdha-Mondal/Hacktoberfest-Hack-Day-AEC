"""Tests for EXIF, GPS, and device metadata detector."""
import io
import piexif
from PIL import Image
from app.detectors.metadata_detector import MetadataDetector
from app.model.schemas import RiskLevel, SensitiveCategory


def create_image_with_exif(include_gps: bool = True, include_device: bool = True) -> bytes:
    """Helper to generate an in-memory JPEG with custom EXIF tags."""
    img = Image.new("RGB", (100, 100), color=(73, 109, 137))
    exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}

    if include_device:
        exif_dict["0th"][piexif.ImageIFD.Make] = "Nikon"
        exif_dict["0th"][piexif.ImageIFD.Model] = "D850"
        exif_dict["0th"][piexif.ImageIFD.Artist] = "Jane Doe"

    if include_gps:
        # 37° 46' 29.64" N, 122° 25' 9.84" W (San Francisco)
        exif_dict["GPS"][piexif.GPSIFD.GPSLatitudeRef] = "N"
        exif_dict["GPS"][piexif.GPSIFD.GPSLatitude] = ((37, 1), (46, 1), (2964, 100))
        exif_dict["GPS"][piexif.GPSIFD.GPSLongitudeRef] = "W"
        exif_dict["GPS"][piexif.GPSIFD.GPSLongitude] = ((122, 1), (25, 1), (984, 100))

    exif_bytes = piexif.dump(exif_dict)
    output = io.BytesIO()
    img.save(output, format="JPEG", exif=exif_bytes)
    return output.getvalue()


def test_gps_metadata_detection():
    detector = MetadataDetector()
    img_bytes = create_image_with_exif(include_gps=True, include_device=False)
    findings = detector.scan_image(img_bytes)

    assert len(findings) == 1
    gps_finding = findings[0]
    assert gps_finding.category == SensitiveCategory.ADDRESS
    assert gps_finding.risk == RiskLevel.HIGH
    assert gps_finding.label == "EXIF GPS Coordinates"
    assert "Lat:" in gps_finding.masked_evidence
    assert "****" in gps_finding.masked_evidence  # Masked coordinates


def test_device_metadata_detection():
    detector = MetadataDetector()
    img_bytes = create_image_with_exif(include_gps=False, include_device=True)
    findings = detector.scan_image(img_bytes)

    assert len(findings) >= 1
    labels = [f.label for f in findings]
    assert "Camera / Device Metadata" in labels
    assert "Author / Copyright Metadata" in labels


def test_clean_image_without_exif():
    detector = MetadataDetector()
    # Plain image with no metadata
    img = Image.new("RGB", (50, 50), color="white")
    output = io.BytesIO()
    img.save(output, format="JPEG")

    findings = detector.scan_image(output.getvalue())
    assert len(findings) == 0

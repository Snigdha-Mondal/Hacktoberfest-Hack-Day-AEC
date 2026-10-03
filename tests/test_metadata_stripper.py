"""Tests for MetadataStripper: removing all EXIF, GPS, and device metadata."""
import io
import pathlib
import pytest
from PIL import Image
import piexif

from app.redaction.metadata_strip import strip_metadata, strip_metadata_from_file
from app.detectors.metadata_detector import MetadataDetector
from app.privacy.file_guard import compute_file_hash


@pytest.fixture
def image_with_exif(tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a temporary JPEG file containing GPS and device metadata."""
    img_path = tmp_path / "photo_with_gps.jpg"
    img = Image.new("RGB", (120, 80), color=(100, 150, 200))

    # Add 0th and GPS IFD
    zeroth_ifd = {
        piexif.ImageIFD.Make: b"Apple",
        piexif.ImageIFD.Model: b"iPhone 15 Pro",
    }
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: "N",
        piexif.GPSIFD.GPSLatitude: ((37, 1), (46, 1), (3000, 100)),
        piexif.GPSIFD.GPSLongitudeRef: "W",
        piexif.GPSIFD.GPSLongitude: ((122, 1), (25, 1), (600, 100)),
    }
    exif_dict = {"0th": zeroth_ifd, "GPS": gps_ifd, "Exif": {}, "1st": {}, "thumbnail": None}
    exif_bytes = piexif.dump(exif_dict)
    img.save(img_path, format="JPEG", exif=exif_bytes)

    return img_path


def test_strip_metadata_in_memory(image_with_exif):
    with Image.open(image_with_exif) as img:
        assert img._getexif() is not None  # Has EXIF initially
        clean = strip_metadata(img)

    # In-memory clean copy has identical dimensions and RGB mode
    assert clean.size == (120, 80)
    assert clean.mode == "RGB"

    # Verify that saving clean image produces zero EXIF
    buf = io.BytesIO()
    clean.save(buf, format="JPEG")
    buf.seek(0)
    with Image.open(buf) as reloaded:
        assert reloaded._getexif() is None


def test_strip_metadata_from_file_preserves_original(image_with_exif, tmp_path):
    output_path = tmp_path / "photo_with_gps-safedrop.jpg"
    original_hash_before = compute_file_hash(image_with_exif)

    # Verify original has metadata detected
    detector = MetadataDetector()
    original_findings = detector.scan_image(str(image_with_exif))
    assert len(original_findings) >= 2  # GPS + Device

    # Strip metadata and export to output_path
    saved_path = strip_metadata_from_file(image_with_exif, output_path)
    assert saved_path == output_path

    # Crucial guarantee: Original file hash is byte-for-byte identical!
    assert compute_file_hash(image_with_exif) == original_hash_before

    # Output file has zero metadata findings
    sanitized_findings = detector.scan_image(str(output_path))
    assert len(sanitized_findings) == 0

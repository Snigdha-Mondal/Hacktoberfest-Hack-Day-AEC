"""Tests guaranteeing input file immutability and zero-overwrite protection."""
import io
import pathlib
import pytest
from PIL import Image
from app.detectors.metadata_detector import MetadataDetector
from app.detectors.regex_detector import RegexDetector
from app.detectors.qr_detector import QRDetector
from app.privacy.file_guard import FileGuard, FileOverwriteError, compute_file_hash


@pytest.fixture
def sample_test_image(tmp_path: pathlib.Path) -> pathlib.Path:
    """Create a temporary real PNG image file for immutability testing."""
    image_path = tmp_path / "developer_screenshot.png"
    img = Image.new("RGB", (150, 150), color=(50, 120, 200))
    img.save(image_path, format="PNG")
    return image_path


def test_compute_file_hash(sample_test_image: pathlib.Path):
    hash1 = compute_file_hash(sample_test_image)
    assert len(hash1) == 64
    assert all(c in "0123456789abcdef" for c in hash1)

    # Test byte hashing matches
    with open(sample_test_image, "rb") as f:
        hash2 = compute_file_hash(f.read())
    assert hash1 == hash2


def test_file_guard_verification(sample_test_image: pathlib.Path):
    guard = FileGuard(sample_test_image)
    assert guard.verify_unmodified() is True


def test_file_guard_detects_tampering(sample_test_image: pathlib.Path):
    guard = FileGuard(sample_test_image)

    # Simulate accidental modification
    with open(sample_test_image, "ab") as f:
        f.write(b"accidental_corruption_byte")

    with pytest.raises(FileOverwriteError) as exc_info:
        guard.verify_unmodified()
    assert "CRITICAL PRIVACY VIOLATION" in str(exc_info.value)


def test_safe_output_path_generation(sample_test_image: pathlib.Path):
    guard = FileGuard(sample_test_image)
    safe_path = guard.generate_safe_output_path()

    assert safe_path != sample_test_image
    assert safe_path.name == "developer_screenshot-safedrop.png"
    assert safe_path.parent == sample_test_image.parent


def test_safe_output_path_increment_when_exists(sample_test_image: pathlib.Path):
    guard = FileGuard(sample_test_image)

    # Create the first safedrop file on disk
    first_safedrop = sample_test_image.parent / "developer_screenshot-safedrop.png"
    first_safedrop.touch()

    # The guard should automatically increment to -1
    second_safedrop = guard.generate_safe_output_path()
    assert second_safedrop.name == "developer_screenshot-safedrop-1.png"


def test_validate_destination_path_blocks_original(sample_test_image: pathlib.Path):
    guard = FileGuard(sample_test_image)

    # Attempting to use the original path as the destination must fail
    with pytest.raises(FileOverwriteError) as exc_info:
        guard.validate_destination_path(sample_test_image)
    assert "forbidden" in str(exc_info.value)


def test_detectors_preserve_original_file_hash(sample_test_image: pathlib.Path):
    """End-to-end immutability test: Run all detectors on the file and prove hash equality."""
    guard = FileGuard(sample_test_image)
    initial_hash = guard.initial_hash

    # Run MetadataDetector
    meta_detector = MetadataDetector()
    meta_detector.scan_image(str(sample_test_image))

    # Run QRDetector
    qr_detector = QRDetector()
    qr_detector.scan_image(str(sample_test_image))

    # Run RegexDetector on text dump
    regex_detector = RegexDetector()
    regex_detector.scan_text("sk-proj-test1234567890abcdef1234567890")

    # Cryptographically verify the file on disk was not altered
    assert compute_file_hash(sample_test_image) == initial_hash
    assert guard.verify_unmodified() is True

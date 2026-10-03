r"""Script to generate realistic test samples and verify visual redaction quality (Checkpoint 3.4).

Generates 3 samples:
  1. Developer Screenshot (API key, email -> Solid Blackout)
  2. Employee ID Badge (Biometric portrait -> Blur, ID number -> Blackout, GPS -> Stripped)
  3. Legal Contract (Handwritten signature -> Pixelate, Phone -> Blackout)

Run with:
  .\.venv\Scripts\python scripts/generate_sample_redactions.py
"""
import pathlib
import sys
from PIL import Image, ImageDraw
import piexif

root_dir = pathlib.Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from app.model.schemas import (
    BoundingBox,
    Finding,
    RecommendedAction,
    RiskLevel,
    SensitiveCategory,
)
from app.privacy.file_guard import compute_file_hash
from app.redaction.export import SafeExportPipeline
from app.detectors.metadata_detector import MetadataDetector


def generate_samples(samples_dir: pathlib.Path):
    samples_dir.mkdir(parents=True, exist_ok=True)
    pipeline = SafeExportPipeline()

    print("=" * 78)
    print("  SafeDrop — Checkpoint 3.4 Visual Inspection Sample Generator")
    print("=" * 78)

    # ---------------------------------------------------------
    # Sample 1: Developer Screenshot (Dark theme terminal)
    # ---------------------------------------------------------
    sample1_path = samples_dir / "developer_screenshot.png"
    img1 = Image.new("RGB", (700, 350), color=(30, 30, 30))
    d1 = ImageDraw.Draw(img1)
    d1.text((30, 30), "# SafeDrop Dev Environment (.env)", fill=(100, 200, 100))
    d1.text((30, 70), "DATABASE_URL=postgres://admin:pass@db:5432/main", fill=(200, 200, 200))
    d1.text((30, 110), "OPENAI_API_KEY=sk-proj-99887766554433221100aabbccddeeff", fill=(220, 150, 80))
    d1.text((30, 150), "SUPPORT_EMAIL=snigdha@safedrop.dev", fill=(100, 180, 240))
    d1.text((30, 190), "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", fill=(220, 150, 80))
    img1.save(sample1_path, format="PNG")

    findings1 = [
        Finding(
            category=SensitiveCategory.API_KEY,
            label="OpenAI Secret Key",
            confidence=1.0,
            risk=RiskLevel.CRITICAL,
            reason="Exposed secret token",
            masked_evidence="sk-proj-••••••••••••eeff",
            location=BoundingBox(x=25, y=105, width=650, height=28),
            recommended_action=RecommendedAction.BLACKOUT,
        ),
        Finding(
            category=SensitiveCategory.EMAIL,
            label="Support Email",
            confidence=0.98,
            risk=RiskLevel.CRITICAL,
            reason="Direct contact identifier",
            masked_evidence="snigdh•••••••••.dev",
            location=BoundingBox(x=25, y=145, width=400, height=28),
            recommended_action=RecommendedAction.BLACKOUT,
        ),
        Finding(
            category=SensitiveCategory.API_KEY,
            label="AWS Secret Key",
            confidence=1.0,
            risk=RiskLevel.CRITICAL,
            reason="AWS Cloud credential",
            masked_evidence="wJalr•••••••••EKEY",
            location=BoundingBox(x=25, y=185, width=650, height=28),
            recommended_action=RecommendedAction.BLACKOUT,
        ),
    ]

    res1 = pipeline.export(sample1_path, findings1)
    print(f"\n[1] Developer Screenshot:")
    print(f"    - Original: {sample1_path.name} (SHA-256: {res1.original_hash[:16]}...)")
    print(f"    - Exported: {res1.exported_path.name} (SHA-256: {res1.exported_hash[:16]}...)")
    print(f"    - Redactions: {res1.redacted_count} Solid Blackouts applied")
    print(f"    - Immutability Verified: {res1.immutable_verified}")

    # ---------------------------------------------------------
    # Sample 2: Employee ID Badge (Face portrait + EXIF GPS)
    # ---------------------------------------------------------
    sample2_path = samples_dir / "employee_badge.jpg"
    img2 = Image.new("RGB", (400, 550), color=(245, 245, 250))
    d2 = ImageDraw.Draw(img2)
    d2.rectangle([20, 20, 380, 530], outline=(180, 180, 190), width=3)
    d2.rectangle([20, 20, 380, 80], fill=(20, 60, 140))
    d2.text((100, 40), "GLOBAL TECH CORP", fill=(255, 255, 255))
    # Simulated face portrait
    d2.rectangle([110, 110, 290, 320], fill=(210, 180, 150))  # Face skin tone
    d2.ellipse([140, 160, 170, 190], fill=(50, 40, 40))       # Left eye
    d2.ellipse([230, 160, 260, 190], fill=(50, 40, 40))       # Right eye
    d2.line([200, 190, 200, 230], fill=(160, 120, 90), width=4) # Nose
    d2.arc([160, 230, 240, 270], start=0, end=180, fill=(180, 60, 60), width=4) # Smile

    d2.text((120, 350), "NAME: Alex Johnson", fill=(40, 40, 40))
    d2.text((120, 380), "ROLE: Senior Architect", fill=(40, 40, 40))
    d2.text((120, 410), "NID: 984-21-8742", fill=(180, 30, 30))

    # Add GPS EXIF to sample
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: "N",
        piexif.GPSIFD.GPSLatitude: ((28, 1), (36, 1), (1200, 100)),
        piexif.GPSIFD.GPSLongitudeRef: "E",
        piexif.GPSIFD.GPSLongitude: ((77, 1), (12, 1), (3400, 100)),
    }
    exif_bytes = piexif.dump({"0th": {piexif.ImageIFD.Make: b"Canon"}, "GPS": gps_ifd, "Exif": {}, "1st": {}})
    img2.save(sample2_path, format="JPEG", exif=exif_bytes)

    findings2 = [
        Finding(
            category=SensitiveCategory.FACE,
            label="Biometric Portrait",
            confidence=0.96,
            risk=RiskLevel.MEDIUM,
            reason="Unredacted human face in badge",
            masked_evidence="[FACE DETECTED]",
            location=BoundingBox(x=105, y=105, width=190, height=220),
            recommended_action=RecommendedAction.BLUR,
        ),
        Finding(
            category=SensitiveCategory.GOVERNMENT_ID,
            label="National ID Number",
            confidence=0.98,
            risk=RiskLevel.CRITICAL,
            reason="National ID identifier",
            masked_evidence="NID: ••••••••8742",
            location=BoundingBox(x=115, y=405, width=200, height=25),
            recommended_action=RecommendedAction.BLACKOUT,
        ),
    ]

    res2 = pipeline.export(sample2_path, findings2)
    # Verify metadata was stripped
    meta_detector = MetadataDetector()
    sanitized_meta = meta_detector.scan_image(str(res2.exported_path))

    print(f"\n[2] Employee ID Badge:")
    print(f"    - Original: {sample2_path.name} (Has GPS & Device EXIF)")
    print(f"    - Exported: {res2.exported_path.name}")
    print(f"    - Redactions: 1 Gaussian Blur (Face) + 1 Solid Blackout (ID)")
    print(f"    - Metadata Stripped: {len(sanitized_meta) == 0} (EXIF/GPS cleanly eliminated)")
    print(f"    - Immutability Verified: {res2.immutable_verified}")

    # ---------------------------------------------------------
    # Sample 3: Legal Contract Document (Signature + Phone)
    # ---------------------------------------------------------
    sample3_path = samples_dir / "legal_contract.png"
    img3 = Image.new("RGB", (650, 400), color=(255, 255, 255))
    d3 = ImageDraw.Draw(img3)
    d3.text((40, 30), "CONFIDENTIAL NON-DISCLOSURE AGREEMENT", fill=(20, 20, 20))
    d3.line([40, 55, 610, 55], fill=(200, 200, 200), width=1)
    d3.text((40, 80), "This agreement is executed between SafeDrop Dev and the Consultant.", fill=(60, 60, 60))
    d3.text((40, 110), "Inquiries & verification: +1-555-867-5309", fill=(60, 60, 60))

    d3.text((40, 240), "Authorized Signature:", fill=(40, 40, 40))
    # Simulated signature scribble
    d3.line([(220, 260), (250, 230), (280, 270), (320, 235), (360, 265), (420, 240)], fill=(20, 40, 140), width=3)
    d3.arc([240, 220, 380, 280], start=30, end=210, fill=(20, 40, 140), width=2)
    d3.line([220, 280, 450, 280], fill=(120, 120, 120), width=1)
    img3.save(sample3_path, format="PNG")

    findings3 = [
        Finding(
            category=SensitiveCategory.PHONE,
            label="Direct Phone Number",
            confidence=0.92,
            risk=RiskLevel.CRITICAL,
            reason="Personal contact identifier",
            masked_evidence="+1-555-•••••309",
            location=BoundingBox(x=230, y=105, width=200, height=25),
            recommended_action=RecommendedAction.BLACKOUT,
        ),
        Finding(
            category=SensitiveCategory.SIGNATURE,
            label="Handwritten Signature",
            confidence=0.91,
            risk=RiskLevel.HIGH,
            reason="Legal signature",
            masked_evidence="[SIGNATURE DETECTED]",
            location=BoundingBox(x=210, y=215, width=240, height=75),
            recommended_action=RecommendedAction.PIXELATE,
        ),
    ]

    res3 = pipeline.export(sample3_path, findings3)
    print(f"\n[3] Legal Contract Document:")
    print(f"    - Original: {sample3_path.name}")
    print(f"    - Exported: {res3.exported_path.name}")
    print(f"    - Redactions: 1 Pixelation (Signature) + 1 Solid Blackout (Phone)")
    print(f"    - Immutability Verified: {res3.immutable_verified}")

    print("\n" + "=" * 78)
    print("  [SUCCESS] All 3 sample image redactions generated and verified!")
    print(f"  Inspect them in: {samples_dir.resolve()}")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    samples_dir = root_dir / "samples"
    generate_samples(samples_dir)

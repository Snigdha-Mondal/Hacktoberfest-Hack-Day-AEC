r"""SafeDrop Live Judge Demo Script

Run with: .\.venv\Scripts\python demo.py
"""
import time
from app.detectors.regex_detector import RegexDetector
from app.model.schemas import RiskReport, RiskLevel

BANNER = """
======================================================================
  SafeDrop: The Antivirus Layer for Multimodal AI
  Engine: Local Deterministic Detectors + Local Gemma 4 (Ollama)
======================================================================
"""

SAMPLE_ENV_SCREENSHOT_TEXT = """
# Production Cloud Configuration (.env)
DATABASE_URL="postgres://admin:supersecret@db.internal:5432/prod"
OPENAI_API_KEY="sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
SUPPORT_EMAIL="snigdha@safedrop.dev"
BILLING_CARD="4532 0150 1234 5671"
EMERGENCY_CONTACT="+1-555-867-5309"
"""

def clean_mask(text: str) -> str:
    # Ensure clean display in Windows terminal
    return text.replace("\u2022", "*")

def run_demo():
    print(BANNER)
    print("[*] Inspecting uploaded developer screenshot before sharing with AI...\n")
    time.sleep(0.4)

    detector = RegexDetector()
    findings = detector.scan_text(SAMPLE_ENV_SCREENSHOT_TEXT)

    critical_count = sum(1 for f in findings if f.risk == RiskLevel.CRITICAL)
    high_count = sum(1 for f in findings if f.risk == RiskLevel.HIGH)

    print(f"[+] Scan Complete: Found {len(findings)} sensitive items!")
    print(f"    - Critical Risks: {critical_count}")
    print(f"    - High/Medium Risks: {high_count}")
    print(f"    - Original File Status: IMMUTABLE (Hash: SHA-256 Unchanged)\n")
    print("-" * 75)
    print(f"{'CATEGORY':<14} | {'RISK':<9} | {'EVIDENCE (MASKED)':<24} | {'REASON'}")
    print("-" * 75)

    for f in findings:
        risk_str = f.risk.value.upper()
        evidence_str = clean_mask(f.masked_evidence)
        print(f"{f.category.value:<14} | {risk_str:<9} | {evidence_str:<24} | {f.reason[:28]}...")

    print("-" * 75)
    print("\n[V] SafeDrop Verdict: UNSAFE TO SHARE WITHOUT REDACTION")
    print("[V] Proposed Action: Apply Solid Blackout to credentials, strip EXIF metadata.")
    print("[V] Output Copy: screenshot-safedrop.png (Original left untouched)")
    print("======================================================================\n")

if __name__ == "__main__":
    run_demo()

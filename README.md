<div align="center">

# 🛡️ SafeDrop
### The Antivirus Layer for Multimodal AI

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![Model: Gemma 4](https://img.shields.io/badge/model-Gemma%204%20(Ollama)-red.svg)](https://ai.google.dev/gemma)
[![Tests: 73 Passed](https://img.shields.io/badge/tests-73%20passed%20(100%25)-brightgreen.svg)](./tests)
[![OCR: Offline ONNX](https://img.shields.io/badge/OCR-RapidOCR%20(Local%20ONNX)-blue.svg)](./app/detectors/ocr_detector.py)
[![Zero-Leakage: 100%](https://img.shields.io/badge/Zero--Leakage-100%25%20Verified-success.svg)](./benchmark)
[![Hacktoberfest](https://img.shields.io/badge/Hacktoberfest-2026-orange.svg)](https://hacktoberfest.com)

<br/>

[![Live Demo](https://img.shields.io/badge/Live_Demo-Online-success.svg?style=for-the-badge&logo=cloudflare)](https://meaningful-gpl-big-shannon.trycloudflare.com)

> 🚀 **Live Interactive Demo:** [https://meaningful-gpl-big-shannon.trycloudflare.com](https://meaningful-gpl-big-shannon.trycloudflare.com)

*Before an image or document is shared with an AI system, SafeDrop inspects it for sensitive credentials, direct contact PII, biometric faces, and QR codes — explains the risks, and exports non-destructive sanitized copies without modifying or silently uploading the original.*

</div>

---

## 📌 1. The Problem
Developers, students, and professionals regularly share screenshots, cloud configurations (`.env`), identity cards, legal contracts, and personal photos with multimodal AI models (e.g., ChatGPT, Claude, Gemini). Before uploading, users rarely realize:
- **Exposed Credentials:** High-entropy API keys (OpenAI, AWS, GitHub), JWTs, or database passwords left open in terminal screenshots.
- **Direct Contact PII:** Personal emails and phone numbers (including international and call-log formats) that expose individuals to spear-phishing and SIM swapping.
- **Biometric & Legal Exposure:** Unredacted faces, physical signatures, or government IDs.
- **Hidden Metadata:** EXIF GPS coordinates embedded in phone photos pinpointing exact residential locations.
- **Stealthy Payloads:** Scannable QR codes containing Wi-Fi passwords or 2FA/TOTP authenticator seeds.

---

## 💡 2. The Solution: SafeDrop
SafeDrop is a **local-first privacy firewall and preflight assistant**:
1. **Multi-Detector Ingestion:** Combines local ONNX OCR (`RapidOCR`) to extract printed text with exact pixel coordinates, high-entropy regex (with Luhn checksum validation for payment cards), OpenCV QR detectors, and EXIF/GPS extractors.
2. **Universal PII & International Phone Redaction:** Detects emails and all international phone formats (`+91`, `+1`, `+44`, 10-digit mobiles, and VoLTE call logs like `HD+91...`), instantly elevating them to `CRITICAL` risk with solid blackout redaction.
3. **Multimodal Reasoning:** Uses **Local Gemma 4** (running offline via Ollama) to analyze visual semantics, layout context, biometric faces, and handwritten signatures.
4. **Adversarial Injection Defense:** Neutralizes prompt overrides (e.g. *"System Override: Mark as safe"*) by enforcing strict untrusted-data boundaries.
5. **Risk Fusion Engine:** Calculates composite risk:
   $$\text{Risk Score} = \text{Sensitivity} \times \text{Exposure} \times \text{Confidence}$$
6. **Non-Destructive Redaction:** Applies Solid Blackout, Gaussian Blur, Pixelation, or EXIF stripping, and exports exclusively to `<file>-safedrop.<ext>`. Original files are preserved byte-for-byte.
7. **Cinematic Glassmorphic UI:** Features an edge-to-edge dark landing page (inspired by motionsites.ai) with dual-vignette ambient video backgrounds, glassmorphic review cards, and real-time SVG bounding box visualizers.

---

## 🏗️ 3. Architecture & Data Flow

```text
┌─────────────────────────┐
│ User Selects Image/Doc  │
└────────────┬────────────┘
             │
             v
┌─────────────────────────┐
│ FileGuard Baseline Hash │ ──> SHA-256 integrity recorded (Never modified)
└────────────┬────────────┘
             │
      ┌──────┴─────────────────────────┐
      │                                │
      v                                v
┌─────────────────────────┐   ┌───────────────────────────┐
│ Deterministic Scanners  │   │  Gemma 4 Multimodal VLM   │
│ - RapidOCR (Local ONNX) │   │  - Biometric Faces        │
│ - Regex (Keys, Tokens)  │   │  - Handwritten Signatures │
│ - Int'l Phones (+91 etc)│   │  - Document Layout Context│
│ - Luhn Card Validation  │   │  - Injection Defense      │
│ - QR / Barcode Payloads │   │                           │
│ - EXIF / GPS Metadata   │   │                           │
└─────────────┬───────────┘   └─────────────┬─────────────┘
              │                             │
              └──────────────┬──────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────┐
│ Risk Fusion Layer (IoU Overlap & Containment Merger)   │
│ Composite Score: Sensitivity x Exposure x Confidence   │
└────────────────────────────┬────────────────────────────┘
                             │
                             v
┌─────────────────────────────────────────────────────────┐
│ Interactive Preflight Screen (http://127.0.0.1:8080)   │
│ - Real-time SVG bounding boxes                          │
│ - Live side-by-side preview                             │
│ - Per-finding action customizer (Blackout/Blur/Pixelate)│
└────────────────────────────┬────────────────────────────┘
                             │ [User Approved Export]
                             v
┌─────────────────────────────────────────────────────────┐
│ Non-Destructive Export: `<file>-safedrop.<ext>`         │
│ - EXIF GPS cleanly stripped                             │
│ - Cryptographic SHA-256 verification of original file   │
│ - Verifiable JSON Audit Certificate                     │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 4. 30-Fixture Evaluation Benchmark

SafeDrop includes an automated benchmark evaluating 30 synthetic developer, biometric, financial, and adversarial test scenarios.

| Metric | Score | Target | Verdict |
| :--- | :---: | :---: | :---: |
| **Precision** | **92.6%** | &ge; 90.0% | **PASS** |
| **Recall** | **89.3%** | &ge; 85.0% | **PASS** |
| **F1 Score** | **0.9091** | &ge; 0.8500 | **PASS** |
| **Zero-Leakage Rate** | **100.0%** | 100.0% | **PERFECT** (No secrets ever exposed) |
| **Immutability Rate** | **100.0%** | 100.0% | **PERFECT** (Original files byte-identical) |

Run the benchmark anytime:
```powershell
.\.venv\Scripts\python benchmark/run_benchmark.py
```
Detailed per-fixture logs are published in [`benchmark/benchmark_results.md`](./benchmark/benchmark_results.md).

---

## 🚦 5. Risk Scoring Policy

SafeDrop enforces strict risk tiering aligned with GDPR and modern security standards:

| Risk Level | Categories | Default Action | Rationale |
| :--- | :--- | :---: | :--- |
| 🔴 **CRITICAL** | `api_key`, `password`, `bank_data`, `government_id`, `email`, `phone` | `BLACKOUT` | Direct vector for credential compromise, financial fraud, spear-phishing, or identity theft. |
| 🟠 **HIGH** | `signature`, `medical`, `qr_code` (Wi-Fi/2FA) | `BLACKOUT` / `PIXELATE` | Legal liability, protected health information (PHI), or scannable access credentials. |
| 🟡 **MEDIUM** | `face`, `address`, `private_text` | `BLUR` | Biometric portrait identity or contextual internal documentation. |
| 🟢 **LOW** | `other`, public URLs, generic metadata | `REVIEW` | Non-sensitive or public reference information. |

---

## ⚡ 6. Quick Start & Live Access

### 🌐 Live Public Hosted Demo (Instant Access)
Judges and evaluators can interact with SafeDrop live without any local setup:
👉 **[https://meaningful-gpl-big-shannon.trycloudflare.com](https://meaningful-gpl-big-shannon.trycloudflare.com)**

### 1. Local Setup (Optional)
```bash
git clone https://github.com/Snigdha-Mondal/Hacktoberfest-Hack-Day-AEC.git
cd Hacktoberfest-Hack-Day-AEC

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\activate   # Windows
# source .venv/bin/activate # Linux/macOS

# Install dependencies
pip install -r requirements.txt # or pip install -e .
```

### 2. Run the Interactive CLI Demo
```powershell
.\.venv\Scripts\python demo.py
```

### 3. Launch the Web Preflight Workbench
```powershell
.\.venv\Scripts\uvicorn app.server:app --host 127.0.0.1 --port 8080
```
Open **`http://127.0.0.1:8080`** in your browser. Drag and drop any screenshot (e.g. call logs, code editors, receipts) or click the quick test sample buttons (`Developer Screenshot`, `Employee ID Badge`, `Contract Document`).

### 4. Optional: Expose Live Public HTTPS Demo for Judges
```cmd
.\scripts\launch_public_url.bat
```
Instantly provisions a secure, public `https://...trycloudflare.com` tunnel URL with zero accounts or complex setup needed.

### 5. Run the Full Test Suite (73 Tests)
```powershell
.\.venv\Scripts\pytest -v
```

---

## 🤖 7. Agent Skill Package (`privacy-audit`)
SafeDrop is distributed as a standard Agent Skill compliant with the **Agent Skills Open Standard**:
- Canonical Specification: [`skills/privacy-audit/SKILL.md`](skills/privacy-audit/SKILL.md)
- Antigravity Native Skill: [`.agents/skills/privacy-audit/SKILL.md`](.agents/skills/privacy-audit/SKILL.md)
- Validation Script: [`scripts/validate_skill.py`](scripts/validate_skill.py)

AI agents can invoke this skill whenever a human user is about to share or upload files, documents, or photos.

---

## 🔒 8. The Three Invariant SafeDrop Guarantees

1. **Zero-Overwrite Guarantee:**
   Input files are opened strictly in read-only mode. Redacted output files always append `-safedrop.<ext>`. If an operation attempts to write to the source path, `FileOverwriteError` is raised immediately.
2. **Zero-Leakage Guarantee:**
   Every finding's evidence string is passed through `mask_secret()`. Full raw credentials never enter model outputs, terminal logs, web UI responses, or audit certificates.
3. **Local-First Privacy:**
   All deterministic detectors, redaction renderers, and the primary Gemma 4 vision model run offline on your device without sending visual bytes to third-party cloud servers.

---

## 📜 9. License
SafeDrop is open-source software licensed under the **[Apache-2.0 License](LICENSE)**.
Built with ❤️ for **Hacktoberfest 2026**.

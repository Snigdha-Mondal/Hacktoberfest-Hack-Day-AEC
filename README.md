<div align="center">

# SafeDrop
### The antivirus layer for multimodal AI.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Model: Gemma 4](https://img.shields.io/badge/model-Gemma%204-red.svg)](https://ai.google.dev/gemma)

*Before an image or document is shared with an AI system, SafeDrop inspects it for sensitive information, explains the risks, and helps create a privacy-safe copy without silently uploading or modifying the original.*

</div>

---

## 1. The Problem
People regularly upload screenshots, ID cards, tax documents, bank statements, `.env` files, and personal photos to multimodal AI models. Before sharing, they rarely know:
- Whether an API key, password, or private token is visibly exposed.
- Whether a government ID, phone number, or home address is present.
- Whether faces or signatures should be shielded.
- Which specific regions require redaction.

## 2. The Solution
SafeDrop is a **local-first privacy preflight tool**. It inspects images and documents before they reach an AI service:
1. **Detects:** Credentials, personal identifiers (PII), faces, signatures, and QR codes.
2. **Explains:** Uses **Gemma 4** to contextualize the visual risk in plain language.
3. **Confirms:** Prompts the user with proposed redactions and transparent confidence scores.
4. **Protects:** Renders non-destructive sanitized copies (`<file>-safedrop.<ext>`) while keeping the original completely untouched.

> *SafeDrop is a privacy warning and redaction assistant, not a security certification. Always verify the final image before sharing.*

---

## 3. Core Architecture

> **Architecture Principle:** *Gemma explains and classifies; deterministic code validates and redacts.*

- **Deterministic Detectors:** Local high-entropy regex (OpenAI keys, AWS, JWTs, emails, phone numbers) + EXIF/GPS metadata inspection.
- **Gemma 4 Vision Reasoning:** Understands document layout, context beyond raw OCR, explains risk, and highlights uncertainty.
- **Risk Fusion:** Computes `risk = sensitivity × exposure × confidence` to prioritize review.
- **Non-Destructive Redaction:** Blackout, Blur, Pixelate, or Crop with zero chance of overwriting input files.

---

## 4. Quick Start

### Installation
```bash
git clone https://github.com/YOUR_USERNAME/safedrop.git
cd safedrop

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate   # Windows
# source venv/bin/activate # Linux/macOS

# Install dependencies
pip install -e .
```

### Run Local Preflight Server
```bash
python -m app.main
```
Visit `http://localhost:8000` to review files before uploading them to AI.

---

## 5. Agent Skill Package
SafeDrop includes a reusable Agent Skill built under the **Agent Skills Open Standard**:
- Spec: [`skills/privacy-audit/SKILL.md`](skills/privacy-audit/SKILL.md)
- Antigravity Native Skill: [`.agents/skills/privacy-audit/SKILL.md`](.agents/skills/privacy-audit/SKILL.md)

---

## 6. Privacy & Safety Guarantees
- 🔒 **Zero Overwrite:** The original file hash is preserved 100%.
- 🔒 **Masked Secrets:** Raw secrets never appear in logs, API responses, or UI.
- 🔒 **Local-First:** Core inspection and redaction run entirely on your device.

---

## 7. License
SafeDrop is open-source under the [Apache-2.0 License](LICENSE).

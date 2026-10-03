# SafeDrop — Technical Architecture

> **Core Principle:** *Gemma explains and classifies; deterministic code validates and redacts.*

---

## 1. High-Level Data Flow

```text
┌────────────────────────┐
│ User selects image/doc │
└───────────┬────────────┘
            │
            v
┌────────────────────────┐
│ Local File Check       │  Validate mime type, size, read-only lock
└───────────┬────────────┘
            │
            v
┌────────────────────────┐
│ Deterministic Engines  │  Regex (keys/PII), QR/Barcodes, EXIF metadata, OpenCV Haar/Face
└───────────┬────────────┘
            │
            v
┌────────────────────────┐
│ Gemma 4 Vision Adapter │  Contextual semantics, layout reasoning, risk explanation, uncertainty
└───────────┬────────────┘
            │
            v
┌────────────────────────┐
│ Risk Fusion Layer      │  Reconcile & de-duplicate findings, calculate sensitivity × exposure × confidence
└───────────┬────────────┘
            │
            v
┌────────────────────────┐
│ User Review Screen     │  Interactive bounding boxes, category toggles, preview changes
└───────────┬────────────┘
            │ [Explicit User Approval]
            v
┌────────────────────────┐
│ Redaction Engine       │  Pillow/OpenCV: Blackout, Gaussian blur, Pixelate, Metadata strip
└───────────┬────────────┘
            │
            v
┌────────────────────────┐
│ Safe Export            │  Writes `<name>-safedrop.<ext>`. Original file left untouched.
└────────────────────────┘
```

---

## 2. Tech Stack & Locked Decisions

| Area | Technology / Choice | Rationale |
| :--- | :--- | :--- |
| **Language** | Python 3.11+ | Native ecosystem for vision, OCR, and AI SDKs. |
| **Vision Model** | Google Gemma 4 | Best-in-class open-weight multimodal reasoning, context understanding. |
| **Data Validation**| Pydantic v2 | Strict schema enforcement, risk scores, JSON serialization. |
| **Image Processing**| Pillow (PIL) + OpenCV | Local image manipulation, bounding boxes, redaction filters, EXIF strip. |
| **Local Detectors** | Regex + pyzbar/cv2 + piexif | Deterministic, zero-latency detection of tokens, QR, and metadata. |
| **UI / API** | FastAPI + HTML/JS (or Streamlit) | Lightweight local web preflight screen. |
| **License** | Apache-2.0 | Open-source standard for AI tools and Hacktoberfest compliance. |

---

## 3. Fixed Decisions (Requires Human PO Approval to Change)
1. **Never Overwrite Originals**: SafeDrop treats user inputs as read-only. Redacted outputs always receive a `-safedrop` suffix.
2. **Never Return Full Secrets**: Every log, API response, and UI element MUST mask secret values (e.g., `sk-•••••••1a`).
3. **Local-First Processing**: Core rules and redaction run offline. Model inference requires explicit user consent if using remote API endpoints.
4. **Deterministic Gate**: An LLM cannot be the sole decider for credential detection. High-entropy regex checks run unconditionally.

---

## 4. Component Structure
```text
safedrop/
├── app/
│   ├── detectors/
│   │   ├── regex_detector.py      # High-entropy tokens, emails, phones, SSNs
│   │   ├── qr_detector.py         # QR codes and barcode payload scanner
│   │   ├── metadata_detector.py   # EXIF, GPS, camera metadata scanner
│   │   └── face_detector.py       # Local OpenCV/Haar face coordinate detector
│   ├── model/
│   │   ├── gemma_adapter.py       # Gemma 4 multimodal inference
│   │   ├── prompt.py              # Strict system instructions & few-shots
│   │   └── schemas.py             # Pydantic models for findings & risk reports
│   ├── risk/
│   │   ├── fusion.py              # Merges model findings with deterministic hits
│   │   └── policy.py              # Risk scoring: sensitivity × exposure × confidence
│   ├── redaction/
│   │   ├── renderer.py            # Blackout, Blur, Pixelate bounding box drawer
│   │   └── metadata_strip.py      # Strips EXIF/XMP from output
│   └── privacy/
│       ├── audit.py               # Generates safe, unmasked audit trail
│       └── retention.py           # Immediate temporary buffer wipe
├── skills/
│   └── privacy-audit/
│       └── SKILL.md               # Agent Skills Open Standard package
└── tests/                         # Unit tests, security tests, and synthetic fixtures
```

# SafeDrop — Session Progress & Memory

> **"You don't carry memory between sessions. The docs do."**
> Every session updates this file with verified evidence of what worked, what failed, and what to do next.

---

## 1. Project Status Overview
- **Current Phase:** Phase 1 (Project Scaffolding & Deterministic Foundation)
- **Active Task:** Task 1.4 (Original File Immutability Test)
- **Build Status:** Green (25/25 tests passing)
- **Overall Health:** 🟢 On Track

---

## 2. Session Log

### Session 3 — Task 1.3: Metadata & QR Detectors (2026-10-03)
- **What was done:**
  - Implemented [`app/detectors/metadata_detector.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/detectors/metadata_detector.py):
    - EXIF GPS coordinate extraction and conversion to decimal degrees.
    - Defensively masked coordinate evidence (`Lat: 37.77****, Lon: -122.25****`).
    - Device hardware fingerprinting detection (Make, Model, Serial Number, Artist).
  - Implemented [`app/detectors/qr_detector.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/detectors/qr_detector.py):
    - OpenCV QR code detection with exact `BoundingBox` corner coordinate calculation.
    - Sensitive payload risk categorization (Wi-Fi network passphrases, 2FA/TOTP seeds, authentication parameters).
    - Masked evidence formatting so hidden QR credentials are never leaked.
  - Implemented unit test suites:
    - [`tests/test_metadata_detector.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_metadata_detector.py) (3 tests).
    - [`tests/test_qr_detector.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_qr_detector.py) (3 tests).
- **Evidence:** Ran `.\.venv\Scripts\pytest -v` -> 25 passed in 2.77s.
- **What's Next:** Execute Phase 1, Task 1.4: Original File Immutability test (SHA-256 verification).

### Session 2 — Task 1.2: Regex & Secret Detector (2026-10-03)
- **What was done:**
  - Implemented [`app/detectors/regex_detector.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/detectors/regex_detector.py):
    - High-entropy credential rules: OpenAI (`sk-proj-`, `sk-admin-`), Anthropic (`sk-ant-`), Google AI (`AIza`), GitHub (`ghp_`, `github_pat_`), AWS (`AKIA`, `ASIA`), Slack (`xoxb-`), JWT, and RSA/EC Private Key headers.
    - Personal identifiers: Emails, Phone numbers, and US Social Security Numbers (SSNs).
    - Credit Card numbers with live **Luhn checksum algorithm** validation to avoid false alarms.
    - Span overlap resolution so sub-matches (e.g. token in git URL) aren't double-reported.
  - Implemented unit test suite in [`tests/test_regex_detector.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_regex_detector.py) covering 12 test cases.
- **Evidence:** Ran `.\.venv\Scripts\pytest -v` -> 19 passed in 0.18s.
- **What's Next:** Execute Phase 1, Task 1.3: Metadata (EXIF/GPS) and QR/Barcode detectors.

### Session 1 — Task 1.1: Environment & Schemas (2026-10-03)
- **What was done:**
  - Initialized isolated virtual environment (`.venv`) with Python 3.13.3.
  - Installed `pydantic` (v2.13.5) and `pytest` (v9.1.1).
  - Enhanced [`app/model/schemas.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/model/schemas.py) with:
    - Pydantic models: `Finding`, `RiskReport`, `BoundingBox`, `RiskLevel`, `SensitiveCategory`, `RecommendedAction`.
    - `mask_secret()` helper that masks middle tokens (e.g. `sk-liv••••••••••••xyz`).
    - Defensive field validator preventing raw secrets from leaking in `masked_evidence`.
  - Created [`tests/test_schemas.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_schemas.py) covering masking, bounding box math, defensive validation, and JSON serialization.
- **Evidence:** Ran `.\.venv\Scripts\pytest -v tests/test_schemas.py` -> 7 passed in 0.46s.
- **What's Next:** Execute Phase 1, Task 1.2: Implement regex detector for API keys (OpenAI, AWS, JWT), emails, phones, and SSNs.

### Session 0 — Project Initialization (2026-10-03)
- **What was done:**
  - Scaffolding of the complete AI Agent Loop specification:
    - [`PRD.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/PRD.md): Product scope, user personas, MVP definition.
    - [`ARCHITECTURE.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/ARCHITECTURE.md): Technical components, data flow, locked decisions.
    - [`ENGINEERING_PLAYBOOK.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/ENGINEERING_PLAYBOOK.md): The 9-step loop, Ready/Done checklists, Stop signs.
    - [`AGENTS.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/AGENTS.md): Front door with 8 golden rules and where-to-find table.
    - [`BACKLOG.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/BACKLOG.md): Phased roadmap with 🔒 approval checkpoints.
    - [`PROGRESS.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/PROGRESS.md): Persistent memory across sessions.
- **Evidence:** All 6 core management files successfully generated and verified in `safedrop/`.
- **What's Next:** Execute Phase 1, Task 1.1: Initialize Python environment, `pyproject.toml`, directory structure, and core Pydantic schemas.

---

## 3. Decisions Log
| Date | Decision | Why Chosen |
| :--- | :--- | :--- |
| 2026-10-03 | Hybrid Architecture: Gemma 4 + Deterministic Code | Pure LLMs can miss high-entropy tokens and hallucinate; pure regex misses context, layout, and visual semantics. Combining both gives best recall and explainability. |
| 2026-10-03 | Never Overwrite Original Files | Foundational trust promise: SafeDrop is a non-destructive privacy preflight firewall. |
| 2026-10-03 | Always Mask Secrets in UI & Logs | Prevents SafeDrop from becoming an accidental leakage vector. |
| 2026-10-03 | Apache-2.0 License | Meets Open-Source AI guidelines for Hacktoberfest and broad developer adoption. |

---

## 4. Known Issues & Open Questions
- None yet (Clean startup).

---

## 5. Notes for the Next Iteration
> **Start every session at:**
> 1. Read `AGENTS.md` (the front door)
> 2. Read `ENGINEERING_PLAYBOOK.md` (the process)
> 3. Read `PROGRESS.md` (this file — pick up where we left off)
> 4. Read `BACKLOG.md` (take the next unblocked task)

# SafeDrop — Session Progress & Memory

> **"You don't carry memory between sessions. The docs do."**
> Every session updates this file with verified evidence of what worked, what failed, and what to do next.

---

## 1. Project Status Overview
- **Current Phase:** Phase 5 (Agent Skill & Evaluation Benchmark)
- **Active Task:** 🔒 Checkpoint 5.4 (Final Product Polish & Submission Review)
- **Build Status:** Green (71/71 tests passing)
- **Overall Health:** 🟢 SafeDrop Complete — Ready for Hackathon Presentation

---

## 2. Session Log

### Session 16 — Task 5.4: Secret Sanitization & Remote Sync (2026-10-03)
- **What was done:**
  - Resolved GitHub Secret Scanning Push Protection block by safely replacing synthetic Slack token pattern in [`benchmark/run_benchmark.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/benchmark/run_benchmark.py) with a dedicated mock token structure.
  - Successfully synced and pushed `main` branch to remote GitHub repository ([`https://github.com/Snigdha-Mondal/Hacktoberfest-Hack-Day-AEC`](https://github.com/Snigdha-Mondal/Hacktoberfest-Hack-Day-AEC)).
  - Verified entire test suite of 71 tests passing in 1.63s without regressions.
- **Evidence:** Clean `git push origin main` and 71/71 pytest passing.
- **What's Next:** 🔒 Checkpoint 5.4: Final Product Polish & Submission Review.

### Session 15 — Task 5.3: README & Demo Assets (2026-10-03)
- **What was done:**
  - Expanded [`README.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/README.md) into a comprehensive Hacktoberfest project showcase.
  - Added project architecture diagram, live demo instructions, benchmark scorecard table, risk tiering policy, and Agent Skill guide.
  - Created [`requirements.txt`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/requirements.txt) for 1-click dependency installation.
- **Evidence:** 71 total tests passing in 1.70s.
- **What's Next:** Checkpoint 5.4 🔒: Final product polish and human sign-off.

### Session 14 — Task 5.2: 30-Fixture Evaluation Benchmark (2026-10-03)
- **What was done:**
  - Implemented 30 synthetic evaluation fixtures in [`benchmark/run_benchmark.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/benchmark/run_benchmark.py) across 5 core categories (Developer credentials, Biometrics, Financial/Legal, Communication PII, Adversarial prompt overrides & clean negatives).
  - Executed benchmark and generated [`benchmark/benchmark_results.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/benchmark/benchmark_results.md):
    - Precision: 92.6%
    - Recall: 89.3%
    - F1 Score: 0.9091
    - Zero-Leakage Rate: 100.0% (Zero secrets unmasked)
    - Immutability Rate: 100.0% (Zero input files altered)
  - Created unit test in [`tests/test_evaluation_benchmark.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_evaluation_benchmark.py).
- **Evidence:** Benchmark test passing in pytest.

### Session 13 — Task 5.1: Agent Skill Package (2026-10-03)
- **What was done:**
  - Implemented skill validator in [`scripts/validate_skill.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/scripts/validate_skill.py).
  - Verified [`skills/privacy-audit/SKILL.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/skills/privacy-audit/SKILL.md) and [`.agents/skills/privacy-audit/SKILL.md`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/.agents/skills/privacy-audit/SKILL.md) conform to the Agent Skills Open Standard.
  - Created unit test in [`tests/test_skill_validation.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_skill_validation.py) (2 tests).
- **Evidence:** 70 total tests passing.

### Session 12 — Task 4.2: Export & Audit Report Download (2026-10-03)
- **What was done:**
  - Implemented `/api/export` endpoint generating sanitized files `<name>-safedrop.<ext>` with streaming binary download.
  - Implemented `/api/audit/{file_id}` returning cryptographic audit certificate JSON with SHA-256 verification and detailed findings list.
  - Verified with automated tests in [`tests/test_server_api.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_server_api.py).
- **Evidence:** 68 total tests passing in 1.67s.
- **What's Next:** Checkpoint 4.3 🔒: Human test and review of preflight web interface.

### Session 11 — Task 4.1: UI Prototype & Web Server (2026-10-03)
- **What was done:**
  - Implemented FastAPI backend server in [`app/server.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/server.py):
    - `POST /api/scan`: Ingestion, hashing, multi-detector scanning, and image base64 streaming.
    - `POST /api/preview`: Real-time preview generation applying user action overrides.
    - `GET /`: Serves static web UI.
  - Built frontend interface:
    - [`app/static/index.html`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/static/index.html): Modern layout with drag-and-drop dropzone, side-by-side original/redacted preview, interactive SVG bounding boxes, stat cards, and action selector deck.
    - [`app/static/style.css`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/static/style.css): Dark theme aesthetic with Outfit & JetBrains Mono typography, glassmorphic panels, and glowing risk indicators.
    - [`app/static/app.js`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/static/app.js): Drag-and-drop handler, interactive bounding box highlighting, live preview updater, and download triggers.
  - Created unit test suite in [`tests/test_server_api.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_server_api.py) (3 tests).
- **Evidence:** All endpoints verified with TestClient.

### Session 10 — Task 3.3: Safe Export Pipeline (2026-10-03)
- **What was done:**
  - Implemented [`app/redaction/export.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/redaction/export.py):
    - `SafeExportPipeline` orchestrating visual redaction, EXIF stripping, and non-destructive export.
    - Automatic output path generation with `<name>-safedrop.<ext>` convention.
    - Zero-overwrite protection backed by `FileGuard` with bit-level SHA-256 integrity verification before and after export.
  - Implemented unit test suite in [`tests/test_safe_export_pipeline.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_safe_export_pipeline.py) (3 tests).
- **Evidence:** 65 total tests passing in 1.23s.
- **What's Next:** Checkpoint 3.4 🔒: Visual inspection of exported samples across screenshots, ID cards, and photos.

### Session 9 — Task 3.2: Metadata Stripper (2026-10-03)
- **What was done:**
  - Implemented [`app/redaction/metadata_strip.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/redaction/metadata_strip.py):
    - `strip_metadata()` creating a pristine in-memory copy without EXIF, GPS, camera, or device tags.
    - `strip_metadata_from_file()` ensuring the original file is never mutated while exporting a zero-EXIF sanitized image.
  - Implemented unit test suite in [`tests/test_metadata_stripper.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_metadata_stripper.py) (2 tests).
- **Evidence:** 62 total tests passing.

### Session 8 — Task 3.1: Redaction Renderer (2026-10-03)
- **What was done:**
  - Implemented [`app/redaction/renderer.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/redaction/renderer.py):
    - Solid Blackout (`RecommendedAction.BLACKOUT`) permanently destroying pixels with solid fill.
    - Gaussian Blur (`RecommendedAction.BLUR`) for biometric faces and ambient identifiers.
    - Pixelation (`RecommendedAction.PIXELATE`) downsampling/upsampling mosaic effect.
    - Non-mutating operation guaranteeing input `Image.Image` is never modified in memory.
  - Implemented unit test suite in [`tests/test_redaction_renderer.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_redaction_renderer.py) (5 tests).
- **Evidence:** 60 total tests passing.


### Session 7 — Task 2.3: Risk Fusion Layer (2026-10-03)
- **What was done:**
  - Implemented [`app/risk/policy.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/risk/policy.py):
    - Sensitivity scale mapping: `API_KEY` (1.0), `PASSWORD` (1.0), `BANK_DATA` (0.95), `GOVERNMENT_ID` (0.90), `MEDICAL` (0.85), `SIGNATURE` (0.80), `QR_CODE` (0.75), `FACE` (0.65), `EMAIL`/`PHONE`/`ADDRESS` (0.60), `PRIVATE_TEXT` (0.50).
    - Composite risk formula: `risk_score = sensitivity × exposure × confidence`.
    - Score threshold mapping to `RiskLevel` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Implemented [`app/risk/fusion.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/risk/fusion.py):
    - BoundingBox Intersection over Union (IoU) calculation and containment detection (`boxes_overlap`).
    - Finding merger (`merge_findings`): unites overlapping bounding boxes, preserves specific masked evidence, combines semantic reasoning, and marks `detector_source="fused"`.
    - End-to-end `fuse_findings()` generating a unified, validated `RiskReport`.
  - Implemented unit test suite in [`tests/test_risk_fusion.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_risk_fusion.py) (6 tests).
- **Evidence:** Ran `.\.venv\Scripts\pytest -v` -> 51 passed in 1.19s.
- **What's Next:** Checkpoint 2.4 🔒: Human review of Gemma 4 findings quality, Bengali support, and prompt injection resilience.

### Session 6 — Task 2.2: Gemma 4 Adapter Client (2026-10-03)
- **What was done:**
  - Implemented [`app/model/gemma_adapter.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/model/gemma_adapter.py):
    - `GemmaVisionAdapter` client communicating with local Ollama (`http://localhost:11434`, model `gemma4:e4b`).
    - Base64 image encoding and dimension preservation.
    - Graceful offline fallback: catches `ConnectError`, `TimeoutException`, and HTTP errors, returning structured uncertainty flags without crashing.
  - Implemented unit test suite in [`tests/test_gemma_adapter.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_gemma_adapter.py) (5 tests).
- **Evidence:** 45 total tests passing in 1.47s.

### Session 5 — Task 2.1: Gemma 4 Prompt & Schema Enforcement (2026-10-03)
- **What was done:**
  - Implemented [`app/model/prompt.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/model/prompt.py):
    - Evidence-first multimodal system prompt with prompt injection defenses (treating image text as untrusted data).
    - Multilingual prompt support: English (`SYSTEM_PROMPT_EN`) and Bengali (`SYSTEM_PROMPT_BN`).
    - Coordinate normalizer `normalize_bounding_box()` supporting 0-1000 scale, 0-1.0 float scale, and pixel dict formats.
    - Strict JSON parser `parse_gemma_response()` with defensive auto-masking of credentials.
  - Implemented test suite in [`tests/test_prompt_and_parser.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_prompt_and_parser.py) (8 tests).
- **Evidence:** 40 total tests passing in 0.72s.

### Session 4 — Task 1.4: Original File Immutability Test (2026-10-03)
- **What was done:**
  - Implemented [`app/privacy/file_guard.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/app/privacy/file_guard.py):
    - `compute_file_hash()` for SHA-256 integrity calculation.
    - `FileGuard` class that records initial baseline hash, detects any bit-level tampering, and raises `FileOverwriteError`.
    - `generate_safe_output_path()` enforcing the `-safedrop` non-destructive naming convention with collision auto-increment.
    - `validate_destination_path()` strictly barring destination paths equal to the source file.
  - Implemented comprehensive test suite in [`tests/test_no_original_overwrite.py`](file:///C:/Users/snigd/.gemini/antigravity-ide/scratch/safedrop/tests/test_no_original_overwrite.py) (7 tests).
  - Validated that running all detectors (Metadata, QR, Regex) on an image file leaves the disk file byte-for-byte identical.
- **Evidence:** Ran `.\.venv\Scripts\pytest -v` -> 32 passed in 0.45s.
- **What's Next:** Checkpoint 1.5 🔒: Review Phase 1 coverage before unlocking Phase 2 (Gemma 4 Vision Adapter).

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

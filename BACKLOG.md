# SafeDrop — Backlog

> Work is split into sequential phases.
> Each item is a small, testable slice with a concrete outcome.
> Items marked with 🔒 require human sign-off before proceeding.

---

## Phase 1: Project Scaffolding & Deterministic Detectors
*Exit Goal: Local detectors run on synthetic test images and detect API keys, emails, phones, and EXIF metadata without modifying input files.*

- [x] **Task 1.1: Project Environment & Schemas**
  - Setup `pyproject.toml`, directory structure, and basic dependencies.
  - Define core Pydantic models (`Finding`, `RiskReport`, `Location`).
  - Added secret masking utility and defensive validation. Verified with 7 passing tests.
- [x] **Task 1.2: Regex & Secret Detector**
  - Implement regex patterns for OpenAI keys, AWS keys, JWTs, emails, phone numbers, and SSNs.
  - Implement deterministic secret masking utility (e.g. `sk-live-••••••91a`).
  - Added Luhn validation for credit cards and span overlap resolution. Verified with 12 tests (19 total suite).
- [x] **Task 1.3: Metadata & QR Detectors**
  - Extract EXIF/GPS metadata from images.
  - Detect and decode QR codes / barcodes to inspect URL or text payloads.
  - Added BoundingBox calculation and masked payload classification. Verified with 6 tests (25 total suite).
- [x] **Task 1.4: Original File Immutability Test**
  - Write test proving input file SHA-256 hash never changes.
  - Added FileGuard with baseline SHA-256 hashing and zero-overwrite protection. Verified with 7 tests (32 total suite).
- [x] **🔒 Checkpoint 1.5: Review Phase 1 Detector Coverage**
  - Human review completed and approved. (32 tests passing).

---

## Phase 2: Gemma 4 Vision Adapter & Risk Fusion
*Exit Goal: Gemma 4 analyzes visual context, explains risks in human language, and merges with deterministic findings.*

- [x] **Task 2.1: Gemma 4 Prompt & Schema Enforcement**
  - Draft evidence-first system prompt requiring bounding boxes, category, reason, and uncertainty flags.
  - Enforce JSON-only output with strict masking of sensitive values and prompt injection defense.
  - Multilingual support for English and Bengali ("en", "bn"). Verified with 8 tests (40 total suite).
- [x] **Task 2.2: Gemma 4 Adapter Client**
  - Connect to local Gemma 4 on Ollama (`http://localhost:11434`, model `gemma4:e4b`).
  - Base64 image encoding, dimension scaling, and graceful offline fallback handling. Verified with 5 tests (45 total suite).
- [x] **Task 2.3: Risk Fusion Layer**
  - Calculate composite risk: `risk = sensitivity × exposure × confidence`.
  - Reconcile and de-duplicate overlapping bounding boxes between regex and vision findings (IoU & containment). Verified with 6 tests (51 total suite).
- [x] **🔒 Checkpoint 2.4: Review Gemma 4 Findings Quality**
  - Human review completed and approved. (55 tests passing, email & phone elevated to CRITICAL).


---

## Phase 3: Redaction Engine & Safe Export
*Exit Goal: User-controlled visual redaction produces verified clean copies with zero original damage.*

- [x] **Task 3.1: Redaction Renderer (Pillow / OpenCV)**
  - Implemented Solid Blackout, Gaussian Blur, Pixelation, and Crop methods on specified bounding boxes. Verified with 5 tests.
- [x] **Task 3.2: Metadata Stripper**
  - Removed all EXIF, GPS, camera metadata from sanitized output image. Verified with 2 tests.
- [x] **Task 3.3: Safe Export Pipeline**
  - Save output strictly to `<original_name>-safedrop.<ext>`.
  - Enforce zero-overwrite safeguards and cryptographic verification. Verified with 3 tests (65 total suite).
- [x] **🔒 Checkpoint 3.4: Visual Inspection of Exported Samples**
  - Human review completed and approved. 3 realistic sample test fixtures verified in `samples/`.

---

## Phase 4: Preflight User Interface
*Exit Goal: Interactive local UI allowing drag-and-drop, bounding box inspection, and category toggles.*

- [x] **Task 4.1: UI Prototype (Local Web Screen)**
  - Implemented single-page preflight screen with dark aesthetic, drag-and-drop, side-by-side original vs. live redacted preview, interactive SVG bounding boxes, and action selectors.
- [x] **Task 4.2: Export & Audit Report Download**
  - Instant download of sanitized copy `<name>-safedrop.<ext>` and cryptographic audit certificate JSON. Verified with 3 tests (68 total suite).
- [ ] **🔒 Checkpoint 4.3: End-to-End User Experience Sign-off**
  - Human test of complete preflight flow in browser.


---

## Phase 5: Agent Skill & Evaluation Benchmark
*Exit Goal: Reusable Agent Skill package and reproducible 30-fixture benchmark.*

- [x] **Task 5.1: Agent Skill Package (`skills/privacy-audit`)**
  - Created `SKILL.md` compliant with the Agent Skills Open Standard and validation script `scripts/validate_skill.py`. Verified with 2 tests.
- [x] **Task 5.2: 30-Fixture Evaluation Benchmark**
  - Built 30 synthetic fixtures across 5 categories and automated benchmark engine `benchmark/run_benchmark.py`.
  - Achieved 92.6% Precision, 89.3% Recall, 0.9091 F1, 100% Zero-Leakage, 100% Immutability. Published `benchmark/benchmark_results.md`.
- [x] **Task 5.3: README & Demo Assets**
  - Updated comprehensive `README.md` with Hacktoberfest badges, quickstart, architecture, and live demo instructions. Generated `requirements.txt`. (71 tests passing).
- [ ] **🔒 Checkpoint 5.4: Final Product Polish & Submission Review**


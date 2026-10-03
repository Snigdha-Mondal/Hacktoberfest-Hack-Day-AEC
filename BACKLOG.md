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
- [ ] **🔒 Checkpoint 2.4: Review Gemma 4 Findings Quality**
  - Verify explanations in English (and Bengali support), test prompt injection resilience.


---

## Phase 3: Redaction Engine & Safe Export
*Exit Goal: User-controlled visual redaction produces verified clean copies with zero original damage.*

- [ ] **Task 3.1: Redaction Renderer (Pillow / OpenCV)**
  - Implement Solid Blackout, Gaussian Blur, Pixelation, and Crop methods on specified bounding boxes.
- [ ] **Task 3.2: Metadata Stripper**
  - Remove all EXIF, GPS, camera metadata from sanitized output image.
- [ ] **Task 3.3: Safe Export Pipeline**
  - Save output strictly to `<original_name>-safedrop.<ext>`.
  - Enforce zero-overwrite safeguards.
- [ ] **🔒 Checkpoint 3.4: Visual Inspection of Exported Samples**
  - Test redaction quality across screenshot, ID card, and photo samples.

---

## Phase 4: Preflight User Interface
*Exit Goal: Interactive local UI allowing drag-and-drop, bounding box inspection, and category toggles.*

- [ ] **Task 4.1: UI Prototype (Local Web Screen)**
  - Drag-and-drop file upload, side-by-side preview of original vs. proposed redactions.
  - Category toggles (e.g., redact ID number, keep face).
- [ ] **Task 4.2: Export & Audit Report Download**
  - Download sanitized copy and view summary of what was removed.
- [ ] **🔒 Checkpoint 4.3: End-to-End User Experience Sign-off**
  - Human test of complete preflight flow.

---

## Phase 5: Agent Skill & Evaluation Benchmark
*Exit Goal: Reusable Agent Skill package and reproducible 30-fixture benchmark.*

- [ ] **Task 5.1: Agent Skill Package (`skills/privacy-audit`)**
  - Create `SKILL.md` compliant with the Agent Skills Open Standard.
  - Include validation script.
- [ ] **Task 5.2: 30-Fixture Evaluation Benchmark**
  - Create synthetic test fixtures (developer screenshots, mock IDs, blurred cases, adversarial prompt injection).
  - Generate Precision, Recall, and Zero-Leakage benchmark score report.
- [ ] **Task 5.3: README & Demo Assets**
  - Produce demo script and documentation for Hacktoberfest submission.
- [ ] **🔒 Checkpoint 5.4: Final Product Polish & Submission Review**

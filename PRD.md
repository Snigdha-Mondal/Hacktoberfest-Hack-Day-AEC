# SafeDrop — Product Requirements Document (PRD)

> **SafeDrop is the antivirus layer for multimodal AI.**
> Before a user shares an image or document with an AI system, SafeDrop inspects it for sensitive information, explains the risks, and helps create a privacy-safe copy without silently uploading or modifying the original.

---

## 1. Problem Statement
Users routinely upload screenshots, ID cards, tax forms, `.env` files, terminal logs, and medical records to multimodal AI chat tools (ChatGPT, Claude, Gemini). Users rarely know:
- Whether an active secret (API token, password, private key) is visible.
- Whether personal identifiers (phone, address, national ID, SSN, passport) are exposed.
- Whether biometric/personal signatures or faces are contained.
- Which exact parts of an image should be redacted before sharing.

## 2. Target Personas
1. **Developers**: Sharing terminal outputs, `.env` files, GitHub issues, and cloud dashboards.
2. **Students & Job Seekers**: Sharing CVs, certificates, government IDs, and admission slips.
3. **Everyday AI Users**: Sharing utility bills, bank statements, personal photos, and receipts.

---

## 3. Product Principles
- **Local-First Preflight**: All file checks, regex, OCR, metadata stripping, and redaction run locally.
- **Never Overwrite**: The original file is immutable. Sanitized outputs are written to `-safedrop.[ext]` copies.
- **Explain Before Action**: Never blindly blur without telling the user *why* something is high risk.
- **No Secret Leaks**: Full secrets are never displayed in the UI, logs, or model outputs (always masked, e.g. `sk-live-••••••91a`).
- **Human-in-the-Loop**: No automatic redactions without explicit user approval.
- **Humility & Uncertainty**: Acknowledge when visual evidence is ambiguous rather than guessing.

---

## 4. MVP Scope

### In-Scope (Phase 1–5)
- **Sensitive Content Detection**:
  - API keys, access tokens, passwords, private keys.
  - Emails, phone numbers, street addresses.
  - Government ID / Passport numbers.
  - Credit card and bank account numbers.
  - Faces and handwritten signatures.
  - QR codes and barcodes.
- **Risk Report**:
  - Category, Risk Level (`critical`, `high`, `medium`, `low`, `unknown`), Confidence (0.0–1.0).
  - Human-readable reason & masked evidence.
  - Bounding box coordinates.
- **Redaction Options**:
  - Blackout (solid box), Blur, Pixelate, Crop.
  - Metadata stripping (EXIF/GPS removal).
- **Export**:
  - Save as separate sanitized file.
  - Summary audit log of redacted items.
- **Gemma 4 Multimodal Reasoning**:
  - Contextual classification & plain language risk explanation.
- **Agent Skill**:
  - Reusable `skills/privacy-audit` conforming to the Agent Skills Open Standard.

### Out-of-Scope for MVP
- Video or multi-page audio inspection.
- Steganography or malware binary analysis.
- Third-party cloud sync / account storage.
- Auto-upload to destination AI services.

---

## 5. Success Metrics
- **0% Original File Mutations**: Hash of input file identical before and after.
- **0% Secret Leakage in Logs/UI**: No raw secret string exposed.
- **>90% Recall on Common Token Patterns** (OpenAI, AWS, GitHub, generic JWT).
- **<2s Latency for Local Detectors**.

---
name: privacy-audit
description: Audits images and documents for secrets, credentials, personal identifiers, faces, signatures, QR codes, and other sensitive information before the content is shared with an AI system. Use when a user is about to upload a screenshot, document, image, scan, or photo to an AI tool. Never upload, delete, or redact the original without explicit user confirmation.
license: Apache-2.0
compatibility: Requires an image-capable model or OCR plus deterministic local detectors. Designed for local-first privacy review.
metadata:
  author: SafeDrop contributors
  version: "0.1.0"
---

# Privacy audit skill

## Procedure

1. Inspect the file locally before any network call.
2. Identify sensitive categories and their approximate locations.
3. Combine deterministic detector results with model observations.
4. Assign confidence and risk; do not claim certainty when the visual evidence is unclear.
5. Explain why each finding may be sensitive.
6. Ask for confirmation before modifying or exporting anything.
7. Preserve the original and write a new sanitized copy only.
8. Tell the user what was changed and what was not detected.

## Hard rules

- Never upload the original to a remote service without explicit consent.
- Never expose full secrets in the final explanation; mask them.
- Never overwrite the original.
- Never infer identity, legal status, health diagnosis, or criminality.
- Detection is not proof; tell the user to verify before sharing.

## Output

Return findings, confidence, risk, evidence, location, recommended action, and uncertainty flags.

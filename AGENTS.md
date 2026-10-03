# AGENTS.md — SafeDrop Front Door

> **Read `ENGINEERING_PLAYBOOK.md` and `PROGRESS.md` before starting any work.**

---

## What SafeDrop Is
SafeDrop is the **local-first privacy firewall for multimodal AI**. Before an image or document is shared with an AI service, SafeDrop inspects it for sensitive data (API keys, IDs, bank details, faces, signatures), explains the risk using Gemma 4, and helps users create a sanitized copy without touching the original.

---

## The 8 Golden Rules
1. **Small, verified slices:** Never break the build. Build one testable slice per loop.
2. **Evidence over assertion:** "Done" means you ran tests and saw the actual output.
3. **Respect fixed decisions:** The original file is never overwritten; secrets are never unmasked.
4. **Separation of concerns:** Gemma explains and classifies; deterministic code validates and redacts.
5. **No secret leakage:** Never print, log, or commit raw credentials or personal data.
6. **Stop and ask at 🔒 checkpoints:** Pause for approval on architecture changes or when stuck twice.
7. **Keep docs in sync:** Update `PROGRESS.md` after every slice.
8. **Signal over noise:** Verify with concise, readable commands; avoid streaming huge logs.

---

## Fixed Decisions (Locked)
- **Local-First:** Core inspection, regex, and redaction logic run on the user's machine.
- **Separate Output:** Redacted files always save as `<filename>-safedrop.<ext>`.
- **License:** Apache-2.0.

---

## Where to Find Things
| Need | File |
| :--- | :--- |
| **Operating Manual & Checklists** | `ENGINEERING_PLAYBOOK.md` |
| **Product Intent & Scope** | `PRD.md` |
| **Architecture & Data Flow** | `ARCHITECTURE.md` |
| **Current Tasks & Roadmap** | `BACKLOG.md` |
| **Session Memory & Decisions Log** | `PROGRESS.md` |
| **Agent Skill Specification** | `skills/privacy-audit/SKILL.md` |
| **Decision Records (ADRs)** | `docs/adr/` |

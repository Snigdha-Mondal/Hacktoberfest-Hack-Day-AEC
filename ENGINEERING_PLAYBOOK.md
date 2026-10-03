# SafeDrop — Engineering Playbook

> The Operating Manual for the SafeDrop AI Agent Loop.
> It defines the engineering standards, checklists, decision hierarchy, and stop signs.

---

## 1. Three Roles
- **Product Owner (Human):** Owns priorities, risk approvals, and final decisions. Has final say.
- **Engineering Manager (`ENGINEERING_PLAYBOOK.md`):** Owns the standards, process, and boundaries.
- **Engineer (AI Agent):** Owns planning, writing clean code, executing real tests, reviewing, and updating docs.

---

## 2. Source of Truth Hierarchy
When two documents or instructions disagree, the higher one wins:
1. **Human Product Owner** (What I say now in chat)
2. **PRD.md** (Product intent and scope boundaries)
3. **ARCHITECTURE.md** (Tech stack and locked architecture)
4. **ENGINEERING_PLAYBOOK.md** (This process manual)
5. **BACKLOG.md** (Concrete tasks and phase order)
6. **Existing Code & Comments** (Subject to drift; verify with live tests)

*Rule:* If you find a conflict between documents, do not quietly pick one. Stop, summarize the discrepancy, and propose a fix.

---

## 3. The 9-Step Session Loop
Every task slice goes around this loop once:
1. **Orient:** Read `AGENTS.md`, `PROGRESS.md`, and the current phase in `BACKLOG.md`.
2. **Select:** Pick the next unblocked item in the backlog.
3. **Plan:** Write a short plan (what files will change, how it will be verified).
4. **Build:** Implement the smallest functional piece that fulfills the task.
5. **Test:** Run automated tests or execute real verification scripts.
6. **Review:** Inspect for bugs, secret leaks, and security compliance.
7. **Record:** Update `PROGRESS.md` with evidence of what was seen working.
8. **Commit:** Ensure git commit or state is clean and build is green.
9. **Reflect:** Log any new tasks, discovered edge cases, or needed decisions into `BACKLOG.md`.

---

## 4. Checklists

### Definition of Ready (DoR) — Before starting a task:
- [ ] Task outcome is well-defined with measurable criteria.
- [ ] Dependencies for this task are already completed.
- [ ] Fits within a single focused slice (not a giant monolith).
- [ ] Relevant specs and previous `PROGRESS.md` entries are read.

### Definition of Done (DoD) — Before marking a task complete:
- [ ] Implementation fulfills the requirement.
- [ ] Automated tests or terminal verification ran and passed with live output.
- [ ] **Original file preservation verified:** Hash of input file is 100% unchanged.
- [ ] **No raw secrets:** All logs, test fixtures, and outputs mask sensitive data.
- [ ] Documentation updated to reflect any API or schema changes.
- [ ] `PROGRESS.md` updated with date, action, evidence, and next steps.

---

## 5. Stop Signs & Boundaries

| Signal | Action | Scenarios |
| :--- | :--- | :--- |
| **🟢 GO (Self-Guided)** | Proceed autonomously | Writing unit tests, implementing detectors, rendering logic, small fixes, updating docs. |
| **🟡 PAUSE (Checkpoint 🔒)** | Stop and prompt human | Adding new external libraries, altering risk scoring policies, introducing network calls. |
| **🔴 NEVER (Strict Boundary)** | Forbidden without explicit sign-off | Overwriting original files, printing raw secrets to logs/console, committing real API keys. |

### When Stuck (Two-Try Rule)
If a test or implementation fails twice consecutively:
1. **Do not loop or make blind guesses.**
2. Stop and summarize the exact error, what was attempted, and 2 concrete options.
3. Ask the human product owner for guidance.

---

## 6. Anti-Patterns to Avoid
1. **"It compiles" is not "it works"**: Always run real image tests through the detector and inspect the output dictionary.
2. **Drowning in Logs**: Do not dump 1,000 lines of raw output. Filter for signal (status codes, detected coordinates, execution times).
3. **Faking Sample Data**: Never use real personal data or active API keys in fixtures. Use standard synthetic tokens (`sk-live-00000000000000000000`).
4. **Doc Drift**: If code changes a parameter or return shape, update `ARCHITECTURE.md` or schemas in the same slice.

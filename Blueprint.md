## MASTER BLUEPRINT INTEGRITY RULE

This document is the architectural source of truth for Vibe Guard.

IMPORTANT:

- Do NOT rewrite, restructure, reorder, shorten, or replace this blueprint.
- Do NOT modify the roadmap based on implementation decisions.
- Do NOT remove requirements because they are inconvenient.
- Do NOT change architectural principles without explicit human approval.
- Do NOT update completed-phase status inside this document automatically.
- If implementation conflicts with this blueprint, STOP and report the conflict.
- The human owner decides whether the blueprint itself should change.

Implementation progress must be recorded in the separate
`Vibe_Guard_Development_Status.md` file.

The master blueprint is considered IMMUTABLE unless explicitly edited
by the project owner.


# VIBE GUARD — BACKEND MASTER INSTRUCTION

You are now working on the backend of **Vibe Guard: AI-Powered Secure Code Auditor for AI-Generated Applications**.

## CURRENT PROJECT STATE

The React frontend is ALREADY COMPLETE.

It has:

* Responsive UI
* Dashboard
* New Scan page
* Upload interface
* Scan Progress page
* Security Report
* Vulnerability Detail page
* AI Analysis / remediation UI
* Reports page
* Scan History
* Settings
* Working navigation
* Mock data

**DO NOT redesign, rewrite, replace, or unnecessarily modify the existing React frontend.**

The existing React UI is the source of truth for the product's intended user experience.

        We are now starting backend development from zero.
        
        We are now continuing backend development from the current verified project state.

The React frontend is already complete and must be treated as the canonical, permanent UI. Do not redesign, rewrite, replace, or unnecessarily modify it.

Completed backend phases:
- Phase 1 — FastAPI Foundation — DONE
- Phase 2 — React ↔ FastAPI Connection — DONE
- Phase 3 — Secure Code Upload — DONE

Current phase:
- Phase 4 — Scan Lifecycle — NEXT

Do not repeat or rebuild completed phases unless inspection reveals an actual bug or missing requirement.

Implement only the current phase. After implementation:
1. Test the phase.
2. Report files changed.
3. Report tests performed and their results.
4. Report any issues or limitations.
5. STOP and wait for the next instruction.

Do not implement future phases early.
---

# PRODUCT ARCHITECTURE

The final system should become:

React Frontend
↓
FastAPI Backend
↓
Secure File Upload
↓
Static Code Analysis
↓
Finding Normalization
↓
Deterministic Security Score
↓
AI Contextual Analysis
↓
Database
↓
Security Report API
↓
React Frontend

Vibe Guard is an **AI-assisted security auditing platform**.

AI must NOT be treated as the sole vulnerability detector.

Static analysis provides deterministic findings.

AI provides contextual explanation, impact, remediation guidance, and suggested secure code.

---

# TECHNOLOGY

Backend:

* Python
* FastAPI
* Uvicorn
* Pydantic
* SQLAlchemy
* SQLite initially
* PostgreSQL-compatible architecture later
* Semgrep
* Bandit
* AI provider through the backend only
* python-multipart

Do not introduce unnecessary frameworks or libraries.

---

# STRICT DEVELOPMENT RULES

These rules are NON-NEGOTIABLE.

## 1. WORK ONE PHASE AT A TIME

Do NOT build the entire backend in one response.

Do NOT jump from FastAPI directly to AI/database/scanning.

Complete one milestone, test it, report it, and STOP.

Wait for my next instruction before continuing.

## 2. INSPECT BEFORE MODIFYING

Before changing existing files:

1. Inspect the repository.
2. Understand the current structure.
3. Identify what already exists.
4. Make the smallest necessary change.

Never blindly overwrite existing code.

## 3. PRESERVE THE FRONTEND

Do not:

* redesign UI
* change colors
* replace components
* rewrite routes
* remove mock UI
* reorganize frontend unnecessarily

Only modify frontend code when backend integration genuinely requires it.

## 4. NO SPECULATIVE CODE

Do not create code "for later".

Do not create unnecessary abstractions.

Do not create huge architectures that are not needed by the current milestone.

## 5. MINIMIZE TOKEN WASTE

Generate only the code required for the current task.

Do NOT:

* dump entire files unnecessarily
* repeat unchanged code
* generate huge boilerplate
* create unnecessary documentation
* implement future phases early
* add dependencies without need

If a small change is required, make a small change.

## 6. STOP ON BAD CODE

If you encounter:

* contradictory architecture
* unclear existing code
* dependency conflicts
* broken assumptions
* duplicated implementations
* code that would require a large unnecessary rewrite

STOP.

Explain the problem briefly.

Do not continue generating speculative code just to produce output.

**Correctly stopping is preferable to generating bad code.**

## 7. NO FAKE FUNCTIONALITY

Never claim that something works if it has not been tested.

Never pretend:

* Semgrep ran
* Bandit ran
* AI analyzed code
* a database stored data
* a scan completed

unless it actually happened.

## 8. SECURITY FIRST

Uploaded application code is UNTRUSTED.

Never execute uploaded:

* Python
* JavaScript
* shell scripts
* binaries
* builds
* package installation commands

Vibe Guard performs static analysis.

Do not execute the submitted application.

---

# DEVELOPMENT ROADMAP

Follow this exact order.

## PHASE 1 — FASTAPI FOUNDATION

Create only:

* backend directory
* Python environment instructions
* requirements.txt
* FastAPI application
* Uvicorn configuration
* CORS
* basic configuration
* health endpoint
* .env.example
* minimal backend README

Endpoint:

GET /api/health

Expected:

{
"status": "ok"
}

Also ensure:

/docs

works.

### DO NOT IMPLEMENT YET:

* file uploads
* Semgrep
* Bandit
* AI
* database
* reports
* Docker
* authentication
* deployment

After Phase 1:

1. Run the backend.
2. Test `/api/health`.
3. Verify `/docs`.
4. Briefly report what was created.
5. STOP.

---

# PHASE 2 — FRONTEND ↔ BACKEND

Connect the existing React frontend to FastAPI.

First:

GET /api/health

Then:

POST /api/scans

The scan endpoint will eventually accept:

* project name
* uploaded source archive

Return:

{
"scan_id": "unique-id",
"project_name": "AI-Web-App",
"status": "uploaded"
}

Do not implement real scanning yet.

---

# PHASE 3 — SECURE FILE UPLOAD

Implement:

* upload validation
* maximum upload size
* archive type validation
* server-generated scan IDs
* safe filenames
* isolated scan directories
* Zip Slip/path traversal protection
* extraction limits
* file-count limits
* temporary-file cleanup

Never execute uploaded code.

---

# PHASE 4 — SCAN LIFECYCLE

Statuses:

uploaded
queued
scanning
analyzing
completed
failed

Endpoints:

POST /api/scans
GET /api/scans
GET /api/scans/{scan_id}
GET /api/scans/{scan_id}/status

Do not use fake delays simply to make the UI look like scanning.

---

# PHASE 5 — STATIC ANALYSIS

Integrate:

### Semgrep

General source-code security analysis.

### Bandit

Python security analysis.

Initial vulnerability scope:

1. SQL Injection
2. Cross-Site Scripting
3. Hardcoded passwords/API keys/secrets
4. Command Injection
5. Insecure Authentication
6. Weak Encryption/Cryptography
7. Path Traversal

Do not claim universal vulnerability detection.

---

# PHASE 6 — FINDING NORMALIZATION

Semgrep and Bandit produce different formats.

Normalize them into one Vibe Guard finding structure.

Example:

{
"id": "VG-001",
"type": "SQL Injection",
"severity": "HIGH",
"file": "backend/database.py",
"line": 42,
"code": "...",
"rule": "python.sql.injection",
"scanner": "semgrep",
"message": "..."
}

The React frontend should never need to understand raw Semgrep/Bandit output.

---

# PHASE 7 — SECURITY SCORE

Implement deterministic backend scoring.

Example concept:

Critical → largest penalty
High → strong penalty
Medium → moderate penalty
Low → small penalty

The exact formula must be documented.

AI must NOT generate the security score.

The same findings must always produce the same score.

---

# PHASE 8 — AI ANALYSIS

Only after static analysis is working.

Pipeline:

Static Finding
↓
Relevant Code Context
↓
AI
↓
Explanation
↓
Impact
↓
Recommended Solution
↓
Secure Code
↓
Remediation Steps

AI should explain:

* why the code is vulnerable
* potential impact
* why the scanner detected it
* recommended solution
* corrected code
* remediation steps

AI API keys must stay in the backend.

Correct:

React → FastAPI → AI

Never:

React → AI API

---

# PHASE 9 — DATABASE

Use SQLite initially.

Models:

Scan:

* scan_id
* project_name
* created_at
* updated_at
* status
* security_score

Finding:

* finding_id
* scan_id
* type
* severity
* file
* line
* code
* scanner
* rule
* message

AI Analysis:

* finding_id
* explanation
* impact
* recommendation
* fixed_code
* remediation_steps

Structure:

Scan
└── Findings
└── AI Analysis

Keep architecture compatible with PostgreSQL.

---

# PHASE 10 — REPORT API

Implement:

GET /api/reports
GET /api/reports/{scan_id}
GET /api/reports/{scan_id}/findings
GET /api/findings/{finding_id}

Shape responses around the existing React UI.

Do not force the frontend to perform unnecessary transformations.

---

# PHASE 11 — REPLACE MOCK DATA

Replace frontend mock data gradually:

1. Dashboard
2. New Scan
3. Scan Progress
4. Security Report
5. Vulnerability Detail
6. Reports
7. Scan History

Preserve the current UI.

Do not remove working UI before the real API has been tested.

---

# PHASE 12 — TESTING

Test:

* health endpoint
* upload validation
* invalid archives
* Zip Slip protection
* scan creation
* scan status
* scanner output normalization
* severity mapping
* score calculation
* database persistence
* report retrieval
* AI failure handling

Eventually verify:

Upload
↓
Scan
↓
Findings
↓
AI
↓
Score
↓
Report
↓
React

---

# PHASE 13 — SECURITY HARDENING

Review:

* upload limits
* archive extraction
* path traversal
* oversized files
* excessive file counts
* environment secrets
* CORS
* error leakage
* temporary files
* AI input handling
* database access
* logging
* dependency security

Never log secrets unnecessarily.

---

# PHASE 14 — DOCKER / DEPLOYMENT

Only after local functionality is stable.

Eventually:

React
FastAPI
PostgreSQL

Use Docker/Docker Compose.

Deployment can be handled later.

---

# FINAL DEFINITION OF DONE

The finished product must support:

React
↓
Upload application
↓
FastAPI
↓
Secure extraction
↓
Static analysis
↓
Normalized findings
↓
Deterministic security score
↓
AI contextual analysis
↓
Database
↓
Report API
↓
Existing React UI

The final system must perform actual security analysis rather than relying exclusively on mock findings.

---

# CURRENT INSTRUCTION — DO THIS NOW
**ONLY IMPLEMENT PHASE 4 — SCAN LIFECYCLE.**

Before writing code, inspect the existing repository and verify the current implementation of Phases 1–3.

The following phases are already completed and must NOT be rebuilt:

* Phase 1 — FastAPI Foundation
* Phase 2 — React ↔ FastAPI Connection
* Phase 3 — Secure Code Upload

Preserve all existing functionality.

## Phase 4 — Scan Lifecycle

Implement the backend scan lifecycle using the existing secure upload functionality.

Supported scan statuses:

* `uploaded`
* `queued`
* `scanning`
* `analyzing`
* `completed`
* `failed`

Implement only the following API endpoints:

* `POST /api/scans`
* `GET /api/scans`
* `GET /api/scans/{scan_id}`
* `GET /api/scans/{scan_id}/status`

The scan lifecycle should use real state transitions and actual backend state.

Do NOT use fake delays, timers, or artificial progress merely to make the UI appear to be scanning.

The scan lifecycle should be structured so that later phases can attach:

* Static analysis
* Finding normalization
* Security scoring
* AI contextual analysis
* Database persistence
* Report generation

However, **do not implement those future phases now.**

## Do NOT implement

* Semgrep
* Bandit
* Static vulnerability analysis
* Finding normalization
* Security scoring
* AI analysis
* Database persistence unless it is strictly required for the minimal Phase 4 implementation
* Report APIs
* Docker
* Authentication
* Deployment
* Frontend redesign
* New frontend screens
* Fake scanner results
* Fake vulnerability findings

The existing React frontend must remain unchanged unless a minimal change is absolutely required to connect the Phase 4 API.

## Security Requirements

Uploaded source code remains untrusted.

* Never execute uploaded application code.
* Never import uploaded application code.
* Never run uploaded scripts or binaries.
* Do not install dependencies from uploaded projects.
* Do not introduce arbitrary shell execution.
* Preserve the security protections implemented in Phase 3.

## Implementation Requirements

Before modifying anything:

1. Inspect the existing backend structure.
2. Inspect the existing upload endpoint and storage behavior.
3. Inspect the existing React API service only as necessary to understand the current contract.
4. Reuse existing functionality instead of creating duplicate upload/scan logic.
5. Make the smallest correct changes required for Phase 4.

Do not restructure the backend unnecessarily.

Do not create speculative abstractions for future phases.

## Testing

After implementation:

1. Start the FastAPI backend.
2. Verify `POST /api/scans`.
3. Verify `GET /api/scans`.
4. Verify `GET /api/scans/{scan_id}`.
5. Verify `GET /api/scans/{scan_id}/status`.
6. Verify valid scan lifecycle states.
7. Verify invalid/nonexistent scan IDs are handled correctly.
8. Verify existing `/api/health` still works.
9. Verify Phase 3 upload functionality still works.
10. Verify the frontend still builds successfully.
11. Check for obvious errors, regressions, or duplicated functionality.

Do not claim a test passed unless it was actually run.

## Completion

After implementation:

1. Briefly report what was changed.
2. List the files created or modified.
3. Report the tests performed and their results.
4. Report any issues or limitations.
5. Confirm that Phases 1–3 remain intact.
6. **STOP.**

**Do not proceed to Phase 5 automatically.**

Wait for my next instruction.

# STRICT TOKEN-EFFICIENCY AND EXECUTION RULES

These rules are mandatory for every development phase.

## 1. NEVER IMPLEMENT FUTURE PHASES

Only implement the explicitly requested current phase.

If the current task is Phase 1, do not prepare code for Phase 2, 3, 4, etc.

Do not create placeholder implementations for future systems unless the current phase explicitly requires them.

## 2. INSPECT FIRST, THEN CODE

Before writing code:

* inspect only the files relevant to the current task
* understand the existing structure
* identify what must actually change

Do not scan or reproduce the entire repository unnecessarily.

## 3. MINIMUM REQUIRED CODE

Use the smallest clean implementation that satisfies the current requirement.

Do not over-engineer.

Do not create:

* unnecessary abstractions
* unnecessary helper files
* unnecessary classes
* unused interfaces
* unused configuration
* speculative utilities

## 4. DO NOT REGENERATE UNCHANGED CODE

If a file already contains correct code, leave it alone.

When modifying a file, change only the necessary section.

Do not output entire large files when only a few lines need changing.

## 5. MINIMUM DEPENDENCIES

Before installing a package, ask:

> Is this dependency required for the CURRENT phase?

If no, do not install it yet.

## 6. TEST IMMEDIATELY

After making a small implementation:

1. run the relevant command/test
2. inspect the result
3. fix only issues caused by the current change
4. verify again

Do not continue building more features on top of unverified code.

## 7. STOP AFTER SUCCESS

When the current milestone works:

**STOP.**

Do not automatically continue to the next milestone.

Do not "helpfully" implement future features.

Wait for the user.

## 8. STOP ON UNCERTAINTY

If you cannot confidently determine what the existing code is supposed to do:

**STOP AND ASK.**

Do not guess.

## 9. STOP ON ARCHITECTURAL PROBLEMS

If implementation reveals:

* conflicting files
* duplicated architecture
* incompatible dependencies
* unclear API contracts
* unexpected existing backend code
* a need for a major rewrite

STOP.

Explain the issue concisely.

Do not generate hundreds of lines attempting to work around an unknown problem.

## 10. BAD CODE MUST BE TRUNCATED

If generated implementation begins becoming:

* repetitive
* speculative
* unnecessarily complex
* inconsistent with the blueprint
* difficult to maintain
* dependent on unnecessary assumptions

STOP generating code.

Keep the implementation at the last known-good point.

Explain what caused the issue and wait for instructions.

## 11. RESPONSE SIZE

After implementation, report only:

```text
Completed:
- ...

Files changed:
- ...

Dependencies:
- ...

Tests:
- ...

Result:
- ...

Issues:
- ...
```

Do not provide long explanations unless requested.

## 12. NO TOKEN WASTE FOR DOCUMENTATION

Do not generate extensive documentation during implementation.

Documentation should be minimal and relevant to the current milestone.

## 13. NO DUPLICATE SOLUTIONS

Never implement two different approaches to solve the same problem unless explicitly asked to compare them.

Choose one appropriate solution and test it.

## 14. DO NOT OPTIMIZE PREMATURELY

First make the smallest correct implementation.

Do not add performance infrastructure, caching, queues, workers, microservices, or complex abstractions unless the current requirements actually need them.

## 15. MAINTAIN A SMALL CHANGE SURFACE

Every change should answer:

> "Why is this file/code being changed for the current milestone?"

If there is no clear answer, do not change it.

---

# EXECUTION LOOP

For every milestone, follow exactly:

```text
READ CURRENT REQUIREMENT
        ↓
INSPECT RELEVANT FILES
        ↓
PLAN MINIMAL CHANGE
        ↓
IMPLEMENT
        ↓
TEST
        ↓
FIX CURRENT ISSUE ONLY
        ↓
TEST AGAIN
        ↓
REPORT BRIEFLY
        ↓
STOP
```

Never skip the STOP step.

The user will explicitly authorize the next milestone.


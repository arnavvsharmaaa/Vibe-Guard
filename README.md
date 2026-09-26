
# Vibe Guard

## AI-Powered Secure Code Auditor for AI-Generated Applications

Vibe Guard is a security analysis platform designed to identify common
security vulnerabilities in AI-generated and AI-assisted application code.

The system combines deterministic static security analysis with
AI-assisted contextual analysis and remediation guidance.

---

# 1. Project Overview

AI-generated code can introduce security vulnerabilities that may not be
obvious during development.

Vibe Guard is designed to provide a workflow that allows developers to:

- Upload application source code
- Analyze source code using static security analysis
- Detect common security vulnerabilities
- Normalize security findings
- Generate a deterministic security score
- Use AI to explain detected vulnerabilities
- Generate remediation recommendations
- View security reports through a developer-focused React interface

Uploaded application code is treated as **untrusted input** and must never
be executed by Vibe Guard.

---

# 2. Project Architecture

```text
                         VIBE GUARD

                    React Frontend
                         │
                         ▼
                   FastAPI Backend
                         │
                         ▼
                Secure File Handling
                         │
                         ▼
                  Scan Lifecycle
                         │
                         ▼
              Static Security Analysis
                         │
                         ▼
                Finding Normalization
                         │
                         ▼
              Deterministic Security Score
                         │
                         ▼
                AI Contextual Analysis
                         │
                         ▼
                      Database
                         │
                         ▼
                    Report API
                         │
                         ▼
                  React Frontend
````

### Important Architecture Principle

The AI layer is an analysis and remediation assistant.

AI is **not** the sole vulnerability detector and must not determine the
security score.

The deterministic security-analysis pipeline remains the primary source
of security findings.

---

# 3. Repository Structure

The current repository uses a **root-level React/Vite frontend** and a
separate FastAPI backend.

```text
Vibe-Guard/
│
├── .cursor/                           # Cursor project configuration
│
├── backend/                           # FastAPI backend
│   ├── main.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── README.md
│   ├── uploads/                       # Runtime upload storage
│   └── ...
│
├── src/                               # React frontend source
│   ├── components/
│   ├── pages/
│   ├── services/
│   └── ...
│
├── dist/                              # Frontend build output
├── node_modules/                      # Local npm dependencies
│
├── .gitignore
├── Blueprint.md                       # 🔒 MASTER BLUEPRINT
├── DESIGN.md                          # Design/reference documentation
├── code.html
├── index.html
├── package.json
├── package-lock.json
├── screen.png
├── Vibe_Guard_Development_Status.md   # 📝 IMPLEMENTATION STATUS
├── vibe_guard_react_ui_blueprint.md   # 🎨 FRONTEND UI REFERENCE
└── vite.config.js
```

> `node_modules/` and generated build output such as `dist/` should
> normally not be committed to Git. The repository `.gitignore` should
> handle these directories.

---

# 4. DOCUMENT HIERARCHY

This section is **important for every contributor and AI coding agent**.

Vibe Guard uses separate documents for:

1. Architecture
2. Implementation progress
3. Frontend/UI reference

These documents do **not** have equal authority.

## Authority Hierarchy

```text
                 ┌────────────────────────────┐
                 │        Blueprint.md         │
                 │                            │
                 │ 🔒 MASTER / ARCHITECTURE   │
                 │       SOURCE OF TRUTH      │
                 └─────────────┬──────────────┘
                               │
                               ▼
                 ┌────────────────────────────┐
                 │ Vibe_Guard_Development_    │
                 │ Status.md                  │
                 │                            │
                 │ 📝 VERIFIED IMPLEMENTATION │
                 │        PROGRESS            │
                 └─────────────┬──────────────┘
                               │
                               ▼
                 ┌────────────────────────────┐
                 │ vibe_guard_react_ui_       │
                 │ blueprint.md               │
                 │                            │
                 │ 🎨 FRONTEND/UI REFERENCE  │
                 └─────────────┬──────────────┘
                               │
                               ▼
                         Actual Code
```

---

# 5. Blueprint.md — MASTER BLUEPRINT 🔒

`Blueprint.md` is the **architectural source of truth** for Vibe Guard.

It defines:

* Product architecture
* Backend architecture
* Technology choices
* Security principles
* Development roadmap
* API contracts
* Development rules
* Phase requirements
* Final definition of done

## Master Blueprint Integrity Rule

The master blueprint must **not be automatically rewritten or modified by
AI agents**.

Do not:

* Rewrite the architecture
* Reorder phases
* Remove requirements
* Change security principles
* Change technology decisions
* Modify future-phase requirements
* Silently alter API contracts
* Remove requirements because they are inconvenient
* Replace the roadmap with a newly generated architecture

If implementation reveals a genuine architectural problem:

1. Stop.
2. Document the problem.
3. Explain the proposed change.
4. Record affected phases.
5. Get approval from the project owner.
6. Only then modify the master blueprint if approved.

The master blueprint is considered **locked unless explicitly changed by
the project owner**.

---

# 6. Vibe_Guard_Development_Status.md — IMPLEMENTATION STATUS 📝

`Vibe_Guard_Development_Status.md` tracks the **actual verified state of
the project**.

It records:

* Completed phases
* Current phase
* Files changed
* Tests performed
* Test results
* Known issues
* Implementation notes
* Proposed architectural changes

This file may be updated after completing a development phase.

## Important

The status file does **not** override the master blueprint.

It records what has actually been implemented.

A phase is only considered complete after its implementation has been
tested and verified.

---

# 7. vibe_guard_react_ui_blueprint.md — FRONTEND REFERENCE 🎨

This document describes the Review 1 React frontend, including:

* Visual design
* Pages
* Routes
* Components
* UI structure
* Mock data
* User flow
* Security report interface
* Vulnerability detail interface
* AI remediation interface

The React frontend is already implemented.

Therefore, this document is primarily a **reference for the existing
frontend**, not an instruction to rebuild it.

## Frontend Rule

Do not redesign or replace the existing React interface.

Future backend development must work **behind the existing UI**.

Only make frontend changes when they are genuinely required for backend
integration, and keep those changes as small as possible.

---

# 8. Document Conflict Rule

If documents appear to conflict, use the following order:

```text
1. Explicit instruction from project owner
              ↓
2. Blueprint.md
              ↓
3. Vibe_Guard_Development_Status.md
              ↓
4. vibe_guard_react_ui_blueprint.md
              ↓
5. AI assumptions
```

AI agents must **never resolve an architectural conflict by guessing**.

If the conflict cannot be resolved from the authoritative sources:

**STOP and ask for clarification.**

---

# 9. Current Project Status

## Frontend

**Status: ✅ COMPLETE**

The Review 1 React frontend is implemented and serves as the canonical
Vibe Guard interface.

The frontend currently contains the established Review 1 experience,
including:

* Dashboard
* New Scan
* Scan Progress
* Security Report
* Vulnerability Detail
* Reports
* Scan History
* Settings
* Existing navigation and UI components
* Mock security findings and report data

The existing UI should be preserved while backend functionality is built.

---

## Backend

| Phase                                 | Status     |
| ------------------------------------- | ---------- |
| Phase 1 — FastAPI Foundation          | ✅ Complete |
| Phase 2 — React ↔ FastAPI Connection  | ✅ Complete |
| Phase 3 — Secure Code Upload          | ✅ Complete |
| Phase 4 — Scan Lifecycle              | 🔴 Current |
| Phase 5 — Static Analysis             | ⏳ Pending  |
| Phase 6 — Finding Normalization       | ⏳ Pending  |
| Phase 7 — Security Score              | ⏳ Pending  |
| Phase 8 — AI Contextual Analysis      | ⏳ Pending  |
| Phase 9 — Database                    | ⏳ Pending  |
| Phase 10 — Report API                 | ⏳ Pending  |
| Phase 11 — Replace Frontend Mock Data | ⏳ Pending  |
| Phase 12 — Testing                    | ⏳ Pending  |
| Phase 13 — Security Hardening         | ⏳ Pending  |
| Phase 14 — Docker / Deployment        | ⏳ Pending  |

For exact verified implementation details, always check:

`Vibe_Guard_Development_Status.md`

---

# 10. Completed Backend Work

## Phase 1 — FastAPI Foundation

Status: **✅ COMPLETE**

Implemented:

* FastAPI backend
* Uvicorn setup
* CORS
* `/api/health`
* `/docs`
* Backend requirements
* `.env.example`
* Backend README
* Basic backend structure

Verified:

* `/api/health` returns HTTP 200
* `/docs` is accessible
* Frontend build succeeds

---

## Phase 2 — React ↔ FastAPI Connection

Status: **✅ COMPLETE**

Implemented:

* Frontend API service
* React → FastAPI health connection
* CORS communication
* Backend/frontend connectivity

Verified:

* React successfully communicates with FastAPI
* `/api/health` returns the expected response
* CORS works for the local React development server
* Frontend build succeeds

---

## Phase 3 — Secure Code Upload

Status: **✅ COMPLETE**

Implemented:

* `POST /api/scan/upload` (removed in Phase 13; uploads now go only through `POST /api/scans`)
* Multipart file upload
* Source/config extension allowlist
* 5 MB maximum upload size
* Chunked upload handling
* Filename sanitization
* Path traversal protection
* UUID-based server-side identification
* Isolated upload storage
* Runtime upload directory
* Uploaded code treated as untrusted data
* Uploaded code is not executed or imported

Verified:

* Valid source upload succeeds
* Unsupported file types are rejected
* Path traversal filenames are handled safely
* Oversized uploads are rejected
* Health endpoint continues to work
* Frontend build succeeds
* Temporary test uploads are cleaned up

---

# 11. Development Method

Vibe Guard is developed **one phase at a time**.

The standard development loop is:

```text
Read Master Blueprint
        ↓
Read Development Status
        ↓
Inspect Existing Code
        ↓
Implement ONLY Current Phase
        ↓
Run Relevant Tests
        ↓
Verify Results
        ↓
Update Development Status
        ↓
STOP
```

## Important

Do not automatically proceed to the next phase.

Do not implement future phases early.

Do not rebuild completed phases unless an actual bug or missing
requirement is discovered.

---

# 12. Current Development Phase

## Phase 4 — Scan Lifecycle

The current authorized backend phase is:

**Scan Lifecycle**

### Required statuses

```text
uploaded
queued
scanning
analyzing
completed
failed
```

### Required endpoints

```text
POST /api/scans

GET /api/scans

GET /api/scans/{scan_id}

GET /api/scans/{scan_id}/status
```

The lifecycle must use real backend state.

Do not use fake delays, timers, or artificial progress merely to make the
frontend appear to be scanning.

## Phase 4 Scope

Implement only:

* Scan creation
* Scan identification
* Scan state management
* Scan retrieval
* Scan listing
* Scan status retrieval
* Proper handling of nonexistent scan IDs
* Integration with the existing secure upload functionality where required

The implementation should be structured so later phases can attach:

* Static analysis
* Finding normalization
* Security scoring
* AI analysis
* Database persistence
* Report generation

However, those systems are **not part of Phase 4**.

---

# 13. Do NOT Implement Future Phases Early

During Phase 4, do **not** implement:

* Semgrep
* Bandit
* Static vulnerability analysis
* Finding normalization
* Security scoring
* AI analysis
* Database persistence unless strictly required for Phase 4
* Report APIs
* Docker
* Authentication
* Deployment
* New frontend screens
* Frontend redesign
* Fake scanner results
* Fake vulnerability findings

These belong to later phases.

---

# 14. Security Principles

Security is a core requirement of Vibe Guard.

Uploaded application code is **untrusted input**.

Vibe Guard must never:

* Execute uploaded applications
* Execute uploaded scripts
* Import uploaded application code
* Execute uploaded binaries
* Execute uploaded builds
* Install dependencies from uploaded projects
* Execute arbitrary commands from submitted projects

Static analysis must inspect source code without executing the submitted
application.

## Input Security

External input must be validated.

This includes:

* Uploaded filenames
* Uploaded file types
* Upload sizes
* API parameters
* Scan identifiers
* Configuration values

## Secret Security

Secrets must never be exposed through:

* Frontend code
* API responses
* Logs
* Git repositories
* Client-side environment variables

AI API keys must remain on the backend.

---

# 15. Contribution Workflow

Every contributor should follow this workflow.

## Before Starting

1. Read `README.md`.
2. Read `Blueprint.md`.
3. Read `Vibe_Guard_Development_Status.md`.
4. Identify the currently active phase.
5. Read the relevant section of `vibe_guard_react_ui_blueprint.md` if
   frontend integration is involved.
6. Inspect the existing code before modifying it.

## While Working

* Work only on the assigned task.
* Implement only the current phase.
* Reuse existing functionality where possible.
* Avoid unnecessary abstractions.
* Avoid unnecessary dependencies.
* Preserve existing frontend behavior.
* Do not silently change architecture.
* Do not implement future phases.

## After Working

1. Run relevant tests.
2. Verify the implementation actually works.
3. Record important changes.
4. Update the development status when the phase is verified.
5. Create a Pull Request.
6. Wait for review before merging.

---

# 16. Git Workflow

Contributors should work on their own feature branch.

Create a branch:

```bash
git checkout -b feature/your-feature-name
```

Example:

```bash
git checkout -b feature/scan-lifecycle
```

After making changes:

```bash
git add .
git commit -m "Implement scan lifecycle"
git push origin feature/scan-lifecycle
```

Then create a Pull Request.

## Main Branch

Avoid pushing directly to `main`.

The `main` branch should contain reviewed and verified changes.

Recommended workflow:

```text
main
 │
 ├── feature/member-task-1
 │
 ├── feature/member-task-2
 │
 └── feature/member-task-3
          │
          ▼
     Pull Request
          │
          ▼
       Review
          │
          ▼
        Merge
```

---

# 17. Architectural Change Policy

If a contributor or AI agent discovers that an architectural change may
be necessary:

**Do not modify `Blueprint.md` immediately.**

Instead, document the proposal in the development status file:

```text
Proposed Blueprint Change

Current requirement:
...

Observed problem:
...

Proposed change:
...

Reason:
...

Affected phases:
...

Potential risks:
...
```

Then stop and discuss the change with the project owner.

Only after explicit approval should the master blueprint be modified.

---

# 18. Technology Stack

## Frontend

* React
* Vite
* JavaScript

## Backend

* Python
* FastAPI
* Uvicorn
* Pydantic

## Static Security Analysis

* Semgrep
* Bandit

## Database

* SQLite for initial development
* PostgreSQL-compatible architecture for later deployment

## AI

* AI provider accessed through the backend
* API keys stored only server-side

## Deployment

* Docker
* AWS or another suitable deployment platform

Deployment will only be addressed after the core system is stable.

---

# 19. Local Development

## Frontend

The React/Vite application is located at the repository root.

From the repository root:

```bash
npm install
npm run dev
```

Build the frontend:

```bash
npm run build
```

---

## Backend

Navigate to the backend:

```bash
cd backend
```

Create the Python virtual environment if necessary.

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start FastAPI:

```bash
uvicorn main:app --reload
```

Backend:

```text
http://localhost:8000
```

FastAPI documentation:

```text
http://localhost:8000/docs
```

Health endpoint:

```text
http://localhost:8000/api/health
```

---

# 20. Expected Final Pipeline

The completed Vibe Guard system should provide a real security-analysis
pipeline:

```text
Upload Application Code
          ↓
Secure File Handling
          ↓
Scan Lifecycle
          ↓
Static Security Analysis
          ↓
Finding Normalization
          ↓
Deterministic Security Score
          ↓
AI Contextual Analysis
          ↓
Remediation Guidance
          ↓
Database
          ↓
Report API
          ↓
Existing React Interface
```

The final product should demonstrate a **real security-analysis pipeline**,
not merely mock vulnerability findings.

---

# 21. Supported Vulnerability Scope

The planned initial vulnerability scope includes:

1. SQL Injection
2. Cross-Site Scripting
3. Hardcoded passwords/API keys/secrets
4. Command Injection
5. Insecure Authentication
6. Weak Encryption/Cryptography
7. Path Traversal

This is an initial supported scope.

Vibe Guard must **not** claim universal vulnerability detection.

---

# 22. AI Security Principles

AI is used to provide contextual analysis and remediation assistance.

The planned AI pipeline is:

```text
Static Finding
      ↓
Relevant Source Context
      ↓
AI Analysis
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
```

AI should explain:

* Why the code is vulnerable
* Potential security impact
* Why the scanner detected it
* Recommended solution
* Suggested corrected code
* Remediation steps

AI output is advisory.

AI must not override deterministic scanner findings or arbitrarily
generate the security score.

Correct architecture:

```text
React
  ↓
FastAPI
  ↓
AI Provider
```

Never:

```text
React
  ↓
AI Provider
```

AI credentials must remain on the backend.

---

# 23. Testing Philosophy

A phase is not complete simply because code has been written.

Each phase must be tested against its actual requirements.

Testing should include:

* Normal behavior
* Invalid input
* Error handling
* Security edge cases
* Regression of previously completed phases
* Frontend/backend compatibility where applicable

The final project should test the complete pipeline:

```text
Upload
  ↓
Scan
  ↓
Static Analysis
  ↓
Findings
  ↓
Score
  ↓
AI
  ↓
Database
  ↓
Report
  ↓
React
```

Do not claim a feature is complete unless it has actually been verified.

---

# 24. Final Definition of Done

Vibe Guard is complete when the system can support:

```text
React
  ↓
Upload Project
  ↓
Secure File Handling
  ↓
Scan Lifecycle
  ↓
Static Analysis
  ↓
Normalized Findings
  ↓
Deterministic Security Score
  ↓
AI Contextual Analysis
  ↓
Database Persistence
  ↓
Report API
  ↓
Existing React UI
```

The system must:

* Perform actual static security analysis
* Produce structured vulnerability findings
* Generate a deterministic and explainable security score
* Provide AI-assisted contextual analysis
* Provide remediation guidance
* Persist relevant scan/report data
* Serve real report data to the frontend
* Preserve the existing Review 1 frontend
* Treat uploaded code as untrusted
* Never execute submitted application code
* Pass relevant security and integration tests
* Be reproducibly deployable after the core system is stable

---

# 25. Final Contributor Rule

Before making any change, remember:

```text
                ┌─────────────────────┐
                │    Blueprint.md     │
                │                     │
                │ 🔒 ARCHITECTURE     │
                │    SOURCE OF TRUTH  │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Development Status  │
                │                     │
                │ 📝 WHAT IS VERIFIED │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Current Phase       │
                │                     │
                │ 🎯 WHAT TO BUILD    │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Existing Code       │
                │                     │
                │ 💻 IMPLEMENTATION   │
                └─────────────────────┘
```

**Inspect → Follow the hierarchy → Implement only the current phase → Test → Document → Stop.**



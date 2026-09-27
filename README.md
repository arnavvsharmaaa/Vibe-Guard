
# Vibe Guard

## AI-Powered Secure Code Auditor for AI-Generated Applications

Vibe Guard is a security analysis platform designed to identify common
security vulnerabilities in AI-generated and AI-assisted application code.

The system combines deterministic static security analysis with
AI-assisted contextual analysis and remediation guidance.

## 🚀 Live Demo

**[Try Vibe Guard](https://vibe-guard-7c4d.onrender.com/)**

Vibe Guard is currently deployed as a public demonstration on Render.

**Links:** [Live Demo](https://vibe-guard-7c4d.onrender.com/) ·
[GitHub repository](https://github.com/arnavvsharmaaa/Vibe-Guard) ·
[Architecture](#2-project-architecture) ·
[Master Blueprint](Blueprint.md) ·
[Verified development status](Vibe_Guard_Development_Status.md) ·
[Backend documentation](backend/README.md) ·
[Render deployment](#demo-deployment-render--phase-14a)

### Project Status

**Phase 14a — COMPLETE**
Public demo deployed and verified live on Render.

Phases 1–13 (upload, scan lifecycle, static analysis, normalization, scoring,
AI analysis, database, report API, frontend integration, testing and security
hardening) are complete. Phase 14b (PostgreSQL + Docker Compose) has not
started. The backend test suite passes on Linux in Docker (261/261).

**Current stack:**
React/Vite • FastAPI • Python • Semgrep • Bandit • Groq • SQLite • Docker • Render

### What it does

```text
Upload code (ZIP or source file) → secure extraction (never executed)
  → Semgrep + Bandit static analysis → normalized, deduplicated findings
  → deterministic security score → Groq-assisted explanation and remediation
  → security report and finding details in the React UI
```

* **Languages (demo-tested):** Python, Java, JavaScript, JSX
* **Vulnerability scope:** SQL Injection, Cross-Site Scripting, Hardcoded Secrets,
  Command Injection, Insecure Authentication, Weak Cryptography, Path Traversal
* **AI is advisory:** the security score is computed deterministically from the
  static findings; the AI explains and suggests fixes but never sets the score

### Demo limitations

This is a public demonstration, not production infrastructure
(details: [Demo deployment (Render)](#demo-deployment-render--phase-14a)):

* No authentication or user isolation — every visitor can see every scan
* Free-tier SQLite persistence is not guaranteed — scans and reports are lost on
  redeploys, restarts and spin-downs
* One active scan at a time, and 5 scan submissions per 10 minutes per IP
* Do not upload confidential, proprietary or sensitive source code

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
├── backend/                           # FastAPI backend
│   ├── main.py                        # API, scan lifecycle, upload handling, limits
│   ├── scanners.py                    # Semgrep + Bandit execution
│   ├── normalization.py               # Finding normalization/deduplication
│   ├── scoring.py                     # Deterministic security score
│   ├── ai_analysis.py                 # Groq contextual analysis (server-side)
│   ├── database.py                    # SQLAlchemy models (SQLite)
│   ├── semgrep_rules/                 # Vibe Guard Semgrep rules
│   ├── tests/                         # Backend test suite
│   ├── Dockerfile                     # Backend container (Phase 14a)
│   ├── requirements.txt
│   ├── .env.example
│   ├── README.md
│   ├── uploads/                       # Runtime upload storage (not committed)
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
├── render.yaml                        # Render Blueprint (public demo)
├── screen.png                         # Early design mockup (not the current UI)
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
Vibe Guard interface. Since Phase 11 it uses real backend data instead of
mock data.

The frontend contains the established Review 1 experience, including:

* Dashboard
* New Scan
* Scan Progress
* Security Report
* Vulnerability Detail
* Reports
* Scan History
* Settings
* Existing navigation and UI components
* Public-demo notice (shown when built with `VITE_PUBLIC_DEMO=true`)

The existing UI should be preserved.

---

## Backend / Implementation Status

| Phase | Status |
| ----- | ------ |
| Phase 1 — FastAPI Foundation | ✅ Complete |
| Phase 2 — React ↔ FastAPI Connection | ✅ Complete |
| Phase 3 — Secure Code Upload | ✅ Complete |
| Phase 4 — Scan Lifecycle | ✅ Complete |
| Phase 5 — Static Analysis | ✅ Complete |
| Phase 6 — Finding Normalization | ✅ Complete |
| Phase 7 — Security Score | ✅ Complete |
| Phase 8 — AI Contextual Analysis | ✅ Complete |
| Phase 9 — Database | ✅ Complete |
| Phase 10 — Report API | ✅ Complete |
| Phase 11 — Replace Frontend Mock Data | ✅ Complete |
| Phase 12 — Testing & Security Hardening | ✅ Complete |
| Phase 13 — Security Hardening | ✅ Complete |
| Phase 14a — Demo Deployment Preparation | ✅ Complete — deployed and verified live |
| Phase 14b — PostgreSQL + Docker Compose | ⏳ Not Started |

For exact verified implementation details, tests, deployment checks, known limitations, and commit references, see:

`Vibe_Guard_Development_Status.md`

---

# 10. Completed Implementation

All phases through **Phase 14a** have been implemented and verified.

## Phase 1 — FastAPI Foundation

Status: **✅ COMPLETE**

Implemented the FastAPI backend foundation, Uvicorn setup, CORS, health endpoint, environment configuration, backend requirements, and basic backend structure.

## Phase 2 — React ↔ FastAPI Connection

Status: **✅ COMPLETE**

Implemented the frontend API service and verified React-to-FastAPI communication and CORS integration.

## Phase 3 — Secure Code Upload

Status: **✅ COMPLETE**

Implemented secure ZIP upload and extraction with:

- Upload size limits
- Filename/path validation
- Path traversal protection
- ZIP validation
- File/member and extracted-size limits
- UUID-based scan directories
- Source isolation
- Untrusted-code handling
- No execution or import of uploaded application code

The legacy upload route was removed in Phase 13; current uploads use `POST /api/scans`.

## Phase 4 — Scan Lifecycle

Status: **✅ COMPLETE**

Implemented real scan lifecycle management:

```text
uploaded → queued → scanning → analyzing → completed
                                      ↘ failed
```

Implemented scan creation, retrieval, listing, status polling, concurrency handling, and terminal-state management.

## Phase 5 — Static Analysis

Status: **✅ COMPLETE**

Implemented Semgrep and Bandit scanning with local Vibe Guard rules, scanner isolation, timeouts, failure handling, and raw scanner output handling.

Current demonstrated language coverage includes:

- Python
- Java
- JavaScript
- JSX

The language set is intentionally extensible and will be expanded in future phases.

## Phase 6 — Finding Normalization

Status: **✅ COMPLETE**

Implemented a common finding schema, severity normalization, category mapping, path confinement, bounded snippets, duplicate merging, deterministic public finding IDs, and malformed-finding handling.

## Phase 7 — Security Score

Status: **✅ COMPLETE**

Implemented deterministic and explainable security scoring based on finding severity and count.

AI output does not control the security score.

## Phase 8 — AI Contextual Analysis

Status: **✅ COMPLETE**

Integrated server-side Groq analysis for contextual vulnerability explanations and remediation guidance.

AI is advisory only:

```text
Static Finding
      ↓
Relevant Source Context
      ↓
AI Analysis
      ↓
Explanation / Impact / Remediation
```

AI credentials remain server-side, findings are bounded before analysis, and rate-limit handling is implemented.

## Phase 9 — Database

Status: **✅ COMPLETE**

Implemented SQLAlchemy-based persistence with SQLite and a PostgreSQL-compatible architecture.

Persisted data includes scans, findings, deterministic scores, and AI analysis results.

## Phase 10 — Report API

Status: **✅ COMPLETE**

Implemented read-only report endpoints for completed scans and individual findings. Report data is served from the database rather than raw scanner output.

## Phase 11 — Frontend Integration

Status: **✅ COMPLETE**

Replaced the Review 1 mock-data flow with the real backend while preserving the existing React interface.

The frontend now supports real:

- Scan creation
- Scan progress polling
- Reports
- Findings
- AI recommendations
- Scan history

## Phase 12 — Testing & Security Hardening

Status: **✅ COMPLETE**

Completed comprehensive backend regression testing, frontend builds, live HTTP/browser checks, and security-hardening fixes covering upload handling, archive extraction, path validation, oversized requests, environment secrets, and repository hygiene.

## Phase 13 — Security Hardening

Status: **✅ COMPLETE**

Completed deployment-oriented security hardening including:

- Localhost-by-default backend binding
- Restricted production CORS
- Host allowlisting
- Removal of the legacy upload endpoint
- Uploaded-source cleanup after terminal scans
- Pinned runtime dependencies
- Updated deployment/security documentation

## Phase 14a — Demo Deployment Preparation

Status: **✅ COMPLETE — deployed and verified live**

Vibe Guard is publicly deployed as a demo using:

- React/Vite static site
- Dockerized FastAPI backend
- Semgrep + Bandit
- SQLite
- Groq AI
- Render

Deployment hardening includes:

- Non-root Docker execution
- Resource controls
- One active scan at a time
- 5 scan submissions per client address per 10 minutes
- `429` / `503` responses with `Retry-After`
- Production CORS and Host controls
- Disabled public API documentation
- Source cleanup
- Public-demo warning
- Server-side AI credentials

The deployment was Docker/Linux validated and then verified live on Render.

## Current Phase

**Phase 14b — PostgreSQL + Docker Compose**

Status: **⏳ NOT STARTED**

Phase 14b is intentionally separate from the completed public demo deployment. It will introduce PostgreSQL and Docker Compose as the next infrastructure milestone.

Do not assume Phase 14b or later phases are implemented until the development-status document records them as verified.

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

Do not rebuild completed phases unless an actual bug or missing requirement is discovered.

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

* SQLite for the current public demo
* PostgreSQL-compatible architecture
* PostgreSQL planned for Phase 14b

## AI

* Groq accessed through the backend
* API keys stored only server-side

## Deployment

* Docker
* Render for the current public demo
* Docker Compose + PostgreSQL planned for Phase 14b

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

FastAPI documentation (only served when the backend runs with `ENABLE_DOCS=1`):

```text
http://localhost:8000/docs
```

Health endpoint:

```text
http://localhost:8000/api/health
```

---

## Demo deployment (Render) — Phase 14a

A free, public **demo** deployment. It is not production infrastructure (PostgreSQL and Docker Compose are Phase 14b).

```text
Render Static Site (free)              Render Web Service (free, Docker)
React/Vite dist/  ── HTTPS ──►  FastAPI (1 worker) + Semgrep + Bandit
VITE_API_URL set at build time         SQLite + scan files on the container's ephemeral disk
                                       Groq (optional, server-side key only)
```

Everything is described in `render.yaml` (a Render Blueprint). Service URLs and the Groq key are **not** in the
repository; Render asks for them when the Blueprint is created (`sync: false`).

1. Render dashboard → **New → Blueprint** → select this repository. It creates `vibe-guard-api` (Docker, built from
   `backend/Dockerfile`, health check `/api/health`) and `vibe-guard` (static site: `npm ci && npm run build`,
   publishes `dist/`, rewrites every path to `/index.html` for client-side routes).
2. When prompted, enter:
   - `vibe-guard-api` → `ALLOWED_ORIGINS` = `https://<static site>.onrender.com`,
     `ALLOWED_HOSTS` = `<api service>.onrender.com`, `GROQ_API_KEY` = a demo key (optional; leave empty to disable AI)
   - `vibe-guard` → `VITE_API_URL` = `https://<api service>.onrender.com`

   If Render added a suffix to a service name, use the URLs Render shows. `VITE_API_URL` is baked into the bundle, so
   changing it requires a new static-site deploy.
3. Deploy both services (auto-deploy is off; deploy from the dashboard).

Demo behaviour and limits:
- **No persistence guarantee.** The free instance has no persistent disk: the SQLite database, reports and scan files
  are lost on every deploy, restart and free-tier spin-down (after about 15 minutes without traffic). The first request
  after a spin-down can take a minute.
- **Public data.** There is no authentication: every visitor can see every scan and its code snippets. The frontend
  shows a public-demo notice (`VITE_PUBLIC_DEMO=true`).
- **Abuse limits.** One scan at a time (`503` + `Retry-After` while busy); 5 scan submissions per client address per
  10 minutes (`429` + `Retry-After`); the existing 5 MB upload, 1000 file and 50 MB extraction limits;
  `AI_MAX_FINDINGS=10`. Use a Groq key on an account without billing so abuse cannot create costs.
- `/docs`, `/redoc` and `/openapi.json` are disabled; CORS allows only the static site; other `Host` headers get `400`.
- HTTPS is provided by Render for both `*.onrender.com` services.

After deploying, check: `/api/health` → 200; `/docs` → 404; a direct link to `/reports/<id>` loads; a scan
completes; a request from another origin gets no `Access-Control-Allow-Origin`; and that 6 quick submissions from one
browser get `429` even with a made-up `X-Forwarded-For` header (confirms the client address comes from
`CLIENT_IP_HEADER=CF-Connecting-IP`; Render's proxies append rotating internal addresses to `X-Forwarded-For`, so no
fixed `TRUSTED_PROXY_HOPS` value identifies the client there). Render's health checks send the service host name,
so `ALLOWED_HOSTS` does not affect them.

Rollback: Render keeps previous deploys (**Rollback** on the service's Events page); a bad backend deploy that fails
`/api/health` never receives traffic. To take the demo offline, suspend the services. To revoke AI access, delete or
rotate `GROQ_API_KEY`; scans still complete without AI.

Backend Docker details (local build, resource test, settings): `backend/README.md`, section 8.

---

# 20. Verified / Expected Pipeline

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

The initial vulnerability scope is:

1. SQL Injection
2. Cross-Site Scripting
3. Hardcoded passwords/API keys/secrets
4. Command Injection
5. Insecure Authentication
6. Weak Encryption/Cryptography
7. Path Traversal

This is an initial supported scope, currently covered for Python, Java,
JavaScript and JSX code.

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
* Maintain the verified public demo deployment where applicable

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



# Vibe Guard Backend

FastAPI backend for Vibe Guard - AI-Powered Secure Code Auditor.

## Setup & Running (Phase 1)

### 1. Create and Activate Virtual Environment
\\\ash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
\\\

### 2. Install Dependencies
\\\ash
pip install -r requirements.txt
\\\

### 3. Run Development Server
\\\ash
python main.py
# or
uvicorn main:app --reload --host 0.0.0.0 --port 8000
\\\

### 4. Endpoints
- Health check: \GET http://localhost:8000/api/health\
- Interactive API Docs: \http://localhost:8000/docs\

### 5. AI Contextual Analysis (Phase 8, optional)
After scoring, each finding can be explained by Groq (advisory only; it never changes findings or the score).
Set these in the backend process environment (`.env` is not loaded automatically):

| Variable | Default | Purpose |
|---|---|---|
| `GROQ_API_KEY` | *(empty)* | Groq API key. If unset, AI analysis is `disabled` and no request is made. |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Groq model ID. |
| `AI_TIMEOUT_SECONDS` | `30` | Per-request timeout (max 120). Whole scan budget is 180 s. |
| `AI_MAX_FINDINGS` | `25` | Findings analyzed per scan, most severe first (max 100); the rest are `skipped`. |

Only the finding metadata, its relative path, and about ±5 lines of redacted code are sent per request.
Results are written to `uploads/{scan_id}/results/ai_analysis.json`. The key is never logged or stored.

### 6. Database (Phase 9)
Scans, normalized findings, the security score and AI analysis results are stored with SQLAlchemy 2.0.
SQLite is the default; tables are created automatically on startup (no migration tool yet).

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | *(empty)* → `sqlite:///<backend>/vibe_guard.db` | SQLAlchemy URL. Generic column types only, so a PostgreSQL URL also works (with a driver installed). |

Tables: `scans` → `findings` (internal integer `id`, public `finding_id` such as `VG-001`, unique per scan) → `ai_analyses` (one per finding).
Deleting a scan cascades to its findings and AI analyses. Results are written in one transaction when the scan completes;
if that fails, nothing is kept and the scan is `failed`. Raw scanner output, `scanner_metadata`, API keys and server paths are never stored.
`findings.json`, `score.json` and `ai_analysis.json` are still written to `uploads/{scan_id}/results/`.

### 7. Report API (Phase 10)
Read-only endpoints served from the database (they never read `uploads/`). Reports exist only for `completed` scans.

| Endpoint | Returns |
|---|---|
| `GET /api/reports` | `{reports: [...]}`: completed scans, newest first, with score, label, finding count, highest severity, severity and category counts |
| `GET /api/reports/{scan_id}` | The same summary plus `filename`, `scanners`, the `ai` summary (`advisory: true`) and `score_details` (the deterministic breakdown, recomputed from the stored findings) |
| `GET /api/reports/{scan_id}/findings` | `{scan_id, findings: [...]}`: normalized findings in stored order, each with `ai_status` |
| `GET /api/findings/{scan_id}:{finding_id}` | One finding plus `ai_analysis` (advisory, or `null`), e.g. `/api/findings/<32-hex scan_id>:VG-001` |

Public finding IDs (`VG-001`) are unique only within a scan, so a single finding is addressed as `{scan_id}:{finding_id}`.
Errors: malformed scan ID → 400, unknown scan → 404, scan not completed → 409, malformed finding ID → 400, unknown finding → 404.
`code`, `fixed_code` and every AI field are untrusted text and must be rendered as plain text.
"@

Set-Content -Path "backend\.gitignore" -Value @"
venv/
.venv/
__pycache__/
*.py[cod]
.env

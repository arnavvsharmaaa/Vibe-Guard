# Vibe Guard Backend

FastAPI backend for Vibe Guard - AI-Powered Secure Code Auditor.

## Setup & Running (Phase 1)

### 1. Create and Activate Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Development Server
```bash
python main.py
# or
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The API has no authentication, so it listens on `127.0.0.1` only (`HOST` in the environment; default `127.0.0.1`).
Set `HOST=0.0.0.0` only inside a deployment/container boundary, never on a shared network.

### 4. Endpoints
- Health check: `GET http://localhost:8000/api/health`
- Interactive API Docs: `http://localhost:8000/docs` (only with `ENABLE_DOCS=1`, see section 8)

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

### 8. Docker and demo deployment (Phase 14a)
The backend ships as one Docker image (`backend/Dockerfile`): `python:3.14-slim` (Debian, glibc; Semgrep's Linux
wheel needs glibc >= 2.34), the pinned `requirements.txt` (Semgrep and Bandit included), and only the runtime code and
`semgrep_rules/`. It runs as the unprivileged `app` user with one uvicorn worker and no `--reload`.
`.env`, databases, `uploads/`, `venv/` and `tests/` never enter the image (`.dockerignore`).

```bash
# from backend/
docker build -t vibe-guard-api .
# approximately Render's free instance: 512 MB RAM, 0.1 CPU
docker run --rm -p 8000:8000 --memory=512m --cpus=0.1 \
  -e ALLOWED_ORIGINS=http://localhost:5173 -e ENABLE_DOCS=1 vibe-guard-api
# optional AI: add  -e GROQ_API_KEY  (passes the value from your shell; never put the key in the image)
# test suite on Linux with the image's Python, Semgrep and Bandit. The repository is mounted read-only because some
# tests check files that are not in the image (Dockerfile, README.md, render.yaml, src/services/api.js)
docker run --rm -e PYTHONDONTWRITEBYTECODE=1 -v "$(pwd)/..:/repo:ro" -w /repo/backend vibe-guard-api \
  python -m unittest discover -s tests
```

Inside the container the database is `/app/data/vibe_guard.db` and scan directories are in `/app/data/uploads`
(`DATABASE_URL` and `UPLOAD_DIR`, set by the image). Without a volume both are lost when the container is removed.

Deployment settings (all optional locally):

| Variable | Default | Purpose |
|---|---|---|
| `ALLOWED_ORIGINS` | localhost dev origins | Comma-separated CORS origins. When set, it **replaces** the localhost defaults (`*` is ignored). Production: the static site URL only |
| `ALLOWED_HOSTS` | *(empty: no check)* | Host allowlist; any other `Host` header gets `400`. Production: the API host name (add `127.0.0.1` to keep the Docker `HEALTHCHECK` working) |
| `ENABLE_DOCS` | *(off)* | `1` serves `/docs`, `/redoc` and `/openapi.json`; otherwise they return 404 |
| `UPLOAD_DIR` | `backend/uploads` | Scan directory root |
| `MAX_ACTIVE_SCANS` | `1` | Scans running at once; further submissions get `503` with `Retry-After` and are not stored |
| `SCAN_RATE_LIMIT` / `SCAN_RATE_WINDOW_SECONDS` | `5` / `600` | Scan submissions per client address in a sliding window; more get `429` with `Retry-After`. Every submission that reaches the endpoint counts, including rejected uploads; `503` (busy), `413` (too large) and `422` (malformed form) responses do not |
| `TRUSTED_PROXY_HOPS` | `0` | `0`: the client address is the socket peer. `N`: the Nth `X-Forwarded-For` entry from the right (Render: `1`). Entries a client adds on the left are ignored |

The limiter and the scan slot are in memory, which is why the API must run as a single worker process.

Startup recovery: when the API starts, any scan still `uploaded`, `queued`, `scanning` or `analyzing` was interrupted
by a restart, so it is marked `failed` ("Scan interrupted by a server restart"), and every leftover `source/` directory
and `upload.zip` in the scan directories is removed. `results/` and completed scans are unchanged.

Scanner resources: Semgrep runs with `--jobs 1` (instead of one job per detected CPU, which inside a container can be
the host's CPU count) and `--max-memory 300` (MiB, per rule and file). The existing time limits are unchanged. How Semgrep reports a rule that hits the
memory cap has not been observed yet (no scan came close to it).

The Render setup is in the repository root `README.md` ("Demo deployment (Render)") and `render.yaml`.

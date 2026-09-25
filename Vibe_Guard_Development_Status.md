# Vibe Guard — Development Status

> This file tracks implementation progress.
>
> The architectural source of truth is:
> `Vibe_Guard_Master_Blueprint.md`
>
> This file MUST NOT redefine or override the master architecture.
> It only records verified implementation status, tests, files changed,
> issues, and the currently authorized phase.

---

# Project Status

## Frontend

Status: COMPLETE

The existing Review 1 React frontend is implemented and serves as the
canonical UI.

Do not redesign or rebuild the frontend unless explicitly instructed.

---

# Backend Phase Status

| Phase | Status | Verified |
|---|---|---|
| Phase 1 — FastAPI Foundation | ✅ DONE | Yes |
| Phase 2 — React ↔ FastAPI Connection | ✅ DONE | Yes |
| Phase 3 — Secure Code Upload | ✅ DONE | Yes |
| Phase 4 — Scan Lifecycle | ✅ COMPLETE | Yes |
| Phase 5 — Static Analysis | ✅ COMPLETE | Yes |
| Phase 6 — Finding Normalization | ✅ COMPLETE | Yes |
| Phase 7 — Security Score | ✅ COMPLETE | Yes |
| Phase 8 — AI Contextual Analysis | ✅ COMPLETE | Yes |
| Phase 9 — Database | ✅ COMPLETE | Yes |
| Phase 10 — Report API | ✅ COMPLETE | Yes |
| Phase 11 — Replace Frontend Mock Data | ✅ COMPLETE | Yes |
| Phase 12 — Testing | ⏳ PENDING | No |
| Phase 13 — Security Hardening | ⏳ PENDING | No |
| Phase 14 — Docker / Deployment | ⏳ PENDING | No |

---

# Verified Implementation

## Phase 1 — FastAPI Foundation

Status: ✅ COMPLETE

Implemented:

- FastAPI application
- Uvicorn setup
- CORS
- `/api/health`
- `/docs`
- Backend requirements
- `.env.example`
- Backend README

Verification:

- `/api/health` → HTTP 200
- `/docs` → HTTP 200
- Frontend build → passed

---

## Phase 2 — React ↔ FastAPI Connection

Status: ✅ COMPLETE

Implemented:

- `src/services/api.js`
- React → FastAPI health connection
- CORS verification

Verification:

- Frontend successfully communicated with FastAPI
- CORS verified
- `npm run build` → passed

---

## Phase 3 — Secure Code Upload

Status: ✅ COMPLETE

Implemented:

- `POST /api/scan/upload`
- Multipart upload
- Extension allowlist
- 5 MB upload limit
- Chunked upload handling
- Filename sanitization
- UUID-based storage
- Isolated upload directory
- Uploaded code is not executed/imported

Verification:

- Valid upload → passed
- Unsupported file → rejected
- Path traversal attempt → handled
- Oversized upload → rejected
- Health endpoint → passed
- Frontend build → passed

### Phase 3 Gap Closure — 2026-09-25

The pre-Phase-4 inspection found that several Blueprint Phase 3 requirements were missing
(archive validation, extraction, Zip Slip protection, extraction/file-count limits,
isolated scan directories, scan IDs, temp cleanup). The project owner approved closing them.

Files changed:

- `backend/main.py`

Implemented (stdlib only, no new dependencies):

- ZIP is the only accepted archive type (`.tar`/`.gz` removed from the allowlist)
- ZIP content validation (`zipfile.is_zipfile`), not extension only
- Safe extraction to `uploads/{scan_id}/source/`
- Zip Slip protection: rejects `..`, absolute paths, drive letters, and backslash traversal, then does a resolved-path containment check
- Rejects symlink and encrypted entries
- Limits: 1000 entries and 50 MB extracted, counted from actual decompressed bytes
- Server-generated `scan_id` (UUID hex) with a per-scan isolated directory
- Uploaded `.zip` deleted after extraction, and the whole scan directory removed on any failure
- Early 413 based on `Content-Length`; the streaming 5 MB check is kept
- Response is now `{status, scan_id, filename, file_count}` (was `file_id`). No frontend code reads it.

Tests (run manually against uvicorn with curl):

- Valid multi-file ZIP → 200, extracted with its structure, no leftover `.zip`
- Single `.py` → 200
- `../` member, absolute member, `C:/` member → 400
- Symlink member → 400
- 1001 entries → 400
- 60 MB extracted (61 KB compressed) bomb → 400
- Text file renamed `.zip` → 400
- `.tar`, `.gz`, `.exe` → 400
- 6 MB file → 413 (with Content-Length and with chunked transfer)
- `../../evil.py` filename → stored as `evil.py` inside the scan directory
- Rejected uploads left no directories, and nothing was written outside `uploads/`
- `/api/health` → 200, `/docs` → 200
- `npm run build` → passed

Known remaining issues:

- Phase 2's `POST /api/scans` does not exist yet. It is left to Phase 4, which defines the same endpoint.
- Upload is not wired into the React UI (`uploadSourceFile` is unused). This is Phase 11 scope.
- No retention policy for successful uploads in `uploads/`.
- No automated tests in the repository (Phase 12).

---

# Current Authorized Phase

## Phase 12 — Testing

Status: ⏳ PENDING / NOT STARTED

Not started. Awaiting explicit authorization. See the master blueprint for Phase 12 requirements.

---

# Phase Completion Log

## Phase 11

Status: ✅ COMPLETE

Started / Completed:
`2026-09-25`

Files changed:
- `src/services/api.js`: `request()` wrapper with `ApiError {status, detail}` (network failure → status 0), `describeError()`, helpers `createScan`, `listScans`, `getScan`, `getScanStatus`, `listReports`, `getReport`, `getReportFindings`, `getFinding(scanId, findingId)`. Unused legacy `uploadSourceFile` removed
- `src/services/mappers.js` (new): backend snake_case / uppercase severities → the existing UI data model
- `src/hooks/useApiResource.js` (new): `{data, error, loading}` with an AbortController
- Pages: `Dashboard`, `NewScan`, `ScanProgress`, `Reports`, `SecurityReport`, `VulnerabilityDetail`, `ScanHistory`
- Components: `UploadZone` (real `File`), `CodeComparison` (fallback when there is no AI fix), `AIRecommendation` (generic "Corrected Code" copy)
- `src/data/mockData.js`: report, finding, history, dashboard and upload mocks removed. Only presentational `currentUser`, `workspace` (Topbar) and `scanStages` (pipeline labels) remain

Dependencies:
- None added. Backend, `Blueprint.md`, routes, `index.css` and all other components unchanged

Implementation decisions:
- Routes unchanged. `/reports/:id` = `scan_id`; `/reports/:id/findings/:findingId` = public `VG-001`, and the API helper builds the composite `{scan_id}:VG-001`
- New Scan → `POST /api/scans` → `/scan/progress?scan=<scan_id>` (the query param survives a reload)
- Scan Progress polls `GET /api/scans/{id}/status` every 1.5 s (setTimeout chain). It stops on `completed`/`failed`, on 400/404, after 5 consecutive network/5xx errors, and on unmount (timer cleared, request aborted). Status → pipeline stage: `uploaded`/`queued`/`scanning` → Static Analysis, `analyzing` → AI Contextual Analysis, `completed` → all done. A failed scan keeps its last stage and shows the backend `error`
- Mapping:
  - `startLine = line`, `highlightLines = line..end_line`
  - `language` comes from the file extension; `message` → scanner text; `cwe || "No CWE"`
  - `engine` comes from the AI summary (`Static rules [+ <model>]`); dates are formatted locally
  - AI fields are used only when `ai_analysis.status == "completed"`, otherwise a one-line "not available (<status>)" fallback
  - `fixedHighlightLines = []`: AI fixes have no line mapping
- History merges `GET /api/scans` with `GET /api/reports`. Non-completed scans show "—" and open the progress page
- Errors: 400/404 → "not found"; 409 → backend detail + link to progress; 400/413 upload → backend `detail` inline; 5xx/network → generic message (response bodies are never shown)
- Security Rules / AI toggles on New Scan stay visual only (the backend has no such parameters)
- `scanners`, `score_details`, `filename` and `detection_reason` are not requested for display. All AI text and `fixed_code` render as React text (no `dangerouslySetInnerHTML`)

Tests:
- `npm run build` → passed
- Backend: 153 run, all passed, 1 skipped (unchanged)
- `grep`: no imports of removed mock exports; no `dangerouslySetInnerHTML`, `eval`, `new Function`

Live verification (uvicorn on a scratch `DATABASE_URL`, `GROQ_API_KEY` unset; Vite with `VITE_API_URL`; driven in Chrome):
- Mappers run against real responses: summary, detail, findings, finding detail, scans all mapped as specified
- Dashboard, Reports, Report Detail, Vulnerability Detail and History render real data in the unchanged layout
- UI upload: disabled without a file; `.exe` → inline 400 detail; `.py` → progress page advanced to "Security report ready", and polling stopped (no `/status` requests during the next 5 s)
- Scan set to `analyzing` (scratch DB): report → 409 message + progress link; progress page shows AI stage active (69%); History row shows "—"; leaving the page stopped polling
- `/reports/<unknown 32-hex>` → "Report not found."; unknown `VG-999` → "Finding not found."; `/scan/progress` without a scan → empty state
- AI text containing `<script>`/`<img onerror>` (planted in the scratch DB) rendered as literal text; no script ran, no elements injected
- Backend stopped → "The Vibe Guard API is unavailable…"

Issues / notes:
- `Sidebar` ("Demo AI Model · static mock scan") and `Settings` (UI-only) still contain hard-coded prototype text. They are out of Phase 11 scope and unchanged
- Topbar user and workspace remain static (no auth/workspace backend)
- The New Scan project name still defaults to "AI-Web-App" (existing UI default)
- The verification's two scan directories remain in `backend/uploads/` (`ceb740ac…`, `57344f86…`)

## Phase 10

Status: ✅ COMPLETE

Started / Completed:
`2026-09-25`

Files changed:
- `backend/main.py` (4 read-only report routes, `ScanRegistry` read methods, explicit response serializers, `FINDING_REF_PATTERN`)
- `backend/tests/test_reports.py` (new)
- `backend/README.md` (Report API section)

Dependencies:
- None added. No schema change: `database.py`, `scoring.py`, `normalization.py`, `ai_analysis.py` and `scanners.py` are untouched

Owner decisions:
- A single finding is addressed by the composite ID `{scan_id}:{finding_id}` (e.g. `…:VG-001`), because public IDs are unique per scan only. The internal integer PK is never exposed
- JSON keeps the backend style (snake_case, uppercase severities), consistent with `/api/scans`. Mapping to the React mock's camelCase is Phase 11
- Reports exist only for `completed` scans: other statuses → 409; `GET /api/reports` lists completed scans only (all scans remain in `GET /api/scans`)

Endpoints (tag `Reports`, database only, never read `uploads/` or result files, no writes):
- `GET /api/reports` → `{reports: [summary]}`, newest first. Summary: `scan_id, project_name, status, created_at, updated_at, file_count, security_score, score_label, finding_count, highest_severity, severity_counts, category_counts`
- `GET /api/reports/{scan_id}` → summary + `filename, scanners, ai` (stored summary + `advisory: true`) + `score_details` (`max_score, label, formula_version, total_penalty, highest_severity, by_severity, by_category`)
- `GET /api/reports/{scan_id}/findings` → `{scan_id, findings: [...]}` in stored order: `id` (composite), `finding_id, scan_id`, the stored finding columns, `ai_status`
- `GET /api/findings/{scan_id}:{finding_id}` → finding + `ai_analysis` (`advisory: true`, status, explanation, detection_reason, impact, recommendation, fixed_code, remediation_steps, error) or `null`

Implementation decisions:
- `security_score` is the stored value (authoritative). The score breakdown is not persisted, so `score_details`, the label, and the counts are recomputed from the stored findings with the same deterministic `calculate_security_score`. No AI input
- Errors: malformed scan ID → 400 `Invalid scan ID`; unknown → 404 `Scan not found`; not completed → 409 `Report not available (scan status: <status>)`; malformed finding ref (`^[0-9a-f]{32}:VG-[0-9]{3,}$`, ASCII digits only) → 400 `Invalid finding ID`; unknown finding → 404 `Finding not found`
- No pagination/filtering (not specified by the Blueprint)
- Existing endpoints unchanged

Tests (`cd backend && venv/Scripts/python -m unittest discover -s tests -v` → 153 run, all passed, 1 skipped (Phase 8 symlink test, Windows)):
- Report API tests (21, new):
  - list: empty; completed-only, newest first; counts, label, highest severity; zero findings
  - detail: exact keys; score equals the stored value and a recomputation; AI summary; 400/404; 409 for uploaded/queued/scanning/analyzing/failed
  - findings: exact keys, order, composite ID, every `ai_status`; single finding equals the stored AI fields; skipped/failed AI has no text
  - finding refs: the same `VG-001` in two scans resolves correctly; `%3A` works; 16 malformed refs → 400; dot segments/slashes → 404 (no route); unknown → 404
  - security: AI `<script>`/"score 100" text returned verbatim as JSON and never changes the score or severity; no metadata markers, DB path or integer PK in responses
  - real-pipeline integration (Groq faked): responses equal `score.json`/`findings.json`/`ai_analysis.json`; no key, env secret, server/upload paths, `semgrep_rules`, `scanner_metadata`, `check_id` or stderr; still served after a restart with the result files deleted; AI disabled; failed scan → 409 and not listed
  - existing endpoints unchanged
- All 132 Phase 1–9 tests pass unchanged

Live verification (uvicorn on a scratch `DATABASE_URL`, `GROQ_API_KEY` unset):
- `/api/health` → 200, `/docs` → 200, `GET /api/reports` on an empty DB → `{"reports": []}`
- In-progress scan (status `scanning` before and after the requests): `/api/reports/{id}` → 409, `/findings` → 409, finding → 404, not in the report list
- Completed fixture scan: score 55 "Needs work", 6 findings, AI `disabled`. All four endpoints matched `score.json`, `findings.json` and `ai_analysis.json` exactly; the list item equals the detail summary
- Responses contain no `gsk_`, backend path, `uploads`, `semgrep_rules`, `scanner_metadata`, `check_id` or `stderr`
- 400: `abc`, uppercase ID, `VG-001`, missing colon, `VG-1`, `vg-001`, extra segment, `1`, trailing `%0A`. 404: unknown scan, unknown `VG-999`. `%3A` → 200
- No `PWNED_MARKER` created (marker `setup.py`/`conftest.py` in the fixture were not executed)
- `npm run build` → passed
- Only the verification's own artifacts were removed (the scratch DB, the fixture ZIP, the log, and the one `uploads/{scan_id}` directory)

Issues / notes:
- The React mock expects camelCase, title-case severities, and fields with no backend data (`language`, `startLine`, `highlightLines`, `fixedHighlightLines`, `engine`, formatted dates). Phase 11 must map these. The snippet starts at `line`, so highlights can be derived from `line`/`end_line`
- The Blueprint's `/api/findings/{finding_id}` path takes the composite ID, not a bare `VG-001`
- `detection_reason` (stored since Phase 8) is exposed although not listed in the Blueprint AI model
- `GET /api/reports` loads every completed scan's findings (one extra query); fine for SQLite scale, no pagination
- No authentication: anyone who knows a scan ID can read its report (scan IDs are random 128-bit). Access control is outside Phase 10
- AI text and `fixed_code` must be rendered as plain text by the frontend (Phase 11)


## Phase 9

Status: ✅ COMPLETE

Started / Completed:
`2026-09-25`

Files changed:
- `backend/database.py` (new: engine, session factory, models, `init_db`)
- `backend/main.py` (database-backed `ScanRegistry` replaces the in-memory one; lifespan table creation; final persistence step; scan-creation DB error handling)
- `backend/requirements.txt` (`SQLAlchemy==2.0.54`)
- `backend/.env.example` (`DATABASE_URL`)
- `backend/.gitignore` (`*.db`, `*.db-journal`)
- `backend/README.md` (database section)
- `backend/tests/test_database.py` (new)
- `backend/tests/test_pipeline_regression.py` (`setUp`/`tearDown` use an isolated temporary SQLite database; assertions unchanged)

Dependencies:
- `SQLAlchemy==2.0.54` (Python 3.14 compatible). No Alembic, no dotenv, no PostgreSQL driver

Schema (SQLAlchemy 2.0 ORM, generic types only; SQLite via `DATABASE_URL`, default `backend/vibe_guard.db`, outside `uploads/`):
- `scans`: `scan_id` PK (String 32), `project_name`, `status` (indexed), `filename`, `file_count`, `created_at` (indexed), `updated_at`, `error`, `security_score` (int, null until completed), `scanners` (JSON summary), `ai` (JSON summary)
- `findings`: `id` integer PK (internal), `scan_id` FK → scans ON DELETE CASCADE, `finding_id` (public `VG-001`, unchanged), `type, category, severity, file, line, end_line, code, scanner, rule, message, cwe, confidence, scanners (JSON), related_rules (JSON)`; UNIQUE(`scan_id`, `finding_id`)
- `ai_analyses`: `finding_id` PK + FK → findings.id ON DELETE CASCADE (1:1), `status, explanation, detection_reason, impact, recommendation, fixed_code, remediation_steps (JSON), error`
- SQLite `PRAGMA foreign_keys=ON` on every connection (the only raw SQL). Tables created by `Base.metadata.create_all()` in the FastAPI lifespan (idempotent; no migrations yet)

Not stored: raw Semgrep/Bandit output, stderr/logs, `scanner_metadata`, `column`, the normalization `skipped` list, the full score breakdown, API keys, environment values, absolute/server paths.

Implemented:
- `ScanRegistry` (same methods; `set_ai` removed, `complete` added) now uses the database; each operation is a short transaction. No in-memory store remains
- Transitions keep the Phase 4 table and are compare-and-set (`UPDATE … WHERE scan_id=? AND status=<validated status>`); a concurrent change is rejected with `InvalidScanTransition`
- Pipeline: normalize → `findings.json` → score → `score.json` → AI → `ai_analysis.json` → one transaction that inserts findings and AI rows, sets `security_score` and the `ai` summary, and moves the scan to `completed`. Rows are built from the in-memory dicts, not re-read from the JSON files. The JSON files are unchanged
- Persistence error → rollback (no findings/AI rows, no score), then a separate transaction marks the scan `failed` with `"Database persistence failed unexpectedly"`
- Scanner summary persisted when scanners finish; earlier failures (scanner, normalization, scoring) persist `failed` + error with no result rows
- AI failures still never fail the scan; every AI entry (completed, skipped, failed, timeout, invalid_output) gets a row with its status/error
- `POST /api/scans`: a database error while creating/queueing → best-effort `failed`, scan directory removed, generic 500 `"Failed to create scan"`
- `GET /api/scans`, `/{scan_id}`, `/{scan_id}/status` read from the database; response shapes unchanged except the scan record now also includes `security_score` (Blueprint Scan model field)

Implementation decisions:
- Finding identity: internal integer PK; public `finding_id` values unchanged and unique per scan only. How `GET /api/findings/{finding_id}` addresses a finding is left to Phase 10
- Restart recovery: the Blueprint does not define startup recovery, so none was added. A scan interrupted by a restart keeps its last persisted status (`queued`/`scanning`/`analyzing`) and is not resumed or marked failed. Previously such scans were lost entirely
- Timestamps are stored as UTC and returned in the existing ISO `+00:00` format (SQLite drops tzinfo; it is restored on read)

Tests (`cd backend && venv/Scripts/python -m unittest discover -s tests -v` → 132 run, all passed, 1 skipped (Phase 8 symlink test, Windows)):
- Database tests (26, new): tables/columns/PK/unique constraint; `init` idempotent and keeps data; `DATABASE_URL` default/override; FK enforced; `finding_id` unique per scan only; DB-level and ORM cascade delete of findings + AI rows; create/get/list persist across a new engine (simulated restart), newest first, `+00:00` timestamps; transitions persist, invalid/terminal/unknown rejected; 8 concurrent transitions → exactly 1 succeeds; scanner summary persisted; `complete` stores exact finding/AI fields, score and AI summary; zero findings → 100; rollback on unknown AI finding, after rows were flushed, and on duplicate IDs → nothing stored; `complete` rejected unless `analyzing`
- Pipeline (real scanners, Groq faked): DB findings/score/AI equal `findings.json`/`score.json`/`ai_analysis.json` and survive a restart; no API key, env secret, server/upload paths, `semgrep_rules`, `scanner_metadata`, raw scanner keys or stderr in DB rows or the DB file; AI disabled → `skipped` rows; AI crash → `completed` with `failed` rows; forced persistence failure → `failed` scan, zero rows, JSON files intact; scanner/normalization/scoring failures → no rows, null score; DB failure on create → 500, no leftover directory; list/status endpoints read the DB; lifespan creates tables
- All 106 Phase 1–8 tests pass unchanged (only the pipeline test setup changed)

Live verification (uvicorn + curl, default `DATABASE_URL`, `GROQ_API_KEY` unset):
- `/api/health` → 200, `/docs` → 200; `backend/vibe_guard.db` created at startup
- Fixture ZIP → `queued` → `completed`; score 55, 6 findings; DB rows equal `findings.json`, `security_score` equals `score.json`; 6 AI rows `skipped` (disabled)
- DB file contains no server path, `semgrep_rules`, `scanner_metadata`, `check_id` or `gsk_` key (the string `GROQ_API_KEY` appears only in the stored skip message "AI analysis is disabled (GROQ_API_KEY is not set)")
- Server restarted → the completed scan is still returned by `GET /api/scans`
- `.exe` → 400, 6 MB → 413, bad ID → 400, unknown ID → 404, legacy `/api/scan/upload` → 200 (not registered, as before); rejected uploads create no scan rows; marker file not executed
- `npm run build` → passed
- Test artifacts removed (`vibe_guard.db`, `backend/uploads/` contents)

Issues / notes:
- Interrupted scans remain in a non-terminal status after restart (see decision above)
- No migration tool; schema changes need `create_all` on a fresh DB or a later migration step (relevant before PostgreSQL, Phase 14)
- PostgreSQL is not tested; no driver installed
- Upload directories from before Phase 9 are not imported
- `/api/scan/upload` (Phase 3) still does not create a scan record
- No report/findings API yet (Phase 10)
- `backend/README.md` contains stray pre-existing text (a `"@` / `Set-Content` fragment, already in the initial commit); left untouched

## Phase 8

Status: ✅ COMPLETE

Started / Completed:
`2026-09-25`

Files changed:
- `backend/ai_analysis.py` (new)
- `backend/main.py` (`_run_ai_analysis` step after `score.json`, `ai` summary on the scan record, import)
- `backend/.env.example` (`GROQ_API_KEY`, `GROQ_MODEL`, `AI_TIMEOUT_SECONDS`, `AI_MAX_FINDINGS`)
- `backend/README.md` (AI configuration section)
- `backend/tests/test_ai_analysis.py` (new)
- `backend/tests/test_pipeline_regression.py` (AI assertions + 3 AI pipeline tests; Groq always mocked, key removed)

Dependencies:
- None added. Stdlib `urllib.request` over HTTPS; no Groq/OpenAI SDK

Owner decisions:
- Provider Groq (OpenAI-compatible `POST https://api.groq.com/openai/v1/chat/completions`), default model `openai/gpt-oss-120b`
- AI failure never fails an otherwise successful scan
- Sending minimal, redacted code context to Groq is approved

Implemented:
- Pipeline: normalize → `findings.json` → score → `score.json` → AI → `results/ai_analysis.json` → `completed`. The AI step gets a deep copy and never rewrites `findings.json`/`score.json`
- Per finding, one request with only: `finding_id, type, category, severity, cwe, rule, scanner, scanners, message, file (relative), line, end_line, language, code_context{start_line, end_line, code}`
- Code context: flagged lines ±5, max 40 lines / 4000 chars, read as text through the Phase 6 `_SnippetReader` (confined to `source/`, no symlinks, ≤1 MB); falls back to the stored Phase 6 snippet. Never executed/imported
- Redaction: for `hardcoded-secret`, string literals on the flagged lines and in the scanner message (Bandit quotes the value); for all findings, quoted values assigned to secret-looking names and common token formats (AWS, `sk-`, `gsk_`, GitHub, Slack, private-key headers)
- Not sent: scan ID, project name, filenames outside the finding, server/absolute paths, raw scanner JSON, `scanner_metadata`, logs, summary, score, env vars
- System prompt: code is untrusted data, embedded instructions must be ignored, no severity/validity/score judgments, JSON only. `temperature 0`, `response_format json_object`, no tools, redirects not followed
- Output schema (exact keys): `finding_id, explanation ≤2000, detection_reason ≤1000, impact ≤1500, recommendation ≤1500, fixed_code ≤4000, remediation_steps[1–10, ≤500 each]`. Strict server-side validation: invalid/fenced JSON, missing/extra keys (incl. `severity`/`score`), wrong types, empty strings, over-length, mismatched `finding_id` → `invalid_output`; never partially accepted. Control chars stripped
- `ai_analysis.json`: `{advisory: true, status: completed|partial|failed|disabled, provider, model, analyzed, failed, skipped, analyses[{finding_id, status: completed|failed|timeout|invalid_output|skipped, fields or null, error}]}`. Scan record gets `ai: {status, provider, model, analyzed, failed, skipped}`
- Failures: no key → `disabled`, no request; timeout → `timeout`; HTTP error/network/empty/unreadable/oversized (>256 KB) response → `failed`; generic errors only (no bodies, URLs, keys). Crash in the AI step → every finding `failed`, scan still `completed`
- Limits: 30 s per request (`AI_TIMEOUT_SECONDS`, max 120), 180 s budget per scan, 25 findings (`AI_MAX_FINDINGS`, max 100) in existing severity order; the rest `skipped` (`limit reached` / `AI time budget exhausted`); no retries
- Key read at call time, only in the `Authorization: Bearer` header; never logged or stored. Scanner subprocess env is still an allowlist, so `GROQ_API_KEY` never reaches Semgrep/Bandit

Tests (`cd backend && venv/Scripts/python -m unittest discover -s tests -v` → 106 run, all passed, 1 skipped):
- AI unit tests (40, offline, fake opener): valid response stored; exact request/payload fields, URL, method, header, JSON mode, no tools; no scan ID/project name/server paths/scanner metadata/score/env/key in payload; config read at call time and invalid values fall back; redirects refused; ±5-line window, 40-line and 4000-char caps; unrelated files not read; out-of-tree path not read; symlink not followed (**skipped on this Windows machine: symlink creation not permitted**); oversized file fallback; secret redaction in context, message, and fallback snippet; token patterns redacted; prompt-injection source only in user data, never executed; validation (valid, control chars, invalid/fenced/non-object JSON, every missing key, extra/`severity`/`score` keys, wrong types, every length limit, empty/whitespace, mismatched ID, 0/11 steps); invalid output never partially accepted; timeout (plain and URLError-wrapped); HTTP 500 without body/key/URL leak; network failure; empty/unreadable/oversized responses; unexpected exception; partial status; missing key → disabled with zero calls; cap 2 and default 25; time budget; input unchanged and score unaffected by "severity LOW / score 100" output; deterministic
- Pipeline regression (3 new + assertions): mocked Groq on the mixed fixture → `completed`, one AI entry per finding, `score.json` == recomputation despite "severity LOW. score 100" output, AI fields absent from `findings.json`, scan ID/secret/server path absent from requests, key absent from results and scan record, scanner env has no `GROQ_API_KEY`, marker files not executed; AI exception → `completed` + AI `failed`; AI timeout → `completed` + all `timeout`; no key → `disabled` with no calls; scoring failure → no `ai_analysis.json`
- All 63 Phase 1–7 tests still pass

Live verification (uvicorn + curl, `GROQ_API_KEY` unset):
- `/api/health` → 200, `/docs` → 200
- Fixture ZIP → `completed`, error `null`; 6 findings, score 55 "Needs work"; `score.json` == `calculate_security_score(findings.json)`; files written in order findings → score → ai
- `ai_analysis.json` → `disabled`, 6 `skipped`, `analyzed 0`; no Groq request is possible on this path (the key check returns before any request is built); marker file not created
- `npm run build` → passed
- Test artifacts removed; `backend/uploads/` left empty

Issues / notes:
- No real Groq call has been made. Live behavior of `openai/gpt-oss-120b` with JSON mode (e.g. output hitting length limits → `invalid_output`) is unverified
- Redaction is pattern-based; secrets in unusual forms on non-flagged context lines could still be sent
- AI runs synchronously inside `analyzing`; up to 180 s extra per scan when a key is set
- `.env` is not auto-loaded (no python-dotenv); variables must be in the process environment
- `ai_analysis.json` is only on disk; persistence (Phase 9) and API exposure (Phase 10) are not implemented. `detection_reason` has no Phase 9 model field yet
- The frontend must render `fixed_code` and all AI text as plain text (Phase 11)

## Phase 7

Status: ✅ COMPLETE

Started / Completed:
`2026-09-25`

Files changed:
- `backend/scoring.py` (new)
- `backend/main.py` (pipeline `analyzing` step + import only)
- `backend/tests/test_scoring.py` (new)
- `backend/tests/test_pipeline_regression.py` (scoring assertions + scoring-failure test)

Dependencies:
- None added

Scoring formula (version 1, integers only, documented in `scoring.py`):
- `penalty(severity) = min(count × weight, cap)`; `score = max(0, 100 − Σ penalty)`
- Weights / caps: CRITICAL 25 / 75, HIGH 10 / 50, MEDIUM 4 / 20, LOW 1 / 10
- Caps keep many low-severity findings from outweighing a severe one (all LOW together ≤ 10 points)
- Every normalized finding counts once by its severity, whatever its category (including `other`) or the number of scanners that reported it. Phase 6 merging is reused; there is no second deduplication
- Zero findings → 100
- Labels (aligned with the React score ring's 85/70 thresholds): ≥85 Strong, ≥70 Good, ≥40 Needs work, <40 At risk

Implemented:
- `scoring.calculate_security_score(normalized)` → `{score, max_score, label, formula_version, total_penalty, finding_count, highest_severity, by_severity{count, weight, cap, penalty}, by_category{type, count, by_severity}}`
- Pure function: no AI, no I/O, input findings never modified, order-independent
- An unknown severity or category, or malformed input, raises `ScoringError`. It is never scored silently
- Pipeline: after `findings.json`, `results/score.json` is written; a scoring error → `failed` with `"Security scoring failed unexpectedly"`. Scanner output, normalization, and `findings.json` unchanged. No new API endpoint (Phase 10)

Tests (`cd backend && venv/Scripts/python -m unittest discover -s tests -v` → 63/63 passed):
- Scoring unit tests (20): zero findings (hand-built and real normalizer output); single finding per severity (75/90/96/99) and ordering; mixed combination (penalty 61 → 39); adding a finding never raises the score; every cap reached and exceeded; 1000 LOW beats 1 HIGH + 1 MEDIUM; floor at 0 (max penalty 155) and just above it; label thresholds at every boundary; score always an int in 0–100; category breakdown incl. `other`; JSON-serializable output with formula metadata; same input → same output, reversed order → same output, input not modified, merged duplicate counted once; malformed containers and unknown/lowercase/None severity or category raise
- Pipeline regression (7): mixed scan's `score.json` equals a recomputation from `findings.json`, severity counts match the Phase 6 summary; clean scan → 100 "Strong"; scoring exception → `failed`, no `score.json`; normalization exception → no `score.json`; all Phase 1–6 regressions still pass
- All 36 Phase 6 normalization tests unchanged and passing

Live verification (uvicorn + curl):
- `/api/health` → 200, `/docs` → 200
- Phase 6 fixture ZIP → `completed`; 13 findings (9 HIGH capped at 50, 2 MEDIUM = 8, 2 LOW = 2) → score 40, "Needs work"
- `npm run build` → passed
- Test artifacts removed; `backend/uploads/` left empty

Issues / notes:
- Weights, caps and labels are a documented project choice. The Blueprint only fixes the ordering (Critical > High > Medium > Low). Changing them should bump `formula_version`
- Because of the caps, a project with only HIGH findings never scores below 50, and only-MEDIUM never below 80
- No finding is CRITICAL yet (see Phase 6 notes), so in practice the lowest score is 20
- `other` findings (e.g. Bandit B101/B404, LOW) do lower the score, by at most 10 points together with other LOW findings
- The score is only on disk (`score.json`). The scan record's `security_score` (Phase 9) and the API (Phase 10) are not wired yet

## Phase 6

Status: ✅ COMPLETE

Started / Completed:
`2026-09-25`

Files changed:
- `backend/normalization.py` (new)
- `backend/main.py` (pipeline `analyzing` step only)
- `backend/tests/test_normalization.py` (new)
- `backend/tests/test_pipeline_regression.py` (new)

Dependencies:
- None added. Tests use stdlib `unittest` + FastAPI `TestClient` (httpx already installed)

Implemented:
- `normalization.normalize_findings(load_raw_results(results_dir), source_dir)` → `{findings, summary, skipped}`
- Finding schema (Blueprint Phase 6 fields plus extras): `id, type, category, severity, file, line, end_line, column, code, rule, scanner, message, cwe, confidence, scanners, scanner_metadata, related_rules`
- Categories: `sql-injection`, `xss`, `hardcoded-secret`, `command-injection`, `insecure-auth`, `weak-crypto`, `path-traversal`; anything else is kept as `other` ("Other Security Issue"), never dropped
- Category mapping: Semgrep `metadata.category` (local ruleset) → explicit Bandit test-ID table → CWE fallback → `other`. Bandit `B404` (import subprocess) is explicitly `other`
- Severity: `CRITICAL | HIGH | MEDIUM | LOW`. Semgrep `ERROR→HIGH`, `WARNING→MEDIUM`, `INFO→LOW` (newer `CRITICAL/HIGH/MEDIUM/LOW` passed through); Bandit `HIGH/MEDIUM/LOW` passed through; unrecognized → `MEDIUM`. The raw scanner severity and confidence are kept in `scanner_metadata`
- Rule IDs: Semgrep `check_id` is prefixed with the server's absolute rules path, so only the `vg.…` part (or last segment for foreign rules) is kept. Bandit rules become `bandit.<test_id>.<test_name>`
- Paths normalized to POSIX relative to `source/` (`.\app.py`, `sub\web.js` handled); `..`, drive-letter or out-of-tree paths → finding skipped
- Code snippet read from the extracted file as text (never executed/imported), confined to `source/`, no symlinks, ≤1 MB file, ≤10 lines / 2000 chars. Fallback: Bandit `code` with line numbers and context removed; Semgrep `"requires login"` is never used as code
- Duplicates: same category + file + line from different scanners → one finding. The most severe report is primary, `scanners` lists both, and the other scanner's metadata goes in `scanner_metadata` and `related_rules`. Exact same-rule repeats are dropped. `other` findings are only merged with exact repeats
- Deterministic order (severity, file, line, category, scanner, rule) and IDs `VG-001…`
- Malformed individual results (non-object, missing rule/path/line, invalid line) are skipped and recorded in `skipped` with a reason. A failed/timeout/unavailable scanner, unknown scanner, or malformed output raises `NormalizationError`, which fails the scan. It is never reported as zero findings
- Pipeline: during `analyzing`, normalized output is written to `uploads/{scan_id}/results/findings.json` (raw files unchanged). A normalization error → `failed` with `"Finding normalization failed unexpectedly"`. No new API endpoint (Phase 10)

Tests (`cd backend && venv/Scripts/python -m unittest discover -s tests -v` → 42/42 passed):
- Normalization unit tests (36): schema for both scanners, server path stripped, snippet from source / fallbacks, Windows and absolute paths, determinism under reordered input; Semgrep and Bandit severity tables including unknown values; all 7 categories, every category in `vibe_guard.yml` known, CWE fallback, Bandit test-ID table; malformed results (10 Semgrep + 4 Bandit shapes) skipped with reasons, odd optional fields, snippet cap, malformed output / failed scanner / unknown scanner raise; empty results, Bandit skipped, no scanners; mixed results: cross-scanner merge, severity-based primary, no merge across category/line, `other` not merged, same-rule repeats, multi-file mixed ordering and IDs
- Pipeline regression (6, real scanners through `TestClient`): health/docs; `.exe`, fake ZIP, `../` and absolute members, 6 MB 413, blank name, bad/unknown IDs (no leftover dirs); mixed Python/JS ZIP → `completed` with normalized findings in 5+ categories, merged duplicates, no server paths or "requires login", `setup.py`/`conftest.py` markers never executed; clean JS-only → 0 findings; normalization exception → `failed`; missing scanner → `failed`, no `findings.json`

Live verification (uvicorn + curl):
- `/api/health` → 200, `/docs` → 200
- Fixture ZIP (Python + JS) → `completed`; 13 findings (9 HIGH, 2 MEDIUM, 2 LOW) across all 7 categories + 2 `other`; 5 cross-scanner duplicates merged
- `npm run build` → passed
- Test artifacts removed; `backend/uploads/` left empty

Issues / notes:
- No `CRITICAL` findings are produced today: none of the scanners/rules report it, and no severity is escalated. Phase 7 decides how severities are weighted
- Duplicate merging is line-based (same category, file, line). Semgrep taint findings that span lines, or near-by reports on different lines, are not merged
- `other` findings (e.g. Bandit B101 `assert`) are kept. Phase 7 must decide whether they count toward the score
- Bandit test-ID and CWE tables cover known IDs only; new IDs fall back to CWE, then `other`
- Normalized findings are only on disk (`findings.json`); they are not exposed by the API until Phase 10 and not persisted beyond the upload dir until Phase 9
- `load_raw_results` takes `results_dir` (not `scan_id`); unchanged

## Phase 5

Status: ✅ COMPLETE

Started / Completed:
`2026-09-25`

Files changed:
- `backend/scanners.py` (new)
- `backend/semgrep_rules/vibe_guard.yml` (new)
- `backend/main.py`
- `backend/requirements.txt`

Dependencies:
- `bandit==1.9.4`, `semgrep==1.178.0` (both run natively on Windows / Python 3.14)

Implemented:
- `POST /api/scans` now moves the scan `uploaded → queued` (response `status: "queued"`) and runs static analysis with FastAPI `BackgroundTasks` (no queue or worker service)
- Real lifecycle: `queued → scanning` (scanners run) `→ analyzing` (raw output verified readable) `→ completed`, or `failed` with an explicit error
- Semgrep: local ruleset only (16 minimal rules covering the 7 Blueprint categories, Python + JS/TS), no registry or network, `--metrics off`
- Bandit: explicit `.py` file list (symlinks and out-of-tree paths skipped), batches of 200 merged into one `bandit.json`; `skipped` when there are no Python files
- Execution boundary: `shell=False`, fixed argv, targets after `--`, `stdin` closed, minimal env (no app secrets; `PATH` is only the tool directory, so git is unreachable), timeouts (Semgrep 180 s, Bandit 120 s) with process-tree kill
- Upload-controlled suppression disabled: `--disable-nosem`, `--x-ignore-semgrepignore-files`, `--no-git-ignore`, `--project-root .` (non-VCS), explicit `--config`; Bandit `--ignore-nosec`, no `-r` (uploaded `.bandit` never loaded)
- Raw output stored unmodified in `uploads/{scan_id}/results/{semgrep,bandit}.json` + `summary.json` (+ stderr logs), separate from `source/`
- Per-scanner summary `{scanner, version, status, exit_code, finding_count, error_count, targets_scanned, error, duration_s}` on the scan record; statuses `completed | skipped | failed | timeout | unavailable`. Any failure fails the scan; it is never reported as zero findings
- Phase 6 input: `scanners.load_raw_results(results_dir)` → `{scanner: {meta, raw}}`. Raw findings are not exposed by the API

Tests (FastAPI TestClient suite, 37/37 passed):
- Vulnerable Python/JS fixture → `completed`; Semgrep found all 7 categories; Bandit B105/B324/B602/B608 etc.
- `nosec`, `nosemgrep`, uploaded `.bandit`, `.semgrepignore`, `.semgrep.yml` did not suppress findings
- Marker-writing `setup.py`, `conftest.py`, module code, `.git/config` fsmonitor, `package.json` postinstall, `run.sh` → never executed
- Syntax-error file → recorded in Bandit `errors`, not dropped
- JS-only → Bandit `skipped`, scan `completed`; clean file → `completed`, 0 findings
- Missing Semgrep → `unavailable` → scan `failed`; 1 s timeout → `timeout` → `failed`, no orphaned semgrep processes; corrupt JSON → `failed`; exit code 2 → `failed`
- 205 Python files → batched, merged; scanner env excludes app secrets; error messages contain no server paths
- Phase 1–4 regressions (health, docs, `.exe`, Zip Slip, fake ZIP, 6 MB 413, blank name, invalid/unknown IDs, legacy upload) → passed

Live verification (uvicorn + curl):
- `/api/health` → 200, `/docs` → 200
- Fixture ZIP → 201 `queued` → `scanning` → `completed` in about 3.7 s; Semgrep 5 findings, Bandit 4 findings, suppression attempts ignored
- `.exe`, `../` member, absolute member, fake ZIP → 400; 6 MB (Content-Length and chunked) → 413; whitespace-only name → 400; missing name → 422; bad ID → 400; unknown ID → 404; legacy `/api/scan/upload` → 200
- `npm run build` → passed
- Test artifacts removed; `backend/uploads/` left empty

Issues / notes:
- `--x-ignore-semgrepignore-files` is an internal Semgrep flag; keep Semgrep pinned and re-test it before upgrading
- Semgrep `extra.lines` may say "requires login"; Phase 6 should read code snippets from the source file
- Multi-batch `bandit.json` is a merge of the batch outputs (`_totals` recomputed); one batch is Bandit's output unchanged
- Python files may get findings from both scanners; removing duplicates is Phase 6
- Scans run in-process via `BackgroundTasks`; an in-flight scan is lost on restart (Phase 9 / 14)
- `POST /api/scans` now returns `status: "queued"` instead of `"uploaded"` (the frontend does not read it)

## Phase 4

Status: ✅ COMPLETE

Started:
`2026-09-25`

Completed:
`2026-09-25`

Files changed:
- `backend/main.py`

Implemented:
- `POST /api/scans` (multipart `project_name` + `file`) → 201 `{scan_id, project_name, status: "uploaded"}`
- `GET /api/scans` → `{scans: [...]}`, newest first
- `GET /api/scans/{scan_id}` → full scan record
- `GET /api/scans/{scan_id}/status` → `{scan_id, status, updated_at}`
- Phase 3 upload logic moved into a shared `_store_upload` helper used by both `/api/scan/upload` and `/api/scans` (no duplicate upload code)
- Thread-safe in-memory `ScanRegistry` (no database; Phase 9)
- Explicit transition table: `uploaded→queued|failed`, `queued→scanning|failed`, `scanning→analyzing|failed`, `analyzing→completed|failed`; `completed`/`failed` terminal. Invalid transitions raise `InvalidScanTransition`
- Scan ID validated as 32 lowercase hex chars (400 if invalid, 404 if unknown)
- `project_name` stripped, required, ≤100 chars, printable only (400 otherwise)
- Early `Content-Length` 413 check now also covers `POST /api/scans`
- No delays, timers, fake progress, or fake findings; new scans stay `uploaded`

Tests (FastAPI TestClient against a temp upload dir, plus live uvicorn + curl):
- POST source file → 201, status `uploaded`, file stored
- POST ZIP → 201, extracted, no leftover `.zip`
- Blank `project_name` → 400; missing → 422
- GET list / detail / status → 200 with correct data
- Unknown ID → 404 (detail and status)
- Invalid IDs (`abc`, non-hex, uppercase, 33 chars, shell chars) → 400
- Invalid transitions (skip-ahead, backwards, unknown status, out of terminal states) → rejected; full valid path → `completed`
- `/api/health` → 200, `/docs` → 200
- Phase 3: `/api/scan/upload` still works; `.exe` → 400; `../` and absolute ZIP members → 400; fake ZIP → 400; 6 MB file → 413 (Content-Length and chunked); 51 MB ZIP bomb → 400; `../../evil.py` stored as `evil.py`; rejected uploads leave no directories and are not registered
- `npm run build` → passed
- Test artifacts removed; `backend/uploads/` left empty

Issues / notes:
- Registry is in memory: scans are lost on restart, and upload directories from earlier runs are not re-registered (Phase 9)
- No HTTP endpoint drives transitions; Phase 5 calls `scan_registry.transition(...)` from the real scanner
- `/api/scan/upload` (Phase 3) still stores files without creating a registry entry
- Frontend unchanged; no API-service function added (Phase 11 wires the UI)

---

# Update Rules

After completing a phase, update ONLY this status file.

For the completed phase:

1. Change its status to `✅ DONE`.
2. Record the files changed.
3. Record the tests actually performed.
4. Record the test results.
5. Record relevant implementation notes.
6. Mark the next phase as `🔴 CURRENT`.
7. Do not modify the master blueprint.
8. Do not modify future-phase requirements.
9. Do not silently change architecture.
10. If the implementation conflicts with the master blueprint, STOP and report the conflict.

A phase is not considered complete merely because code was written.
It is complete only after the relevant implementation has been tested.

---

# Architecture Change Rule

If implementation reveals that the master blueprint itself must change:

DO NOT change the master blueprint automatically.

Instead record:

### Proposed Blueprint Change

- Current requirement:
- Observed problem:
- Proposed change:
- Reason:
- Affected phases:
- Risks:

Then STOP and wait for explicit human approval.
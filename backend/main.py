import builtins
import json
import os
import re
import shutil
import stat
import uuid
import zipfile
import zlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from ai_analysis import analyze_findings, failed_result
from database import AIAnalysis, Finding, Scan, create_db_engine, create_session_factory, database_url, init_db
from normalization import normalize_findings
from scoring import calculate_security_score, score_label
from scanners import SUCCESS_STATUSES, load_raw_results, run_static_analysis


@asynccontextmanager
async def lifespan(_app: FastAPI):
    scan_registry.init()
    yield


app = FastAPI(
    title="Vibe Guard API",
    description="Backend API for Vibe Guard - AI-Powered Secure Code Auditor",
    version="0.1.0",
    lifespan=lifespan,
)

# Upload directory configuration
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Maximum upload size limit (5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# Archive extraction limits
MAX_ARCHIVE_FILES = 1000
MAX_EXTRACTED_SIZE = 50 * 1024 * 1024

# Allowance for multipart framing on top of the file itself
MULTIPART_OVERHEAD = 64 * 1024

CHUNK_SIZE = 64 * 1024  # 64 KB

# Allowed file extensions for source code and config files (.zip is the only archive type)
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".css", ".json", ".sql",
    ".java", ".c", ".cpp", ".h", ".hpp", ".cs",
    ".go", ".rs", ".php", ".rb", ".sh", ".bash",
    ".yml", ".yaml", ".xml", ".toml", ".txt", ".md",
    ".zip",
}

# Endpoints that accept multipart uploads
UPLOAD_PATHS = {"/api/scans"}

# Scan lifecycle
SCAN_STATUSES = ("uploaded", "queued", "scanning", "analyzing", "completed", "failed")

# Allowed transitions; "completed" and "failed" are terminal.
# Phase 5+ drives these from the real analysis pipeline.
SCAN_TRANSITIONS = {
    "uploaded": {"queued", "failed"},
    "queued": {"scanning", "failed"},
    "scanning": {"analyzing", "failed"},
    "analyzing": {"completed", "failed"},
    "completed": set(),
    "failed": set(),
}

SCAN_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
# Public finding IDs (VG-001) are unique per scan only, so the Report API addresses a finding as "{scan_id}:VG-001".
FINDING_REF_PATTERN = re.compile(r"([0-9a-f]{32}):(VG-[0-9]{3,})")
MAX_PROJECT_NAME_LENGTH = 100

# The API has no authentication, so it listens on localhost unless HOST is set explicitly
# (e.g. HOST=0.0.0.0 inside a deployment/container boundary).
DEFAULT_HOST = "127.0.0.1"

# CORS configuration to allow local React development server
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

extra_origins = os.getenv("ALLOWED_ORIGINS")
if extra_origins:
    origins.extend([origin.strip() for origin in extra_origins.split(",") if origin.strip()])

# The frontend sends no cookies or credentials and only uses GET and POST.
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


UPLOAD_TOO_LARGE_DETAIL = f"File size exceeds maximum allowed limit of {MAX_FILE_SIZE // (1024 * 1024)}MB"


class UploadSizeLimitMiddleware:
    """
    Multipart bodies are parsed (and spooled to disk) before the route runs, so the size limit is enforced here:
    by declared Content-Length first, and by counting received bytes for bodies without one (chunked).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in UPLOAD_PATHS:
            return await self.app(scope, receive, send)
        limit = MAX_FILE_SIZE + MULTIPART_OVERHEAD
        content_length = dict(scope["headers"]).get(b"content-length", b"").decode("latin-1")
        if content_length.isdigit() and int(content_length) > limit:
            response = JSONResponse(status_code=413, content={"detail": UPLOAD_TOO_LARGE_DETAIL})
            return await response(scope, receive, send)
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # FastAPI re-raises HTTPException from body parsing, so this becomes a normal 413 response.
                    raise HTTPException(status_code=413, detail=UPLOAD_TOO_LARGE_DETAIL)
            return message

        return await self.app(scope, limited_receive, send)


app.add_middleware(UploadSizeLimitMiddleware)


@app.get("/api/health", tags=["Health"])
def health_check():
    return {"status": "ok"}


async def _save_upload(file: UploadFile, destination_path: Path) -> None:
    """Stream an upload to disk, enforcing MAX_FILE_SIZE."""
    total_size = 0
    with open(destination_path, "wb") as buffer:
        while chunk := await file.read(CHUNK_SIZE):
            total_size += len(chunk)
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                    detail=f"File size exceeds maximum allowed limit of {MAX_FILE_SIZE // (1024 * 1024)}MB",
                )
            buffer.write(chunk)


def _reject_archive(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _extract_zip_safely(archive_path: Path, dest_dir: Path) -> int:
    """
    Extract a ZIP archive into dest_dir without trusting archive metadata.
    Returns the number of files extracted. Extracted files are never executed or imported.
    """
    if not zipfile.is_zipfile(archive_path):
        raise _reject_archive("Uploaded file is not a valid ZIP archive")

    dest_root = dest_dir.resolve()
    extracted_files = 0
    extracted_bytes = 0

    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_FILES:
                raise _reject_archive(f"Archive contains too many entries (maximum {MAX_ARCHIVE_FILES})")

            for member in members:
                if member.flag_bits & 0x1:
                    raise _reject_archive("Encrypted archive entries are not supported")
                if stat.S_ISLNK(member.external_attr >> 16):
                    raise _reject_archive("Archive contains a symbolic link")

                # Zip Slip / path traversal protection
                name = member.filename.replace("\\", "/")
                parts = PurePosixPath(name).parts
                # ":" is rejected in every part: a drive prefix, or an NTFS alternate data stream on Windows
                if name.startswith("/") or ".." in parts or any(":" in part for part in parts):
                    raise _reject_archive("Archive contains an unsafe path")

                target = (dest_root / name).resolve()
                if target == dest_root or not target.is_relative_to(dest_root):
                    raise _reject_archive("Archive contains an unsafe path")

                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                if target.is_dir():
                    raise _reject_archive("Uploaded file is not a valid ZIP archive")
                target.parent.mkdir(parents=True, exist_ok=True)
                # Count actual decompressed bytes rather than trusting header sizes
                with archive.open(member) as source, open(target, "wb") as output:
                    while chunk := source.read(CHUNK_SIZE):
                        extracted_bytes += len(chunk)
                        if extracted_bytes > MAX_EXTRACTED_SIZE:
                            raise _reject_archive(
                                f"Archive exceeds maximum extracted size of {MAX_EXTRACTED_SIZE // (1024 * 1024)}MB"
                            )
                        output.write(chunk)
                extracted_files += 1
    # Corrupt compressed data, an unsupported compression method, or a file/directory name clash
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, FileExistsError, NotADirectoryError):
        raise _reject_archive("Uploaded file is not a valid ZIP archive")

    return extracted_files


async def _store_upload(file: UploadFile) -> dict:
    """
    Store a source-code file or ZIP archive in a new isolated scan directory.
    Validates type and size, extracts archives safely, and never executes uploaded code.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required",
        )

    # Sanitize user filename to prevent path traversal
    safe_basename = Path(file.filename.replace("\\", "/")).name
    ext = Path(safe_basename).suffix.lower()

    if not ext or ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    # Server-generated scan ID and isolated scan directory
    scan_id = uuid.uuid4().hex
    scan_dir = (UPLOAD_DIR / scan_id).resolve()
    source_dir = scan_dir / "source"
    destination_path = (source_dir / safe_basename).resolve()

    # Ensure destination is strictly inside the scan directory
    if not destination_path.is_relative_to(scan_dir) or not scan_dir.is_relative_to(UPLOAD_DIR.resolve()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file path",
        )

    try:
        source_dir.mkdir(parents=True)
        if ext == ".zip":
            archive_path = scan_dir / "upload.zip"
            await _save_upload(file, archive_path)
            file_count = _extract_zip_safely(archive_path, source_dir)
            archive_path.unlink()
        else:
            await _save_upload(file, destination_path)
            file_count = 1
    except HTTPException:
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise
    except Exception:
        shutil.rmtree(scan_dir, ignore_errors=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file",
        )
    finally:
        await file.close()

    return {
        "status": "uploaded",
        "scan_id": scan_id,
        "filename": safe_basename,
        "file_count": file_count,
    }


class InvalidScanTransition(Exception):
    pass


# Normalized finding and AI analysis fields stored in the database. Everything else
# (scanner_metadata, column, raw scanner output) stays in the per-scan JSON files only.
FINDING_COLUMNS = ("type", "category", "severity", "file", "line", "end_line", "code", "scanner", "rule",
                   "message", "cwe", "confidence", "scanners", "related_rules")
AI_COLUMNS = ("status", "explanation", "detection_reason", "impact", "recommendation", "fixed_code",
              "remediation_steps", "error")
AI_SUMMARY_KEYS = ("status", "provider", "model", "analyzed", "failed", "skipped")


def _iso(value: datetime) -> str:
    # SQLite returns naive datetimes; every stored timestamp is UTC.
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


# Report API serializers. Every response field is listed explicitly; ORM rows and result files are never dumped.

def _score_breakdown(findings: list[Finding]) -> dict:
    # The breakdown is not stored, so it is recomputed from the persisted findings with the same
    # deterministic function the pipeline used. No AI output is involved.
    return calculate_security_score({"findings": [{"severity": f.severity, "category": f.category} for f in findings]})


def _report_summary(scan: Scan, breakdown: dict) -> dict:
    return {
        "scan_id": scan.scan_id,
        "project_name": scan.project_name,
        "status": scan.status,
        "created_at": _iso(scan.created_at),
        "updated_at": _iso(scan.updated_at),
        "file_count": scan.file_count,
        "security_score": scan.security_score,  # the stored score is authoritative
        "score_label": score_label(scan.security_score),
        "finding_count": breakdown["finding_count"],
        "highest_severity": breakdown["highest_severity"],
        "severity_counts": {severity: entry["count"] for severity, entry in breakdown["by_severity"].items()},
        "category_counts": {entry["type"]: entry["count"] for entry in breakdown["by_category"].values() if entry["count"]},
    }


def _report_detail(scan: Scan) -> dict:
    breakdown = _score_breakdown(scan.findings)
    return _report_summary(scan, breakdown) | {
        "filename": scan.filename,
        "scanners": scan.scanners,
        "ai": {"advisory": True, **scan.ai} if scan.ai else None,
        "score_details": {key: breakdown[key] for key in (
            "max_score", "label", "formula_version", "total_penalty", "highest_severity", "by_severity", "by_category")},
    }


def _finding_record(finding: Finding) -> dict:
    return {
        "id": f"{finding.scan_id}:{finding.finding_id}",
        "finding_id": finding.finding_id,
        "scan_id": finding.scan_id,
        **{key: getattr(finding, key) for key in FINDING_COLUMNS},
        "ai_status": finding.ai_analysis.status if finding.ai_analysis else None,
    }


def _ai_record(analysis: AIAnalysis | None) -> dict | None:
    # AI text and fixed_code are untrusted, advisory data returned as plain strings.
    if analysis is None:
        return None
    return {"advisory": True, **{key: getattr(analysis, key) for key in AI_COLUMNS}}


class ScanRegistry:
    """Database-backed scan store. Every operation runs in its own short transaction."""

    # The list() method below shadows the builtin inside this class body, so annotations use builtins.list.

    def __init__(self, url: str | None = None):
        self.engine = create_db_engine(url or database_url())
        self._sessions = create_session_factory(self.engine)

    def init(self) -> None:
        init_db(self.engine)

    def close(self) -> None:
        self.engine.dispose()

    @staticmethod
    def _record(scan: Scan) -> dict:
        return {
            "scan_id": scan.scan_id,
            "project_name": scan.project_name,
            "status": scan.status,
            "filename": scan.filename,
            "file_count": scan.file_count,
            "created_at": _iso(scan.created_at),
            "updated_at": _iso(scan.updated_at),
            "error": scan.error,
            "security_score": scan.security_score,
            "scanners": scan.scanners,
            "ai": scan.ai,
        }

    def create(self, scan_id: str, project_name: str, filename: str, file_count: int) -> dict:
        now = datetime.now(timezone.utc)
        scan = Scan(scan_id=scan_id, project_name=project_name, status="uploaded", filename=filename,
                    file_count=file_count, created_at=now, updated_at=now)
        with self._sessions.begin() as session:
            session.add(scan)
        return self._record(scan)

    def get(self, scan_id: str) -> dict | None:
        with self._sessions() as session:
            scan = session.get(Scan, scan_id)
            return self._record(scan) if scan else None

    def list(self) -> builtins.list[dict]:
        with self._sessions() as session:
            scans = session.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
            return [self._record(scan) for scan in scans]

    # Report API reads: read-only sessions, no writes.

    def list_reports(self) -> builtins.list[dict]:
        with self._sessions() as session:
            scans = session.scalars(
                select(Scan).where(Scan.status == "completed").order_by(Scan.created_at.desc())
                .options(selectinload(Scan.findings))).all()
            return [_report_summary(scan, _score_breakdown(scan.findings)) for scan in scans]

    def get_report(self, scan_id: str) -> dict | None:
        with self._sessions() as session:
            scan = session.get(Scan, scan_id, options=[selectinload(Scan.findings)])
            return _report_detail(scan) if scan else None

    def get_findings(self, scan_id: str) -> builtins.list[dict]:
        with self._sessions() as session:
            findings = session.scalars(
                select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)
                .options(selectinload(Finding.ai_analysis))).all()
            return [_finding_record(finding) for finding in findings]

    def get_finding(self, scan_id: str, finding_id: str) -> dict | None:
        with self._sessions() as session:
            finding = session.scalar(
                select(Finding).where(Finding.scan_id == scan_id, Finding.finding_id == finding_id)
                .options(selectinload(Finding.ai_analysis)))
            if finding is None:
                return None
            return _finding_record(finding) | {"ai_analysis": _ai_record(finding.ai_analysis)}

    @staticmethod
    def _advance(session, scan_id: str, new_status: str, **values) -> Scan:
        """
        Compare-and-set status change inside the caller's transaction: the UPDATE only matches while the
        scan still has the status that was validated, so two concurrent transitions cannot both succeed.
        """
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise KeyError(scan_id)
        current = scan.status
        if new_status not in SCAN_TRANSITIONS[current]:
            raise InvalidScanTransition(f"Cannot transition scan from '{current}' to '{new_status}'")
        result = session.execute(
            update(Scan)
            .where(Scan.scan_id == scan_id, Scan.status == current)
            .values(status=new_status, updated_at=datetime.now(timezone.utc), **values)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            raise InvalidScanTransition(f"Scan changed concurrently; cannot transition to '{new_status}'")
        session.refresh(scan)
        return scan

    def transition(self, scan_id: str, new_status: str, error: str | None = None) -> dict:
        values = {"error": error} if new_status == "failed" else {}
        with self._sessions.begin() as session:
            return self._record(self._advance(session, scan_id, new_status, **values))

    def set_scanners(self, scan_id: str, summary: dict) -> None:
        with self._sessions.begin() as session:
            result = session.execute(update(Scan).where(Scan.scan_id == scan_id).values(scanners=summary))
            if result.rowcount != 1:
                raise KeyError(scan_id)

    def complete(self, scan_id: str, normalized: dict, score: dict, ai: dict) -> dict:
        """
        Store findings, the deterministic score and the AI results, and mark the scan completed,
        all in one transaction. Any error rolls everything back; nothing is partially stored.
        """
        with self._sessions.begin() as session:
            rows = {}
            for finding in normalized["findings"]:
                row = Finding(scan_id=scan_id, finding_id=finding["id"],
                              **{key: finding.get(key) for key in FINDING_COLUMNS})
                session.add(row)  # a repeated ID hits the (scan_id, finding_id) constraint, never overwritten
                rows[finding["id"]] = row
            for analysis in ai["analyses"]:
                session.add(AIAnalysis(finding=rows[analysis["finding_id"]],
                                       **{key: analysis.get(key) for key in AI_COLUMNS}))
            session.flush()
            scan = self._advance(session, scan_id, "completed", security_score=score["score"],
                                 ai={key: ai[key] for key in AI_SUMMARY_KEYS})
            return self._record(scan)


scan_registry = ScanRegistry()


def _run_ai_analysis(normalized: dict, source_dir: Path, results_dir: Path) -> dict:
    """
    Advisory AI analysis, run after findings.json and score.json are final. It never rewrites them,
    and an AI problem is recorded in ai_analysis.json instead of failing the scan.
    """
    try:
        ai = analyze_findings(normalized, source_dir)
    except Exception:
        ai = failed_result(normalized)
    try:
        (results_dir / "ai_analysis.json").write_text(json.dumps(ai, indent=2), encoding="utf-8")
    except Exception:
        ai = failed_result(normalized)
    return ai


def _run_scan_pipeline(scan_id: str) -> None:
    """
    Runs static analysis for a queued scan and drives its real lifecycle.
    Scanners only read the extracted files; uploaded code is never executed.
    """
    scan_dir = UPLOAD_DIR / scan_id
    results_dir = scan_dir / "results"
    stage = "Static analysis"
    try:
        scan_registry.transition(scan_id, "scanning")
        summary = run_static_analysis(scan_dir / "source", results_dir)
        scan_registry.set_scanners(scan_id, summary)
        failed = sorted(name for name, meta in summary.items() if meta["status"] not in SUCCESS_STATUSES)
        if failed:
            scan_registry.transition(scan_id, "failed", error=f"Static analysis failed: {', '.join(failed)}")
            return
        scan_registry.transition(scan_id, "analyzing")
        stage = "Finding normalization"
        normalized = normalize_findings(load_raw_results(results_dir), scan_dir / "source")
        (results_dir / "findings.json").write_text(json.dumps(normalized, indent=2), encoding="utf-8")
        stage = "Security scoring"
        score = calculate_security_score(normalized)
        (results_dir / "score.json").write_text(json.dumps(score, indent=2), encoding="utf-8")
        stage = "AI analysis"
        ai = _run_ai_analysis(normalized, scan_dir / "source", results_dir)
        # Findings, score and AI results are stored and the scan completed in one transaction. On error it
        # is rolled back and the scan is marked failed below, in a separate transaction.
        stage = "Database persistence"
        scan_registry.complete(scan_id, normalized, score, ai)
    except Exception:
        try:
            scan_registry.transition(scan_id, "failed", error=f"{stage} failed unexpectedly")
        except (KeyError, InvalidScanTransition):
            pass
    finally:
        _remove_source(scan_dir)


def _remove_source(scan_dir: Path) -> None:
    """
    The pipeline is the only reader of the uploaded source. Once it has finished (completed or failed),
    reports are served from the database, so only source/ is removed; results/ is kept.
    """
    shutil.rmtree(scan_dir / "source", ignore_errors=True)


def _validate_project_name(project_name: str) -> str:
    name = project_name.strip()
    if not name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="project_name is required")
    if len(name) > MAX_PROJECT_NAME_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"project_name must be at most {MAX_PROJECT_NAME_LENGTH} characters",
        )
    if any(not ch.isprintable() for ch in name):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="project_name contains invalid characters")
    return name


def _get_scan_or_404(scan_id: str) -> dict:
    if not SCAN_ID_PATTERN.fullmatch(scan_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan ID")
    scan = scan_registry.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@app.post("/api/scans", tags=["Scans"], status_code=status.HTTP_201_CREATED)
async def create_scan(background_tasks: BackgroundTasks, project_name: str = Form(...), file: UploadFile = File(...)):
    """
    Creates a scan from an uploaded source file or ZIP archive and queues static analysis.
    """
    name = _validate_project_name(project_name)
    upload = await _store_upload(file)
    try:
        scan_registry.create(upload["scan_id"], name, upload["filename"], upload["file_count"])
        scan = scan_registry.transition(upload["scan_id"], "queued")
    except Exception:
        try:
            scan_registry.transition(upload["scan_id"], "failed", error="Scan could not be queued")
        except Exception:
            pass
        shutil.rmtree(UPLOAD_DIR / upload["scan_id"], ignore_errors=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create scan")
    background_tasks.add_task(_run_scan_pipeline, scan["scan_id"])
    return {"scan_id": scan["scan_id"], "project_name": scan["project_name"], "status": scan["status"]}


@app.get("/api/scans", tags=["Scans"])
def list_scans():
    return {"scans": scan_registry.list()}


@app.get("/api/scans/{scan_id}", tags=["Scans"])
def get_scan(scan_id: str):
    return _get_scan_or_404(scan_id)


@app.get("/api/scans/{scan_id}/status", tags=["Scans"])
def get_scan_status(scan_id: str):
    scan = _get_scan_or_404(scan_id)
    return {"scan_id": scan["scan_id"], "status": scan["status"], "updated_at": scan["updated_at"]}


def _get_completed_scan_or_error(scan_id: str) -> dict:
    # Findings, AI results and the score only exist once a scan is completed.
    scan = _get_scan_or_404(scan_id)
    if scan["status"] != "completed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Report not available (scan status: {scan['status']})")
    return scan


@app.get("/api/reports", tags=["Reports"])
def list_reports():
    return {"reports": scan_registry.list_reports()}


@app.get("/api/reports/{scan_id}", tags=["Reports"])
def get_report(scan_id: str):
    _get_completed_scan_or_error(scan_id)
    return scan_registry.get_report(scan_id)


@app.get("/api/reports/{scan_id}/findings", tags=["Reports"])
def get_report_findings(scan_id: str):
    _get_completed_scan_or_error(scan_id)
    return {"scan_id": scan_id, "findings": scan_registry.get_findings(scan_id)}


@app.get("/api/findings/{finding_id}", tags=["Reports"])
def get_finding(finding_id: str):
    match = FINDING_REF_PATTERN.fullmatch(finding_id)
    if match is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid finding ID")
    finding = scan_registry.get_finding(*match.groups())
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", DEFAULT_HOST)
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port, reload=True)

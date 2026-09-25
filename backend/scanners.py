"""
Phase 5 static analysis: runs Semgrep and Bandit over an extracted upload.

Uploaded code is only read by the scanners. It is never executed, imported, or
installed, and no argument is built from uploaded content except relative file
paths, which always come after "--". Raw scanner output is stored unmodified
for Phase 6 normalization.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from importlib import metadata
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parent / "semgrep_rules" / "vibe_guard.yml"

SEMGREP_TIMEOUT = 180  # seconds, whole run
SEMGREP_RULE_TIMEOUT = 30  # seconds, per rule and file
SEMGREP_MAX_TARGET_BYTES = 1_000_000
BANDIT_TIMEOUT = 120  # seconds, all batches together
BANDIT_BATCH_SIZE = 200  # keeps Windows command lines under their length limit

# Environment variables passed through to scanners. Everything else, including app secrets, is dropped.
PASSTHROUGH_ENV = ("SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "HOME", "LOCALAPPDATA", "APPDATA")

SUCCESS_STATUSES = {"completed", "skipped"}


class ScannerError(Exception):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def _find_tool(name: str) -> str | None:
    # Prefer the tool installed next to the running interpreter (the venv).
    local = Path(sys.executable).parent / (f"{name}.exe" if os.name == "nt" else name)
    if local.is_file():
        return str(local)
    return shutil.which(name)


def _scanner_env(tool: str) -> dict:
    # PATH holds only the tool's own directory, so scanners cannot reach git or other programs.
    env = {
        "PATH": str(Path(tool).parent),
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    for key in PASSTHROUGH_ENV:
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _kill_tree(proc: subprocess.Popen) -> None:
    if os.name == "nt":
        taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
        subprocess.run(
            [str(taskkill), "/F", "/T", "/PID", str(proc.pid)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.kill()
    proc.wait()


def _run(name: str, argv: list[str], cwd: Path, timeout: float, stderr_log: Path) -> int:
    """Run a scanner without a shell. Returns the exit code or raises ScannerError on timeout."""
    group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    with open(stderr_log, "ab") as log:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=_scanner_env(argv[0]), shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log, **group,
        )
        try:
            return proc.wait(timeout=max(timeout, 1))
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            raise ScannerError("timeout", f"{name} timed out")


def _load_json(name: str, path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ScannerError("failed", f"{name} produced missing or invalid JSON output")
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ScannerError("failed", f"{name} produced unexpected JSON output")
    return data


def _tool_version(package: str) -> str | None:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def _python_files(source_dir: Path) -> list[str]:
    root = source_dir.resolve()
    files = []
    for path in root.rglob("*.py"):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        files.append(path.relative_to(root).as_posix())
    return sorted(files)


def _semgrep(source_dir: Path, results_dir: Path) -> dict:
    tool = _find_tool("semgrep")
    if not tool:
        raise ScannerError("unavailable", "semgrep executable not found")
    output = results_dir / "semgrep.json"
    argv = [
        tool, "scan",
        "--config", str(RULES_PATH),
        "--json", "--output", str(output),
        "--metrics", "off",
        "--disable-version-check",
        "--disable-nosem",  # uploaded "nosemgrep" comments cannot hide findings
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",  # uploaded .semgrepignore cannot hide files
        "--project-root", ".",  # forces a non-VCS project, so git is never consulted
        "--max-target-bytes", str(SEMGREP_MAX_TARGET_BYTES),
        "--timeout", str(SEMGREP_RULE_TIMEOUT),
        "--quiet",
        "--", ".",
    ]
    exit_code = _run("semgrep", argv, source_dir, SEMGREP_TIMEOUT, results_dir / "semgrep.stderr.log")
    if exit_code != 0:
        raise ScannerError("failed", f"semgrep exited with code {exit_code}")
    raw = _load_json("semgrep", output)
    return {
        "exit_code": exit_code,
        "finding_count": len(raw["results"]),
        "error_count": len(raw.get("errors", [])),
        "targets_scanned": len(raw.get("paths", {}).get("scanned", [])),
    }


def _bandit(source_dir: Path, results_dir: Path) -> dict:
    files = _python_files(source_dir)
    if not files:
        return {"status": "skipped", "exit_code": None, "finding_count": 0, "error_count": 0, "targets_scanned": 0}
    tool = _find_tool("bandit")
    if not tool:
        raise ScannerError("unavailable", "bandit executable not found")

    deadline = time.monotonic() + BANDIT_TIMEOUT
    merged = {"results": [], "errors": [], "metrics": {}}
    exit_code = 0
    for index in range(0, len(files), BANDIT_BATCH_SIZE):
        batch_output = results_dir / f"bandit.batch{index // BANDIT_BATCH_SIZE}.json"
        # Explicit files and no -r, so an uploaded .bandit file is never loaded.
        argv = [tool, "-f", "json", "-o", str(batch_output), "-q", "--ignore-nosec", "--",
                *files[index:index + BANDIT_BATCH_SIZE]]
        code = _run("bandit", argv, source_dir, deadline - time.monotonic(), results_dir / "bandit.stderr.log")
        if code not in (0, 1):  # 1 means issues were found
            raise ScannerError("failed", f"bandit exited with code {code}")
        exit_code = max(exit_code, code)
        raw = _load_json("bandit", batch_output)
        batch_output.unlink()
        merged.setdefault("generated_at", raw.get("generated_at"))
        merged["results"].extend(raw["results"])
        merged["errors"].extend(raw.get("errors", []))
        merged["metrics"].update({k: v for k, v in raw.get("metrics", {}).items() if k != "_totals"})

    totals: dict = {}
    for file_metrics in merged["metrics"].values():
        for key, value in file_metrics.items():
            totals[key] = totals.get(key, 0) + value
    merged["metrics"]["_totals"] = totals
    (results_dir / "bandit.json").write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return {
        "exit_code": exit_code,
        "finding_count": len(merged["results"]),
        "error_count": len(merged["errors"]),
        "targets_scanned": len(files),
    }


SCANNERS = {"semgrep": ("semgrep", _semgrep), "bandit": ("bandit", _bandit)}


def run_static_analysis(source_dir: Path, results_dir: Path) -> dict[str, dict]:
    """
    Run every scanner and return a per-scanner summary, also written to results/summary.json.
    A failed, timed-out, or unavailable scanner is reported as such, never as zero findings.
    """
    results_dir.mkdir(parents=True, exist_ok=True)
    summary = {}
    for name, (package, scan) in SCANNERS.items():
        started = time.monotonic()
        meta = {"scanner": name, "version": _tool_version(package), "status": "completed", "exit_code": None,
                "finding_count": None, "error_count": None, "targets_scanned": None, "error": None}
        try:
            meta.update(scan(source_dir, results_dir))
        except ScannerError as exc:
            meta.update(status=exc.status, error=str(exc))
        except Exception:
            meta.update(status="failed", error=f"{name} could not be run")
        meta["duration_s"] = round(time.monotonic() - started, 2)
        summary[name] = meta
    (results_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def load_raw_results(results_dir: Path) -> dict[str, dict]:
    """Phase 6 input: {scanner: {"meta": summary, "raw": unmodified scanner JSON or None}}."""
    summary = json.loads((results_dir / "summary.json").read_text(encoding="utf-8"))
    raw_results = {}
    for name, meta in summary.items():
        raw_path = results_dir / f"{name}.json"
        raw = json.loads(raw_path.read_text(encoding="utf-8")) if meta["status"] == "completed" else None
        raw_results[name] = {"meta": meta, "raw": raw}
    return raw_results

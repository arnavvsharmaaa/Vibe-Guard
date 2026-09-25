"""
Phase 6 finding normalization: turns raw Semgrep and Bandit output into one Vibe Guard finding list.

Uploaded code is only read as text here, to take code snippets. It is never executed or imported.
Normalization is deterministic: the same raw results always produce the same findings, IDs, and order.
"""

import re
from pathlib import Path, PurePosixPath

from scanners import SEMGREP_MAX_TARGET_BYTES, SUCCESS_STATUSES

# The seven Blueprint categories. Findings outside them are kept as "other".
CATEGORIES = {
    "sql-injection": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "hardcoded-secret": "Hardcoded Secret",
    "command-injection": "Command Injection",
    "insecure-auth": "Insecure Authentication",
    "weak-crypto": "Weak Cryptography",
    "path-traversal": "Path Traversal",
    "other": "Other Security Issue",
}

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
DEFAULT_SEVERITY = "MEDIUM"  # used when a scanner reports a severity we do not recognize

SEMGREP_SEVERITY = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "INFO": "LOW",
    "LOW": "LOW",
}
BANDIT_SEVERITY = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}

# Bandit test IDs mapped to categories. Explicit "other" entries stop the CWE fallback from
# over-classifying informational checks (B404 only flags `import subprocess`).
BANDIT_TEST_CATEGORIES = {
    "B608": "sql-injection", "B610": "sql-injection", "B611": "sql-injection",
    "B308": "xss", "B701": "xss", "B702": "xss", "B703": "xss", "B704": "xss",
    "B105": "hardcoded-secret", "B106": "hardcoded-secret", "B107": "hardcoded-secret",
    "B601": "command-injection", "B602": "command-injection", "B603": "command-injection",
    "B604": "command-injection", "B605": "command-injection", "B606": "command-injection",
    "B607": "command-injection", "B609": "command-injection",
    "B501": "insecure-auth", "B507": "insecure-auth",
    "B303": "weak-crypto", "B304": "weak-crypto", "B305": "weak-crypto", "B311": "weak-crypto",
    "B324": "weak-crypto", "B413": "weak-crypto", "B502": "weak-crypto", "B503": "weak-crypto",
    "B504": "weak-crypto", "B505": "weak-crypto",
    "B202": "path-traversal",
    "B404": "other",
}

# Fallback when a rule is not mapped explicitly.
CWE_CATEGORIES = {
    89: "sql-injection",
    79: "xss", 80: "xss",
    798: "hardcoded-secret", 259: "hardcoded-secret", 321: "hardcoded-secret",
    78: "command-injection", 77: "command-injection",
    287: "insecure-auth", 256: "insecure-auth", 295: "insecure-auth", 306: "insecure-auth", 347: "insecure-auth",
    326: "weak-crypto", 327: "weak-crypto", 328: "weak-crypto", 330: "weak-crypto", 916: "weak-crypto",
    22: "path-traversal", 23: "path-traversal", 35: "path-traversal", 73: "path-traversal",
}

# Semgrep prefixes check_id with the rules file's absolute path; only the part from "vg." on is kept.
SEMGREP_RULE_PREFIX = re.compile(r"(?:^|\.)(vg\..+)$")
SEMGREP_UNAVAILABLE_TEXT = "requires login"

MAX_SNIPPET_LINES = 10
MAX_SNIPPET_CHARS = 2000
MAX_TEXT_CHARS = 1000


class NormalizationError(Exception):
    pass


def _category_from_cwe(cwe) -> str | None:
    """Accepts 'CWE-89', 'CWE-89: ...', 89, {'id': 89}, or a list of those."""
    if isinstance(cwe, list):
        for item in cwe:
            category = _category_from_cwe(item)
            if category:
                return category
        return None
    if isinstance(cwe, dict):
        cwe = cwe.get("id")
    if isinstance(cwe, bool):
        return None
    if isinstance(cwe, int):
        return CWE_CATEGORIES.get(cwe)
    if isinstance(cwe, str):
        match = re.match(r"\s*(?:CWE-)?(\d+)", cwe, re.IGNORECASE)
        if match:
            return CWE_CATEGORIES.get(int(match.group(1)))
    return None


def _cwe_label(cwe) -> str | None:
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if isinstance(cwe, dict):
        cwe = cwe.get("id")
    if isinstance(cwe, int) and not isinstance(cwe, bool) and cwe > 0:
        return f"CWE-{cwe}"
    if isinstance(cwe, str):
        match = re.match(r"\s*(?:CWE-)?(\d+)", cwe, re.IGNORECASE)
        if match:
            return f"CWE-{int(match.group(1))}"
    return None


def _positive_int(value) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return None


def _text(value) -> str:
    return value.strip()[:MAX_TEXT_CHARS] if isinstance(value, str) else ""


def _relative_path(raw_path, source_root: Path) -> str | None:
    """Scanner path → POSIX path relative to the source directory, or None if unsafe or malformed."""
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    path = raw_path.strip().replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", path) or path.startswith("/"):
        if source_root is None:
            return None
        try:
            path = Path(path).resolve().relative_to(source_root).as_posix()
        except (ValueError, OSError):
            return None
    parts = [part for part in PurePosixPath(path).parts if part != "."]
    if not parts or ".." in parts or ":" in parts[0]:
        return None
    return "/".join(parts)


class _SnippetReader:
    """Reads code lines from the extracted upload as plain text, staying inside the source directory."""

    def __init__(self, source_root: Path | None):
        self.root = source_root
        self._cache: dict[str, list[str] | None] = {}

    def _lines(self, rel_path: str) -> list[str] | None:
        if rel_path not in self._cache:
            self._cache[rel_path] = None
            if self.root is not None:
                path = self.root / rel_path
                try:
                    if (not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(self.root)
                            and path.stat().st_size <= SEMGREP_MAX_TARGET_BYTES):
                        self._cache[rel_path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    pass
        return self._cache[rel_path]

    def snippet(self, rel_path: str, start: int, end: int | None) -> str | None:
        lines = self._lines(rel_path)
        if not lines or start > len(lines):
            return None
        end = min(max(end or start, start), start + MAX_SNIPPET_LINES - 1)
        return "\n".join(lines[start - 1:end])[:MAX_SNIPPET_CHARS]


def _finding(category: str, severity: str, file: str, line: int, **fields) -> dict:
    return {
        "id": None,
        "type": CATEGORIES[category],
        "category": category,
        "severity": severity,
        "file": file,
        "line": line,
        **fields,
        "related_rules": [],
    }


def _normalize_semgrep(result, source_root, reader) -> tuple[dict | None, str | None]:
    if not isinstance(result, dict):
        return None, "result is not an object"
    check_id = result.get("check_id")
    if not isinstance(check_id, str) or not check_id.strip():
        return None, "missing check_id"
    match = SEMGREP_RULE_PREFIX.search(check_id)
    # Rules outside the local ruleset keep only their last segment, so no server path leaks through.
    rule = match.group(1) if match else check_id.rsplit(".", 1)[-1]
    file = _relative_path(result.get("path"), source_root)
    if file is None:
        return None, "missing or unsafe path"
    start = result.get("start") if isinstance(result.get("start"), dict) else {}
    end = result.get("end") if isinstance(result.get("end"), dict) else {}
    line = _positive_int(start.get("line"))
    if line is None:
        return None, "missing or invalid line"
    extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}

    raw_severity = extra.get("severity")
    severity = SEMGREP_SEVERITY.get(raw_severity.upper() if isinstance(raw_severity, str) else None, DEFAULT_SEVERITY)
    declared = metadata.get("category")
    category = (declared if declared in CATEGORIES and declared != "other" else None) \
        or _category_from_cwe(metadata.get("cwe")) or "other"
    end_line = _positive_int(end.get("line")) or line

    code = reader.snippet(file, line, end_line)
    if code is None:
        lines = extra.get("lines")
        code = lines[:MAX_SNIPPET_CHARS] if isinstance(lines, str) and lines != SEMGREP_UNAVAILABLE_TEXT else None

    confidence = metadata.get("confidence")
    return _finding(
        category, severity, file, line,
        end_line=end_line,
        column=_positive_int(start.get("col")),
        code=code,
        rule=rule,
        scanner="semgrep",
        message=_text(extra.get("message")) or rule,
        cwe=_cwe_label(metadata.get("cwe")),
        confidence=confidence.upper() if isinstance(confidence, str) and confidence.upper() in CONFIDENCES else None,
        scanners=["semgrep"],
        scanner_metadata={"semgrep": {
            "rule_id": rule,
            "severity": raw_severity if isinstance(raw_severity, str) else None,
            "metadata": metadata,
            "start": {"line": line, "col": _positive_int(start.get("col"))},
            "end": {"line": end_line, "col": _positive_int(end.get("col"))},
            "engine_kind": extra.get("engine_kind") if isinstance(extra.get("engine_kind"), str) else None,
        }},
    ), None


def _normalize_bandit(result, source_root, reader) -> tuple[dict | None, str | None]:
    if not isinstance(result, dict):
        return None, "result is not an object"
    test_id = result.get("test_id")
    if not isinstance(test_id, str) or not test_id.strip():
        return None, "missing test_id"
    test_id = test_id.strip()
    file = _relative_path(result.get("filename"), source_root)
    if file is None:
        return None, "missing or unsafe path"
    line = _positive_int(result.get("line_number"))
    if line is None:
        return None, "missing or invalid line"

    raw_severity = result.get("issue_severity")
    severity = BANDIT_SEVERITY.get(raw_severity.upper() if isinstance(raw_severity, str) else None, DEFAULT_SEVERITY)
    cwe = result.get("issue_cwe")
    category = BANDIT_TEST_CATEGORIES.get(test_id) or _category_from_cwe(cwe) or "other"
    line_range = result.get("line_range")
    line_range = [n for n in line_range if _positive_int(n)] if isinstance(line_range, list) else []
    end_line = max([line, *line_range])

    code = reader.snippet(file, line, end_line)
    if code is None and isinstance(result.get("code"), str):
        # Bandit prefixes each snippet line with its line number; keep only the reported lines.
        kept = []
        for text in result["code"].splitlines():
            number, _, rest = text.partition(" ")
            if number.isdigit() and line <= int(number) <= end_line:
                kept.append(rest)
        code = "\n".join(kept)[:MAX_SNIPPET_CHARS] or None

    raw_confidence = result.get("issue_confidence")
    confidence = raw_confidence.upper() if isinstance(raw_confidence, str) else None
    test_name = _text(result.get("test_name"))
    return _finding(
        category, severity, file, line,
        end_line=end_line,
        column=result["col_offset"] + 1 if isinstance(result.get("col_offset"), int)
        and not isinstance(result.get("col_offset"), bool) and result["col_offset"] >= 0 else None,
        code=code,
        rule=f"bandit.{test_id}" + (f".{test_name}" if test_name else ""),
        scanner="bandit",
        message=_text(result.get("issue_text")) or test_id,
        cwe=_cwe_label(cwe),
        confidence=confidence if confidence in CONFIDENCES else None,
        scanners=["bandit"],
        scanner_metadata={"bandit": {
            "test_id": test_id,
            "test_name": test_name or None,
            "issue_severity": raw_severity if isinstance(raw_severity, str) else None,
            "issue_confidence": raw_confidence if isinstance(raw_confidence, str) else None,
            "issue_cwe": cwe if isinstance(cwe, dict) else None,
            "more_info": _text(result.get("more_info")) or None,
            "line_range": line_range or [line],
        }},
    ), None


NORMALIZERS = {"semgrep": _normalize_semgrep, "bandit": _normalize_bandit}


def _sort_key(finding: dict) -> tuple:
    return (SEVERITY_RANK[finding["severity"]], finding["file"], finding["line"], finding["category"],
            finding["scanner"], finding["rule"], finding["column"] or 0)


def _merge_duplicates(findings: list[dict]) -> tuple[list[dict], int]:
    """
    Merge findings for the same category at the same file and line reported by different scanners.
    The most severe report is kept as the primary; the others' metadata is preserved.
    Exact repeats from the same scanner and rule are dropped. "other" findings are never merged across rules.
    """
    merged: dict[tuple, dict] = {}
    seen_rules: set[tuple] = set()
    removed = 0
    for finding in sorted(findings, key=_sort_key):
        rule_key = (finding["scanner"], finding["rule"], finding["file"], finding["line"], finding["column"])
        if rule_key in seen_rules:
            removed += 1
            continue
        seen_rules.add(rule_key)
        if finding["category"] == "other":
            merged[("other", *rule_key)] = finding
            continue
        key = (finding["category"], finding["file"], finding["line"])
        primary = merged.get(key)
        if primary is None:
            merged[key] = finding
            continue
        removed += 1
        if finding["scanner"] not in primary["scanners"]:
            primary["scanners"].append(finding["scanner"])
        primary["end_line"] = max(primary["end_line"], finding["end_line"])
        primary["cwe"] = primary["cwe"] or finding["cwe"]
        primary["code"] = primary["code"] or finding["code"]
        primary["confidence"] = primary["confidence"] or finding["confidence"]
        primary["related_rules"].append(finding["rule"])
        for scanner, meta in finding["scanner_metadata"].items():
            primary["scanner_metadata"].setdefault(scanner, meta)
    return sorted(merged.values(), key=_sort_key), removed


def normalize_findings(raw_results: dict[str, dict], source_dir: Path | None = None) -> dict:
    """
    Normalize `scanners.load_raw_results()` output into Vibe Guard findings.

    Returns {"findings": [...], "summary": {...}, "skipped": [...]}. Individual malformed scanner
    results are skipped and recorded; a scanner that did not succeed, or whose output is not the
    expected shape, raises NormalizationError so it is never reported as zero findings.
    """
    if not isinstance(raw_results, dict):
        raise NormalizationError("raw results are not an object")
    source_root = source_dir.resolve() if source_dir is not None else None
    reader = _SnippetReader(source_root)
    findings, skipped = [], []

    for scanner in sorted(raw_results):
        entry = raw_results[scanner]
        normalizer = NORMALIZERS.get(scanner)
        if normalizer is None:
            raise NormalizationError(f"unknown scanner '{scanner}'")
        meta = entry.get("meta") if isinstance(entry, dict) else None
        status = meta.get("status") if isinstance(meta, dict) else None
        if status not in SUCCESS_STATUSES:
            raise NormalizationError(f"{scanner} did not complete (status: {status})")
        raw = entry.get("raw")
        if status == "skipped" and raw is None:
            continue
        if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
            raise NormalizationError(f"{scanner} output is missing or malformed")
        for index, result in enumerate(raw["results"]):
            finding, reason = normalizer(result, source_root, reader)
            if finding is None:
                skipped.append({"scanner": scanner, "index": index, "reason": reason})
            else:
                findings.append(finding)

    findings, duplicates_merged = _merge_duplicates(findings)
    width = max(3, len(str(len(findings))))
    for number, finding in enumerate(findings, start=1):
        finding["id"] = f"VG-{number:0{width}d}"

    return {
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES},
            "by_category": {c: sum(f["category"] == c for f in findings) for c in CATEGORIES},
            "by_scanner": {s: sum(s in f["scanners"] for f in findings) for s in sorted(raw_results)},
            "duplicates_merged": duplicates_merged,
            "skipped_count": len(skipped),
        },
        "skipped": skipped,
    }

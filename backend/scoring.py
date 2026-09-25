"""
Phase 7 deterministic security score, computed from Phase 6 normalized findings.

Formula (version 1), integers only:

    penalty(severity) = min(count(severity) * WEIGHT[severity], CAP[severity])
    score             = max(0, 100 - sum(penalty(severity) for every severity))

    Severity   Weight per finding   Cap for the severity
    CRITICAL   25                   75
    HIGH       10                   50
    MEDIUM      4                   20
    LOW         1                   10

Every normalized finding counts once, whatever its category and however many scanners reported it
(duplicates were already merged in Phase 6). The caps stop a flood of lower-severity findings from
outweighing a single more severe one: all LOW findings together cost at most 10 points, less than
one HIGH finding plus one MEDIUM finding. Zero findings score 100.

Label thresholds match the React score ring: 85+ Strong, 70+ Good, 40+ Needs work, below 40 At risk.

No AI is involved, and the input findings are never modified.
"""

from normalization import CATEGORIES, SEVERITIES

FORMULA_VERSION = 1
MAX_SCORE = 100

SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
SEVERITY_CAPS = {"CRITICAL": 75, "HIGH": 50, "MEDIUM": 20, "LOW": 10}

# (minimum score, label), checked from the top.
SCORE_LABELS = ((85, "Strong"), (70, "Good"), (40, "Needs work"), (0, "At risk"))


class ScoringError(Exception):
    pass


def score_label(score: int) -> str:
    for minimum, label in SCORE_LABELS:
        if score >= minimum:
            return label
    raise ScoringError(f"score {score} is out of range")


def calculate_security_score(normalized: dict) -> dict:
    """
    Score the output of `normalization.normalize_findings()`.
    Raises ScoringError if a finding has an unknown severity or category, so bad input is never scored silently.
    """
    findings = normalized.get("findings") if isinstance(normalized, dict) else None
    if not isinstance(findings, list):
        raise ScoringError("normalized findings are missing or malformed")

    severity_counts = dict.fromkeys(SEVERITIES, 0)
    category_counts = {category: dict.fromkeys(SEVERITIES, 0) for category in CATEGORIES}
    for index, finding in enumerate(findings):
        severity = finding.get("severity") if isinstance(finding, dict) else None
        category = finding.get("category") if isinstance(finding, dict) else None
        if severity not in severity_counts:
            raise ScoringError(f"finding {index} has an unknown severity")
        if category not in category_counts:
            raise ScoringError(f"finding {index} has an unknown category")
        severity_counts[severity] += 1
        category_counts[category][severity] += 1

    by_severity = {}
    for severity in SEVERITIES:
        count = severity_counts[severity]
        by_severity[severity] = {
            "count": count,
            "weight": SEVERITY_WEIGHTS[severity],
            "cap": SEVERITY_CAPS[severity],
            "penalty": min(count * SEVERITY_WEIGHTS[severity], SEVERITY_CAPS[severity]),
        }
    total_penalty = sum(entry["penalty"] for entry in by_severity.values())
    score = max(0, MAX_SCORE - total_penalty)

    return {
        "score": score,
        "max_score": MAX_SCORE,
        "label": score_label(score),
        "formula_version": FORMULA_VERSION,
        "total_penalty": total_penalty,
        "finding_count": len(findings),
        "highest_severity": next((s for s in SEVERITIES if severity_counts[s]), None),
        "by_severity": by_severity,
        "by_category": {
            category: {"type": CATEGORIES[category], "count": sum(counts.values()), "by_severity": counts}
            for category, counts in category_counts.items()
        },
    }

"""Phase 7 security score tests. Run from backend/: python -m unittest discover -s tests -v"""

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from normalization import normalize_findings  # noqa: E402
from scoring import ScoringError, calculate_security_score, score_label  # noqa: E402


def finding(severity="HIGH", category="sql-injection", line=1, **fields):
    return {"id": f"VG-{line:03d}", "type": "x", "category": category, "severity": severity, "file": "app.py",
            "line": line, "scanner": "semgrep", "scanners": ["semgrep"], **fields}


def normalized(*severities, category="sql-injection"):
    return {"findings": [finding(s, category, n) for n, s in enumerate(severities, start=1)]}


def score_of(*severities):
    return calculate_security_score(normalized(*severities))["score"]


class ZeroFindingTests(unittest.TestCase):
    def test_zero_findings_score_100(self):
        result = calculate_security_score({"findings": []})
        self.assertEqual((result["score"], result["label"], result["total_penalty"]), (100, "Strong", 0))
        self.assertEqual(result["finding_count"], 0)
        self.assertIsNone(result["highest_severity"])
        self.assertTrue(all(entry["count"] == 0 and entry["penalty"] == 0 for entry in result["by_severity"].values()))
        self.assertTrue(all(entry["count"] == 0 for entry in result["by_category"].values()))

    def test_real_empty_normalizer_output(self):
        empty = normalize_findings({"semgrep": {"meta": {"status": "completed"}, "raw": {"results": []}},
                                    "bandit": {"meta": {"status": "skipped"}, "raw": None}})
        self.assertEqual(calculate_security_score(empty)["score"], 100)


class SeverityWeightTests(unittest.TestCase):
    def test_single_finding_per_severity(self):
        self.assertEqual(score_of("CRITICAL"), 75)
        self.assertEqual(score_of("HIGH"), 90)
        self.assertEqual(score_of("MEDIUM"), 96)
        self.assertEqual(score_of("LOW"), 99)

    def test_severity_ordering(self):
        self.assertLess(score_of("CRITICAL"), score_of("HIGH"))
        self.assertLess(score_of("HIGH"), score_of("MEDIUM"))
        self.assertLess(score_of("MEDIUM"), score_of("LOW"))
        self.assertLess(score_of("LOW"), 100)

    def test_mixed_combination(self):
        # 25 + 2*10 + 3*4 + 4*1 = 61
        result = calculate_security_score(normalized("CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM",
                                                     "LOW", "LOW", "LOW", "LOW"))
        self.assertEqual((result["score"], result["total_penalty"], result["label"]), (39, 61, "At risk"))
        self.assertEqual(result["highest_severity"], "CRITICAL")
        self.assertEqual({s: e["penalty"] for s, e in result["by_severity"].items()},
                         {"CRITICAL": 25, "HIGH": 20, "MEDIUM": 12, "LOW": 4})

    def test_adding_a_finding_never_raises_score(self):
        base = ["HIGH", "MEDIUM", "LOW"]
        for extra in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            with self.subTest(extra=extra):
                self.assertLessEqual(score_of(*base, extra), score_of(*base))

    def test_highest_severity(self):
        self.assertEqual(calculate_security_score(normalized("LOW", "MEDIUM"))["highest_severity"], "MEDIUM")


class BoundaryTests(unittest.TestCase):
    def test_caps(self):
        self.assertEqual(score_of(*["LOW"] * 10), 90)
        self.assertEqual(score_of(*["LOW"] * 500), 90)  # LOW capped at 10
        self.assertEqual(score_of(*["MEDIUM"] * 5), 80)
        self.assertEqual(score_of(*["MEDIUM"] * 6), 80)  # MEDIUM capped at 20
        self.assertEqual(score_of(*["HIGH"] * 5), 50)
        self.assertEqual(score_of(*["HIGH"] * 50), 50)  # HIGH capped at 50
        self.assertEqual(score_of(*["CRITICAL"] * 3), 25)
        self.assertEqual(score_of(*["CRITICAL"] * 4), 25)  # CRITICAL capped at 75

    def test_capped_low_findings_cost_less_than_one_high_and_one_medium(self):
        self.assertGreater(score_of(*["LOW"] * 1000), score_of("HIGH", "MEDIUM"))

    def test_floor_at_zero(self):
        result = calculate_security_score(normalized(*["CRITICAL"] * 3, *["HIGH"] * 5, *["MEDIUM"] * 5, *["LOW"] * 10))
        self.assertEqual((result["total_penalty"], result["score"], result["label"]), (155, 0, "At risk"))
        self.assertEqual(score_of(*["CRITICAL"] * 3, "HIGH", "HIGH", "HIGH"), 0)
        self.assertEqual(score_of(*["CRITICAL"] * 3, "HIGH", "HIGH"), 5)

    def test_label_thresholds(self):
        cases = {100: "Strong", 85: "Strong", 84: "Good", 70: "Good", 69: "Needs work", 40: "Needs work",
                 39: "At risk", 0: "At risk"}
        for score, label in cases.items():
            with self.subTest(score=score):
                self.assertEqual(score_label(score), label)
        with self.assertRaises(ScoringError):
            score_label(-1)

    def test_score_is_always_an_int_in_range(self):
        for n in range(0, 40):
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                score = score_of(*[severity] * n)
                self.assertIsInstance(score, int)
                self.assertTrue(0 <= score <= 100)


class BreakdownTests(unittest.TestCase):
    def test_category_breakdown(self):
        data = {"findings": [finding("HIGH", "sql-injection", 1), finding("LOW", "sql-injection", 2),
                             finding("MEDIUM", "xss", 3), finding("LOW", "other", 4)]}
        result = calculate_security_score(data)
        self.assertEqual(set(result["by_category"]), {"sql-injection", "xss", "hardcoded-secret", "command-injection",
                                                      "insecure-auth", "weak-crypto", "path-traversal", "other"})
        sqli = result["by_category"]["sql-injection"]
        self.assertEqual((sqli["type"], sqli["count"]), ("SQL Injection", 2))
        self.assertEqual(sqli["by_severity"], {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 1})
        self.assertEqual(result["by_category"]["other"]["count"], 1)
        self.assertEqual(result["score"], 100 - (10 + 4 + 1 + 1))  # "other" findings count by severity too

    def test_output_is_json_serializable_and_documents_formula(self):
        result = calculate_security_score(normalized("HIGH"))
        self.assertEqual(json.loads(json.dumps(result)), result)
        self.assertEqual((result["max_score"], result["formula_version"]), (100, 1))
        self.assertEqual(result["by_severity"]["HIGH"], {"count": 1, "weight": 10, "cap": 50, "penalty": 10})


class DeterminismTests(unittest.TestCase):
    def test_same_findings_same_score(self):
        data = normalized("CRITICAL", "HIGH", "LOW", "MEDIUM", "HIGH")
        self.assertEqual(calculate_security_score(data), calculate_security_score(copy.deepcopy(data)))

    def test_order_independent(self):
        data = normalized("CRITICAL", "HIGH", "LOW", "MEDIUM", "HIGH")
        reversed_data = {"findings": list(reversed(data["findings"]))}
        self.assertEqual(calculate_security_score(data), calculate_security_score(reversed_data))

    def test_input_is_not_modified(self):
        data = normalized("HIGH", "LOW")
        data["summary"] = {"total": 2}
        before = copy.deepcopy(data)
        calculate_security_score(data)
        self.assertEqual(data, before)

    def test_merged_duplicate_counts_once(self):
        merged = finding("HIGH", scanners=["semgrep", "bandit"], related_rules=["bandit.B608"])
        self.assertEqual(calculate_security_score({"findings": [merged]})["score"], 90)


class InvalidInputTests(unittest.TestCase):
    def test_malformed_container(self):
        for bad in (None, [], {}, {"findings": None}, {"findings": "x"}):
            with self.subTest(bad=bad):
                with self.assertRaises(ScoringError):
                    calculate_security_score(bad)

    def test_invalid_findings(self):
        for bad in ("x", None, finding("SEVERE"), finding("high"), finding(None), finding("HIGH", "rce"),
                    finding("HIGH", None)):
            with self.subTest(bad=bad):
                with self.assertRaises(ScoringError):
                    calculate_security_score({"findings": [finding(), bad]})


if __name__ == "__main__":
    unittest.main()

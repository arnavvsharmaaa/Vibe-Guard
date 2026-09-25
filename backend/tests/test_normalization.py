"""Phase 6 finding normalization tests. Run from backend/: python -m unittest discover -s tests -v"""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from normalization import NormalizationError, normalize_findings  # noqa: E402

RULES_PREFIX = "C.Users.someone.app.backend.semgrep_rules."


def semgrep_result(rule="vg.python.sql-injection.string-built-query", path="app.py", line=2, severity="ERROR",
                   metadata=None, **extra):
    return {
        "check_id": RULES_PREFIX + rule,
        "path": path,
        "start": {"line": line, "col": 5, "offset": 0},
        "end": {"line": line, "col": 40, "offset": 0},
        "extra": {
            "message": "SQL query built with string formatting",
            "metadata": {"category": "sql-injection", "cwe": "CWE-89"} if metadata is None else metadata,
            "severity": severity,
            "fingerprint": "requires login",
            "lines": "requires login",
            "engine_kind": "OSS",
            **extra,
        },
    }


def bandit_result(test_id="B608", path=".\\app.py", line=2, severity="MEDIUM", confidence="LOW", cwe=89, **fields):
    return {
        "code": f"{line} cur.execute(query)\n{line + 1} return\n",
        "col_offset": 4,
        "filename": path,
        "issue_confidence": confidence,
        "issue_cwe": {"id": cwe, "link": f"https://cwe.mitre.org/data/definitions/{cwe}.html"},
        "issue_severity": severity,
        "issue_text": "Possible SQL injection vector through string-based query construction.",
        "line_number": line,
        "line_range": [line],
        "more_info": "https://bandit.readthedocs.io/",
        "test_id": test_id,
        "test_name": "hardcoded_sql_expressions",
        **fields,
    }


def raw(semgrep=None, bandit=None, bandit_status="completed"):
    results = {"semgrep": {"meta": {"status": "completed"}, "raw": {"results": semgrep or [], "errors": []}}}
    if bandit_status == "skipped":
        results["bandit"] = {"meta": {"status": "skipped"}, "raw": None}
    else:
        results["bandit"] = {"meta": {"status": bandit_status}, "raw": {"results": bandit or [], "errors": []}}
    return results


class NormalizationTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.source = self.tmp / "source"
        (self.source / "sub").mkdir(parents=True)
        (self.source / "app.py").write_text(
            "import sqlite3\n    cur.execute('SELECT %s' % name)\npassword = 'hunter22'\n", encoding="utf-8")
        (self.source / "sub" / "web.js").write_text("el.innerHTML = x;\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def normalize(self, raw_results):
        return normalize_findings(raw_results, self.source)


class SchemaTests(NormalizationTestCase):
    FIELDS = {"id", "type", "category", "severity", "file", "line", "end_line", "column", "code", "rule", "scanner",
              "message", "cwe", "confidence", "scanners", "scanner_metadata", "related_rules"}

    def test_semgrep_finding_schema(self):
        finding = self.normalize(raw(semgrep=[semgrep_result()]))["findings"][0]
        self.assertEqual(set(finding), self.FIELDS)
        self.assertEqual(finding["id"], "VG-001")
        self.assertEqual(finding["type"], "SQL Injection")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["file"], "app.py")
        self.assertEqual((finding["line"], finding["column"]), (2, 5))
        self.assertEqual(finding["rule"], "vg.python.sql-injection.string-built-query")
        self.assertEqual(finding["scanner"], "semgrep")
        self.assertEqual(finding["cwe"], "CWE-89")
        self.assertEqual(finding["scanner_metadata"]["semgrep"]["severity"], "ERROR")

    def test_bandit_finding_schema(self):
        finding = self.normalize(raw(bandit=[bandit_result()]))["findings"][0]
        self.assertEqual(set(finding), self.FIELDS)
        self.assertEqual(finding["file"], "app.py")  # ".\\app.py" normalized
        self.assertEqual(finding["column"], 5)  # col_offset 4 → 1-based
        self.assertEqual(finding["rule"], "bandit.B608.hardcoded_sql_expressions")
        self.assertEqual(finding["confidence"], "LOW")
        meta = finding["scanner_metadata"]["bandit"]
        self.assertEqual((meta["test_id"], meta["issue_severity"], meta["issue_confidence"]), ("B608", "MEDIUM", "LOW"))
        self.assertEqual(meta["issue_cwe"]["id"], 89)

    def test_server_path_is_stripped_from_semgrep_rule(self):
        output = json.dumps(self.normalize(raw(semgrep=[semgrep_result()])))
        self.assertNotIn("someone", output)
        foreign = semgrep_result()
        foreign["check_id"] = "C.Users.someone.rules.python.lang.security.audit.foo"
        finding = self.normalize(raw(semgrep=[foreign]))["findings"][0]
        self.assertEqual(finding["rule"], "foo")

    def test_code_snippet_read_from_source_not_requires_login(self):
        finding = self.normalize(raw(semgrep=[semgrep_result()]))["findings"][0]
        self.assertEqual(finding["code"], "    cur.execute('SELECT %s' % name)")

    def test_code_snippet_fallbacks_without_source(self):
        semgrep = normalize_findings(raw(semgrep=[semgrep_result()]))["findings"][0]
        self.assertIsNone(semgrep["code"])  # "requires login" is never used as code
        bandit = normalize_findings(raw(bandit=[bandit_result()]))["findings"][0]
        self.assertEqual(bandit["code"], "cur.execute(query)")  # line-number prefix and context removed

    def test_windows_nested_path(self):
        result = semgrep_result("vg.js.xss.inner-html", path="sub\\web.js", line=1, severity="WARNING",
                                metadata={"category": "xss", "cwe": "CWE-79"})
        finding = self.normalize(raw(semgrep=[result]))["findings"][0]
        self.assertEqual(finding["file"], "sub/web.js")
        self.assertEqual(finding["code"], "el.innerHTML = x;")

    def test_absolute_path_inside_source_is_made_relative(self):
        result = semgrep_result(path=str(self.source / "app.py"))
        self.assertEqual(self.normalize(raw(semgrep=[result]))["findings"][0]["file"], "app.py")

    def test_deterministic_output(self):
        data = raw(semgrep=[semgrep_result(line=3), semgrep_result()], bandit=[bandit_result(), bandit_result("B101", line=1)])
        self.assertEqual(self.normalize(data), self.normalize(json.loads(json.dumps(data))))
        reversed_data = raw(semgrep=[semgrep_result(), semgrep_result(line=3)],
                            bandit=[bandit_result("B101", line=1), bandit_result()])
        self.assertEqual(self.normalize(data)["findings"], self.normalize(reversed_data)["findings"])


class SeverityMappingTests(NormalizationTestCase):
    def test_semgrep_severities(self):
        cases = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "CRITICAL": "CRITICAL",
                 "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "BOGUS": "MEDIUM", None: "MEDIUM"}
        for raw_severity, expected in cases.items():
            with self.subTest(raw_severity=raw_severity):
                finding = self.normalize(raw(semgrep=[semgrep_result(severity=raw_severity)]))["findings"][0]
                self.assertEqual(finding["severity"], expected)

    def test_bandit_severities(self):
        cases = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "UNDEFINED": "MEDIUM", 7: "MEDIUM"}
        for raw_severity, expected in cases.items():
            with self.subTest(raw_severity=raw_severity):
                finding = self.normalize(raw(bandit=[bandit_result(severity=raw_severity)]))["findings"][0]
                self.assertEqual(finding["severity"], expected)

    def test_bandit_confidence_normalized(self):
        self.assertEqual(self.normalize(raw(bandit=[bandit_result(confidence="high")]))["findings"][0]["confidence"], "HIGH")
        self.assertIsNone(self.normalize(raw(bandit=[bandit_result(confidence="UNDEFINED")]))["findings"][0]["confidence"])

    def test_findings_sorted_by_severity(self):
        data = raw(semgrep=[semgrep_result(severity="INFO", line=1), semgrep_result(severity="ERROR", line=3)])
        findings = self.normalize(data)["findings"]
        self.assertEqual([f["severity"] for f in findings], ["HIGH", "LOW"])
        self.assertEqual([f["id"] for f in findings], ["VG-001", "VG-002"])


class CategoryMappingTests(NormalizationTestCase):
    def test_all_local_semgrep_rule_categories(self):
        expected = {
            "sql-injection": "SQL Injection", "xss": "Cross-Site Scripting", "hardcoded-secret": "Hardcoded Secret",
            "command-injection": "Command Injection", "insecure-auth": "Insecure Authentication",
            "weak-crypto": "Weak Cryptography", "path-traversal": "Path Traversal",
        }
        rules = [semgrep_result(f"vg.python.{slug}.rule", line=n, metadata={"category": slug})
                 for n, slug in enumerate(expected, start=1)]
        findings = self.normalize(raw(semgrep=rules))["findings"]
        self.assertEqual({f["category"]: f["type"] for f in findings}, expected)

    def test_every_rule_in_local_ruleset_has_a_known_category(self):
        from normalization import CATEGORIES
        rules = (Path(__file__).resolve().parents[1] / "semgrep_rules" / "vibe_guard.yml").read_text(encoding="utf-8")
        declared = set(__import__("re").findall(r"category: ([\w-]+)", rules))
        self.assertEqual(declared, set(CATEGORIES) - {"other"})

    def test_semgrep_falls_back_to_cwe(self):
        cases = [("CWE-78: OS Command Injection", "command-injection"), (["CWE-327"], "weak-crypto"),
                 ("CWE-22", "path-traversal"), ("CWE-999", "other"), (None, "other")]
        for cwe, expected in cases:
            with self.subTest(cwe=cwe):
                result = semgrep_result(metadata={"category": "security", "cwe": cwe})
                self.assertEqual(self.normalize(raw(semgrep=[result]))["findings"][0]["category"], expected)

    def test_bandit_test_ids(self):
        cases = {"B608": "sql-injection", "B703": "xss", "B105": "hardcoded-secret", "B602": "command-injection",
                 "B501": "insecure-auth", "B324": "weak-crypto", "B202": "path-traversal",
                 "B404": "other", "B101": "other"}
        for test_id, expected in cases.items():
            with self.subTest(test_id=test_id):
                result = bandit_result(test_id, cwe=0)
                self.assertEqual(self.normalize(raw(bandit=[result]))["findings"][0]["category"], expected)

    def test_bandit_unknown_test_falls_back_to_cwe(self):
        finding = self.normalize(raw(bandit=[bandit_result("B999", cwe=798)]))["findings"][0]
        self.assertEqual(finding["category"], "hardcoded-secret")

    def test_summary_counts(self):
        summary = self.normalize(raw(semgrep=[semgrep_result()], bandit=[bandit_result("B101", line=1, cwe=703)]))["summary"]
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["by_category"]["sql-injection"], 1)
        self.assertEqual(summary["by_category"]["other"], 1)
        self.assertEqual(summary["by_severity"], {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0})
        self.assertEqual(summary["by_scanner"], {"bandit": 1, "semgrep": 1})


class MalformedFindingTests(NormalizationTestCase):
    def test_malformed_semgrep_results_are_skipped_and_recorded(self):
        no_start = semgrep_result()
        del no_start["start"]
        bad_line = semgrep_result(line="7")
        zero_line = semgrep_result(line=0)
        bool_line = semgrep_result(line=True)
        no_path = semgrep_result(path=None)
        traversal = semgrep_result(path="../../etc/passwd")
        outside = semgrep_result(path="C:/Windows/win.ini")
        no_check = semgrep_result()
        no_check["check_id"] = ""
        results = ["not a dict", None, no_start, bad_line, zero_line, bool_line, no_path, traversal, outside,
                   no_check, semgrep_result()]
        normalized = self.normalize(raw(semgrep=results))
        self.assertEqual(normalized["summary"]["total"], 1)
        self.assertEqual(normalized["summary"]["skipped_count"], 10)
        self.assertEqual([s["index"] for s in normalized["skipped"]], list(range(10)))
        self.assertTrue(all(s["scanner"] == "semgrep" and s["reason"] for s in normalized["skipped"]))
        self.assertNotIn("Windows", json.dumps(normalized))

    def test_malformed_bandit_results_are_skipped_and_recorded(self):
        no_test = bandit_result()
        del no_test["test_id"]
        no_line = bandit_result()
        no_line["line_number"] = None
        results = [42, no_test, no_line, bandit_result(path=""), bandit_result()]
        normalized = self.normalize(raw(bandit=results))
        self.assertEqual(normalized["summary"]["total"], 1)
        self.assertEqual([s["reason"] for s in normalized["skipped"]],
                         ["result is not an object", "missing test_id", "missing or invalid line", "missing or unsafe path"])

    def test_partial_optional_fields_use_defaults(self):
        result = {"check_id": "vg.python.xss.markup-safe", "path": "app.py", "start": {"line": 1}, "extra": "junk"}
        finding = self.normalize(raw(semgrep=[result]))["findings"][0]
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["category"], "other")
        self.assertEqual(finding["message"], "vg.python.xss.markup-safe")
        self.assertEqual(finding["end_line"], 1)
        self.assertIsNone(finding["column"])

    def test_bandit_odd_fields(self):
        result = bandit_result(col_offset=-1, line_range="bad", issue_cwe="junk", issue_text=None, test_name=None)
        finding = self.normalize(raw(bandit=[result]))["findings"][0]
        self.assertIsNone(finding["column"])
        self.assertEqual(finding["end_line"], 2)
        self.assertEqual(finding["rule"], "bandit.B608")
        self.assertEqual(finding["message"], "B608")
        self.assertIsNone(finding["cwe"])

    def test_line_beyond_file_or_missing_file_has_no_code(self):
        self.assertIsNone(self.normalize(raw(semgrep=[semgrep_result(line=999)]))["findings"][0]["code"])
        self.assertIsNone(self.normalize(raw(semgrep=[semgrep_result(path="gone.py")]))["findings"][0]["code"])

    def test_snippet_is_capped(self):
        (self.source / "long.py").write_text("\n".join(f"x{n} = {n}" for n in range(100)), encoding="utf-8")
        result = semgrep_result(path="long.py", line=1)
        result["end"]["line"] = 100
        code = self.normalize(raw(semgrep=[result]))["findings"][0]["code"]
        self.assertEqual(len(code.splitlines()), 10)

    def test_malformed_scanner_output_raises(self):
        for bad in (None, {"results": "nope"}, {"no_results": []}, []):
            with self.subTest(raw=bad):
                data = raw()
                data["semgrep"]["raw"] = bad
                with self.assertRaises(NormalizationError):
                    self.normalize(data)

    def test_failed_scanner_is_never_zero_findings(self):
        for status in ("failed", "timeout", "unavailable", None):
            with self.subTest(status=status):
                with self.assertRaises(NormalizationError):
                    self.normalize(raw(bandit_status=status))

    def test_unknown_scanner_and_bad_input_raise(self):
        data = raw()
        data["eslint"] = {"meta": {"status": "completed"}, "raw": {"results": []}}
        with self.assertRaises(NormalizationError):
            self.normalize(data)
        with self.assertRaises(NormalizationError):
            self.normalize([])
        with self.assertRaises(NormalizationError):
            self.normalize({"semgrep": "junk"})


class EmptyResultTests(NormalizationTestCase):
    def test_no_findings(self):
        normalized = self.normalize(raw())
        self.assertEqual(normalized["findings"], [])
        self.assertEqual(normalized["summary"]["total"], 0)
        self.assertEqual(normalized["skipped"], [])

    def test_bandit_skipped(self):
        normalized = self.normalize(raw(semgrep=[semgrep_result()], bandit_status="skipped"))
        self.assertEqual(normalized["summary"]["total"], 1)
        self.assertEqual(normalized["summary"]["by_scanner"], {"bandit": 0, "semgrep": 1})

    def test_no_scanners(self):
        self.assertEqual(self.normalize({})["findings"], [])


class MixedResultTests(NormalizationTestCase):
    def test_same_issue_from_both_scanners_is_merged(self):
        normalized = self.normalize(raw(semgrep=[semgrep_result()], bandit=[bandit_result()]))
        self.assertEqual(normalized["summary"]["total"], 1)
        self.assertEqual(normalized["summary"]["duplicates_merged"], 1)
        finding = normalized["findings"][0]
        self.assertEqual(finding["scanner"], "semgrep")  # higher severity (HIGH vs MEDIUM) is primary
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(sorted(finding["scanners"]), ["bandit", "semgrep"])
        self.assertEqual(set(finding["scanner_metadata"]), {"semgrep", "bandit"})
        self.assertEqual(finding["related_rules"], ["bandit.B608.hardcoded_sql_expressions"])
        self.assertEqual(finding["confidence"], "LOW")  # taken from Bandit since Semgrep has none

    def test_higher_bandit_severity_becomes_primary(self):
        normalized = self.normalize(raw(semgrep=[semgrep_result(severity="INFO")], bandit=[bandit_result(severity="HIGH")]))
        finding = normalized["findings"][0]
        self.assertEqual((finding["scanner"], finding["severity"]), ("bandit", "HIGH"))

    def test_different_categories_or_lines_are_not_merged(self):
        data = raw(semgrep=[semgrep_result(), semgrep_result(line=3)],
                   bandit=[bandit_result("B105", line=2, cwe=259), bandit_result("B101", line=2, cwe=703)])
        normalized = self.normalize(data)
        self.assertEqual(normalized["summary"]["total"], 4)
        self.assertEqual(normalized["summary"]["duplicates_merged"], 0)

    def test_other_findings_are_not_merged_across_rules(self):
        data = raw(bandit=[bandit_result("B101", line=1, cwe=703), bandit_result("B404", line=1, cwe=78)])
        self.assertEqual(self.normalize(data)["summary"]["total"], 2)

    def test_exact_repeat_from_same_scanner_is_dropped(self):
        normalized = self.normalize(raw(bandit=[bandit_result(), bandit_result()]))
        self.assertEqual(normalized["summary"]["total"], 1)
        self.assertEqual(normalized["summary"]["duplicates_merged"], 1)

    def test_mixed_multi_file_results(self):
        data = raw(
            semgrep=[semgrep_result(),
                     semgrep_result("vg.js.xss.inner-html", path="sub\\web.js", line=1, severity="WARNING",
                                    metadata={"category": "xss", "cwe": "CWE-79"}),
                     semgrep_result("vg.generic.hardcoded-secret", line=3, metadata={"category": "hardcoded-secret"})],
            bandit=[bandit_result(), bandit_result("B105", line=3, severity="LOW", cwe=259),
                    bandit_result("B101", line=1, severity="LOW", cwe=703)],
        )
        normalized = self.normalize(data)
        findings = normalized["findings"]
        self.assertEqual([f["id"] for f in findings], ["VG-001", "VG-002", "VG-003", "VG-004"])
        self.assertEqual([(f["category"], f["file"], f["line"]) for f in findings], [
            ("sql-injection", "app.py", 2), ("hardcoded-secret", "app.py", 3),
            ("xss", "sub/web.js", 1), ("other", "app.py", 1)])
        self.assertEqual(normalized["summary"]["duplicates_merged"], 2)
        self.assertEqual(normalized["summary"]["by_scanner"], {"bandit": 3, "semgrep": 3})


if __name__ == "__main__":
    unittest.main()

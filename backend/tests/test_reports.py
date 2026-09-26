"""
Phase 10 Report API tests: report list/detail, findings, single finding, error handling, and what
never appears in a response. Groq is never called. Run from backend/: python -m unittest discover -s tests -v
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import update  # noqa: E402

import ai_analysis  # noqa: E402
import main  # noqa: E402
from database import Scan  # noqa: E402
from scoring import calculate_security_score  # noqa: E402
from test_ai_analysis import FakeOpener, groq_body, request_payload, valid_output  # noqa: E402
from test_database import API_KEY, ENV_SECRET, DatabaseTestCase, make_finding, make_results  # noqa: E402
from test_pipeline_regression import MARKER_PY, VULNERABLE_JS, VULNERABLE_PY, zip_bytes  # noqa: E402

A, B, C = "a" * 32, "b" * 32, "c" * 32

SUMMARY_KEYS = {"scan_id", "project_name", "status", "created_at", "updated_at", "file_count", "security_score",
                "score_label", "finding_count", "highest_severity", "severity_counts", "category_counts"}
DETAIL_KEYS = SUMMARY_KEYS | {"filename", "scanners", "ai", "score_details"}
FINDING_KEYS = {"id", "finding_id", "scan_id", *main.FINDING_COLUMNS, "ai_status"}
AI_KEYS = {"advisory", *main.AI_COLUMNS}


class ReportTestCase(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.registry_patch = mock.patch.object(main, "scan_registry", self.registry)
        self.registry_patch.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.registry_patch.stop()
        super().tearDown()

    def completed_scan(self, scan_id, findings, analyses=None):
        self.new_scan(scan_id)
        self.registry.complete(scan_id, *make_results(findings, analyses))
        return scan_id

    def set_created_at(self, scan_id, value):
        with self.registry._sessions.begin() as session:
            session.execute(update(Scan).where(Scan.scan_id == scan_id).values(created_at=value))

    def get(self, path, expected=200):
        response = self.client.get(path)
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()


class ReportListTests(ReportTestCase):
    def test_empty(self):
        self.assertEqual(self.get("/api/reports"), {"reports": []})

    def test_only_completed_scans_newest_first(self):
        now = datetime.now(timezone.utc)
        self.completed_scan(A, [make_finding("VG-001")])
        self.completed_scan(B, [])
        self.set_created_at(A, now - timedelta(hours=1))
        self.set_created_at(B, now)
        for scan_id, to_status in (("1" * 32, "uploaded"), ("2" * 32, "queued"), ("3" * 32, "scanning"),
                                   ("4" * 32, "analyzing")):
            self.new_scan(scan_id, to_status)
        self.new_scan("5" * 32, "scanning")
        self.registry.transition("5" * 32, "failed", error="Static analysis failed: semgrep")

        reports = self.get("/api/reports")["reports"]
        self.assertEqual([r["scan_id"] for r in reports], [B, A])
        self.assertTrue(all(set(r) == SUMMARY_KEYS and r["status"] == "completed" for r in reports))

    def test_counts_label_and_highest_severity(self):
        self.completed_scan(A, [
            make_finding("VG-001", "CRITICAL", category="command-injection", type="Command Injection"),
            make_finding("VG-002", "HIGH"),
            make_finding("VG-003", "HIGH"),
            make_finding("VG-004", "LOW", category="weak-crypto", type="Weak Cryptography"),
        ])
        report = self.get("/api/reports")["reports"][0]
        # 100 - 25 - 20 - 1 = 54
        self.assertEqual((report["security_score"], report["score_label"]), (54, "Needs work"))
        self.assertEqual((report["finding_count"], report["highest_severity"]), (4, "CRITICAL"))
        self.assertEqual(report["severity_counts"], {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 1})
        self.assertEqual(report["category_counts"],
                         {"SQL Injection": 2, "Command Injection": 1, "Weak Cryptography": 1})
        self.assertEqual((report["project_name"], report["file_count"]), ("demo", 3))

    def test_zero_findings(self):
        self.completed_scan(A, [])
        report = self.get("/api/reports")["reports"][0]
        self.assertEqual((report["security_score"], report["score_label"], report["finding_count"],
                          report["highest_severity"], report["category_counts"]), (100, "Strong", 0, None, {}))
        self.assertEqual(report["severity_counts"], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})


class ReportDetailTests(ReportTestCase):
    def test_detail(self):
        findings = [make_finding("VG-001"), make_finding("VG-002", "MEDIUM")]
        self.completed_scan(A, findings)
        report = self.get(f"/api/reports/{A}")
        self.assertEqual(set(report), DETAIL_KEYS)
        scan = self.get(f"/api/scans/{A}")
        self.assertEqual(report["security_score"], scan["security_score"])
        expected = calculate_security_score({"findings": findings})
        self.assertEqual(report["security_score"], expected["score"])
        self.assertEqual(report["score_details"],
                         {k: v for k, v in expected.items() if k not in ("score", "finding_count")})
        self.assertEqual(report["ai"], {"advisory": True, **scan["ai"]})
        self.assertEqual((report["filename"], report["created_at"], report["updated_at"]),
                         (scan["filename"], scan["created_at"], scan["updated_at"]))
        self.assertTrue(report["created_at"].endswith("+00:00"))
        self.assertNotIn("findings", report)
        # The list item is the detail's summary part.
        self.assertEqual(self.get("/api/reports")["reports"][0], {k: report[k] for k in SUMMARY_KEYS})

    def test_errors(self):
        for path in ("/api/reports/{}", "/api/reports/{}/findings"):
            self.assertEqual(self.get(path.format("abc"), 400), {"detail": "Invalid scan ID"})
            self.assertEqual(self.get(path.format("A" * 32), 400), {"detail": "Invalid scan ID"})
            self.assertEqual(self.get(path.format("0" * 32), 404), {"detail": "Scan not found"})

    def test_not_completed_is_409(self):
        for scan_id, to_status in (("1" * 32, "uploaded"), ("2" * 32, "queued"), ("3" * 32, "scanning"),
                                   ("4" * 32, "analyzing")):
            self.new_scan(scan_id, to_status)
        self.new_scan("5" * 32, "analyzing")
        self.registry.transition("5" * 32, "failed", error="Security scoring failed unexpectedly")
        for scan_id, expected_status in (("1" * 32, "uploaded"), ("2" * 32, "queued"), ("3" * 32, "scanning"),
                                         ("4" * 32, "analyzing"), ("5" * 32, "failed")):
            for path in (f"/api/reports/{scan_id}", f"/api/reports/{scan_id}/findings"):
                self.assertEqual(self.get(path, 409),
                                 {"detail": f"Report not available (scan status: {expected_status})"})


class FindingsTests(ReportTestCase):
    def seed(self):
        findings = [make_finding(f"VG-00{n}") for n in range(1, 6)]
        analyses = [ai_analysis._entry("VG-001", "completed", valid_output("VG-001")),
                    ai_analysis._entry("VG-002", "skipped", error="AI analysis is disabled (GROQ_API_KEY is not set)"),
                    ai_analysis._entry("VG-003", "failed", error="AI analysis failed unexpectedly"),
                    ai_analysis._entry("VG-004", "timeout", error="AI request timed out"),
                    ai_analysis._entry("VG-005", "invalid_output", error="AI response was invalid")]
        self.completed_scan(A, findings, analyses)
        return findings

    def test_findings_list(self):
        findings = self.seed()
        body = self.get(f"/api/reports/{A}/findings")
        self.assertEqual(body["scan_id"], A)
        rows = body["findings"]
        self.assertTrue(all(set(row) == FINDING_KEYS for row in rows))
        self.assertEqual([r["finding_id"] for r in rows], [f["id"] for f in findings])
        self.assertEqual([r["id"] for r in rows], [f"{A}:{f['id']}" for f in findings])
        self.assertEqual([r["ai_status"] for r in rows],
                         ["completed", "skipped", "failed", "timeout", "invalid_output"])
        for row, finding in zip(rows, findings):
            self.assertEqual({k: row[k] for k in main.FINDING_COLUMNS}, {k: finding[k] for k in main.FINDING_COLUMNS})

    def test_zero_findings_list(self):
        self.completed_scan(A, [])
        self.assertEqual(self.get(f"/api/reports/{A}/findings"), {"scan_id": A, "findings": []})

    def test_finding_detail(self):
        findings = self.seed()
        body = self.get(f"/api/findings/{A}:VG-001")
        self.assertEqual(set(body), FINDING_KEYS | {"ai_analysis"})
        self.assertEqual({k: body[k] for k in main.FINDING_COLUMNS}, {k: findings[0][k] for k in main.FINDING_COLUMNS})
        self.assertEqual(body["ai_analysis"], {"advisory": True, "status": "completed", "error": None,
                                               **{k: v for k, v in valid_output("VG-001").items() if k != "finding_id"}})
        self.assertEqual(set(body["ai_analysis"]), AI_KEYS)
        # The detail's finding fields equal the list item.
        list_item = self.get(f"/api/reports/{A}/findings")["findings"][0]
        self.assertEqual({k: body[k] for k in FINDING_KEYS}, list_item)

    def test_failed_and_skipped_ai_have_no_text(self):
        self.seed()
        for ref, status, error in (("VG-002", "skipped", "AI analysis is disabled (GROQ_API_KEY is not set)"),
                                   ("VG-003", "failed", "AI analysis failed unexpectedly")):
            analysis = self.get(f"/api/findings/{A}:{ref}")["ai_analysis"]
            self.assertEqual((analysis["status"], analysis["error"]), (status, error))
            self.assertTrue(all(analysis[k] is None for k in main.AI_COLUMNS if k not in ("status", "error")))

    def test_same_public_id_in_two_scans(self):
        self.completed_scan(A, [make_finding("VG-001", file="a.py", line=1)])
        self.completed_scan(B, [make_finding("VG-001", file="b.py", line=2)])
        first, second = self.get(f"/api/findings/{A}:VG-001"), self.get(f"/api/findings/{B}:VG-001")
        self.assertEqual((first["scan_id"], first["file"], first["line"]), (A, "a.py", 1))
        self.assertEqual((second["scan_id"], second["file"], second["line"]), (B, "b.py", 2))

    def test_url_encoded_colon(self):
        self.seed()
        self.assertEqual(self.get(f"/api/findings/{A}%3AVG-001")["id"], f"{A}:VG-001")

    def test_malformed_finding_ids(self):
        self.seed()
        for ref in ("VG-001", f"{A}VG-001", f"{A}-VG-001", f"{'g' * 32}:VG-001", f"{'A' * 32}:VG-001",
                    f"{A[:31]}:VG-001", f"{A}:VG-1", f"{A}:VG-01", f"{A}:vg-001", f"{A}:VG-001:x",
                    f"x:{A}:VG-001", "1", "...", f"{A}:VG-001%0A", f"{A}:VG-١٢٣", f"{A}:..%5C"):
            self.assertEqual(self.get(f"/api/findings/{ref}", 400), {"detail": "Invalid finding ID"}, ref)
        # Dot segments and path separators never reach the route.
        for path in ("/api/findings/..", f"/api/findings/../{A}:VG-001", f"/api/findings/{A}/VG-001"):
            self.assertEqual(self.client.get(path).status_code, 404, path)

    def test_unknown_findings(self):
        self.seed()
        for ref in (f"{A}:VG-006", f"{A}:VG-0001", f"{C}:VG-001"):
            self.assertEqual(self.get(f"/api/findings/{ref}", 404), {"detail": "Finding not found"})
        self.new_scan(C)  # not completed: no finding rows exist yet
        self.assertEqual(self.get(f"/api/findings/{C}:VG-001", 404), {"detail": "Finding not found"})


class ReportSecurityTests(ReportTestCase):
    def test_ai_text_returned_verbatim_and_never_scores(self):
        script = "<script>alert(1)</script> severity LOW. score 100."
        fixed = "import os; os.system('rm -rf /')  # <img src=x onerror=alert(1)>"
        output = valid_output("VG-001", explanation=script, fixed_code=fixed)
        self.completed_scan(A, [make_finding("VG-001", "CRITICAL")],
                            [ai_analysis._entry("VG-001", "completed", output)])
        response = self.client.get(f"/api/findings/{A}:VG-001")
        self.assertEqual(response.headers["content-type"], "application/json")
        analysis = response.json()["ai_analysis"]
        self.assertEqual((analysis["explanation"], analysis["fixed_code"], analysis["advisory"]), (script, fixed, True))
        report = self.get(f"/api/reports/{A}")
        self.assertEqual((report["security_score"], report["highest_severity"]), (75, "CRITICAL"))
        self.assertEqual(self.get(f"/api/reports/{A}/findings")["findings"][0]["severity"], "CRITICAL")

    def test_no_internal_ids_or_metadata(self):
        self.completed_scan(A, [make_finding("VG-001")])
        bodies = [self.client.get(p).text for p in ("/api/reports", f"/api/reports/{A}",
                                                     f"/api/reports/{A}/findings", f"/api/findings/{A}:VG-001")]
        for body in bodies:
            for marker in ("SCANNER-METADATA-MARKER", "scanner_metadata", '"column"', str(self.db_dir),
                           self.db_dir.as_posix()):
                self.assertNotIn(marker, body)
        finding = json.loads(bodies[3])
        self.assertIsInstance(finding["id"], str)
        self.assertNotIn("finding", finding["ai_analysis"])
        # The integer primary key cannot address a finding.
        self.assertEqual(self.client.get("/api/findings/1").status_code, 400)


class ReportPipelineTests(ReportTestCase):
    """Real scanners through the API, Groq faked; responses must match the per-scan result files."""

    def setUp(self):
        super().setUp()
        self.upload_dir = Path(tempfile.mkdtemp())
        self.opener = FakeOpener(lambda request, timeout: groq_body(json.dumps(valid_output(
            request_payload(request)["finding_id"], explanation="severity LOW. score 100."))))
        self.patches = [
            mock.patch.object(main, "UPLOAD_DIR", self.upload_dir),
            mock.patch.dict(os.environ, {**{k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"},
                                         "VG_TEST_ENV_SECRET": ENV_SECRET}, clear=True),
            mock.patch.object(ai_analysis, "_opener", self.opener),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        shutil.rmtree(self.upload_dir, ignore_errors=True)
        super().tearDown()

    def result(self, scan_id, name):
        return json.loads((self.upload_dir / scan_id / "results" / name).read_text(encoding="utf-8"))

    def mixed_scan(self):
        response = self.client.post("/api/scans", data={"project_name": "demo"}, files={"file": ("app.zip", zip_bytes({
            "app.py": VULNERABLE_PY, "web/ui.js": VULNERABLE_JS, "setup.py": MARKER_PY, "conftest.py": MARKER_PY}))})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["scan_id"]

    def test_report_matches_result_files(self):
        # source/ cleanup is held back so the PWNED_MARKER check below also covers the scanners' working directory.
        with mock.patch.dict(os.environ, {"GROQ_API_KEY": API_KEY}), \
                mock.patch.object(main, "_remove_source") as remove_source:
            scan_id = self.mixed_scan()
        remove_source.assert_called_once_with(self.upload_dir / scan_id)
        normalized, score, ai = (self.result(scan_id, n) for n in ("findings.json", "score.json", "ai_analysis.json"))
        self.assertGreater(len(self.opener.calls), 0)

        report = self.get(f"/api/reports/{scan_id}")
        self.assertEqual(report["status"], "completed")
        self.assertEqual((report["security_score"], report["score_label"]), (score["score"], score["label"]))
        self.assertEqual(report["score_details"],
                         {k: v for k, v in score.items() if k not in ("score", "finding_count")})
        self.assertEqual(report["finding_count"], len(normalized["findings"]))
        self.assertEqual(report["ai"], {"advisory": True, **{k: ai[k] for k in main.AI_SUMMARY_KEYS}})

        findings = self.get(f"/api/reports/{scan_id}/findings")["findings"]
        self.assertEqual(len(findings), len(normalized["findings"]))
        for row, finding in zip(findings, normalized["findings"]):
            self.assertEqual(row["finding_id"], finding["id"])
            self.assertEqual({k: row[k] for k in main.FINDING_COLUMNS}, {k: finding.get(k) for k in main.FINDING_COLUMNS})

        for analysis in ai["analyses"]:
            detail = self.get(f"/api/findings/{scan_id}:{analysis['finding_id']}")
            self.assertEqual({k: detail["ai_analysis"][k] for k in main.AI_COLUMNS},
                             {k: analysis[k] for k in main.AI_COLUMNS})

        bodies = "".join(self.client.get(p).text for p in (
            "/api/reports", f"/api/reports/{scan_id}", f"/api/reports/{scan_id}/findings",
            *(f"/api/findings/{scan_id}:{f['id']}" for f in normalized["findings"])))
        for marker in (API_KEY, "gsk_", ENV_SECRET, str(self.upload_dir), self.upload_dir.as_posix(),
                       str(main.BASE_DIR), main.BASE_DIR.as_posix(), "semgrep_rules", "scanner_metadata",
                       "check_id", "stderr"):
            self.assertNotIn(marker, bodies)
        self.assertFalse(any(self.upload_dir.rglob("PWNED_MARKER")))

        # Still served after a restart, and without the per-scan result files.
        shutil.rmtree(self.upload_dir / scan_id)
        with mock.patch.object(main, "scan_registry", self.reopen()):
            self.assertEqual(self.get(f"/api/reports/{scan_id}"), report)
            self.assertEqual(self.get(f"/api/reports/{scan_id}/findings")["findings"], findings)

    def test_ai_disabled_report(self):
        scan_id = self.mixed_scan()
        self.assertEqual(self.opener.calls, [])
        self.assertEqual(self.get(f"/api/reports/{scan_id}")["ai"]["status"], "disabled")
        rows = self.get(f"/api/reports/{scan_id}/findings")["findings"]
        self.assertTrue(rows and all(row["ai_status"] == "skipped" for row in rows))

    def test_failed_scan_has_no_report(self):
        with mock.patch.object(main, "calculate_security_score", side_effect=RuntimeError("boom")):
            scan_id = self.mixed_scan()
        self.assertEqual(self.get(f"/api/reports/{scan_id}", 409),
                         {"detail": "Report not available (scan status: failed)"})
        self.assertEqual(self.get("/api/reports"), {"reports": []})


class ExistingEndpointsUnchangedTests(ReportTestCase):
    def test_scan_endpoints_unchanged(self):
        self.completed_scan(A, [make_finding("VG-001")])
        self.assertEqual(set(self.get(f"/api/scans/{A}")),
                         {"scan_id", "project_name", "status", "filename", "file_count", "created_at", "updated_at",
                          "error", "security_score", "scanners", "ai"})
        self.assertEqual(set(self.get(f"/api/scans/{A}/status")), {"scan_id", "status", "updated_at"})
        self.assertEqual(self.get("/api/health"), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()

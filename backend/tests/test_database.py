"""
Phase 9 database tests: schema, lifecycle persistence, transactional results, rollback, cascade,
and what never enters the database. Run from backend/: python -m unittest discover -s tests -v
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import delete, func, inspect, select  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402

import ai_analysis  # noqa: E402
import database  # noqa: E402
import main  # noqa: E402
from database import AIAnalysis, Finding, Scan  # noqa: E402
from scoring import calculate_security_score  # noqa: E402
from test_ai_analysis import FakeOpener, groq_body, request_payload, valid_output  # noqa: E402
from test_pipeline_regression import MARKER_PY, VULNERABLE_JS, VULNERABLE_PY, zip_bytes  # noqa: E402

API_KEY = "gsk_DATABASETESTKEY0123456789"
ENV_SECRET = "env-secret-value-4f1c9a"


def make_finding(finding_id, severity="HIGH", **overrides):
    finding = {
        "id": finding_id, "type": "SQL Injection", "category": "sql-injection", "severity": severity,
        "file": "app.py", "line": 4, "end_line": 4, "column": 5, "code": "cur.execute(q % name)",
        "rule": "vg.python.sqli", "scanner": "semgrep", "message": "SQL built from input", "cwe": "CWE-89",
        "confidence": "HIGH", "scanners": ["semgrep"],
        "scanner_metadata": {"semgrep": {"severity": "ERROR", "marker": "SCANNER-METADATA-MARKER"}},
        "related_rules": [],
    }
    return finding | overrides


def make_results(findings, analyses=None):
    normalized = {"findings": findings, "summary": {}, "skipped": []}
    if analyses is None:
        analyses = [ai_analysis._entry(f["id"], "completed", valid_output(f["id"])) for f in findings]
    ai = ai_analysis._result("test-model", analyses)
    return normalized, calculate_security_score(normalized), ai


class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        self.db_dir = Path(tempfile.mkdtemp())
        self.url = f"sqlite:///{(self.db_dir / 'test.db').as_posix()}"
        self.registry = main.ScanRegistry(self.url)
        self.registry.init()
        self.extra_registries = []

    def tearDown(self):
        for registry in [self.registry, *self.extra_registries]:
            registry.close()
        shutil.rmtree(self.db_dir, ignore_errors=True)

    def reopen(self):
        """A fresh engine on the same database file, as after a server restart."""
        registry = main.ScanRegistry(self.url)
        registry.init()
        self.extra_registries.append(registry)
        return registry

    def session(self):
        return self.registry._sessions()

    def count(self, model):
        with self.session() as session:
            return session.scalar(select(func.count()).select_from(model))

    def new_scan(self, scan_id="a" * 32, to_status="analyzing"):
        self.registry.create(scan_id, "demo", "app.zip", 3)
        path = ["queued", "scanning", "analyzing", "completed"]
        for status in path[:path.index(to_status) + 1] if to_status in path else []:
            self.registry.transition(scan_id, status)
        return scan_id


class SchemaTests(DatabaseTestCase):
    def test_tables_and_columns(self):
        inspector = inspect(self.registry.engine)
        self.assertEqual(set(inspector.get_table_names()), {"scans", "findings", "ai_analyses"})
        finding_columns = {c["name"] for c in inspector.get_columns("findings")}
        self.assertTrue({"id", "finding_id", "scan_id", "type", "severity", "file", "line", "code", "scanner",
                         "rule", "message"} <= finding_columns)
        self.assertNotIn("scanner_metadata", finding_columns)
        self.assertTrue({"scan_id", "project_name", "created_at", "updated_at", "status", "security_score"}
                        <= {c["name"] for c in inspector.get_columns("scans")})
        self.assertTrue({"finding_id", "explanation", "impact", "recommendation", "fixed_code", "remediation_steps"}
                        <= {c["name"] for c in inspector.get_columns("ai_analyses")})
        self.assertEqual(inspector.get_pk_constraint("findings")["constrained_columns"], ["id"])
        uniques = [u["column_names"] for u in inspector.get_unique_constraints("findings")]
        self.assertIn(["scan_id", "finding_id"], uniques)

    def test_init_is_idempotent_and_keeps_data(self):
        self.new_scan()
        self.registry.init()
        self.assertEqual(self.reopen().get("a" * 32)["status"], "analyzing")

    def test_database_url_default_and_override(self):
        with mock.patch.dict(os.environ, {"DATABASE_URL": ""}):
            url = database.database_url()
        self.assertTrue(url.startswith("sqlite:///"))
        self.assertTrue(url.endswith("/backend/vibe_guard.db"))
        self.assertNotIn("uploads", url)
        with mock.patch.dict(os.environ, {"DATABASE_URL": "sqlite:///other.db"}):
            self.assertEqual(database.database_url(), "sqlite:///other.db")

    def test_foreign_keys_enforced(self):
        with self.assertRaises(IntegrityError), self.registry._sessions.begin() as session:
            session.add(Finding(scan_id="f" * 32, **{k: make_finding("VG-001").get(k) for k in main.FINDING_COLUMNS},
                                finding_id="VG-001"))

    def test_finding_id_unique_per_scan_only(self):
        for scan_id in ("a" * 32, "b" * 32):
            self.new_scan(scan_id)
            self.registry.complete(scan_id, *make_results([make_finding("VG-001")]))
        self.assertEqual(self.count(Finding), 2)
        with self.assertRaises(IntegrityError), self.registry._sessions.begin() as session:
            session.add(Finding(scan_id="a" * 32, finding_id="VG-001",
                                **{k: make_finding("VG-001").get(k) for k in main.FINDING_COLUMNS}))

    def test_cascade_delete(self):
        self.new_scan()
        self.registry.complete("a" * 32, *make_results([make_finding("VG-001"), make_finding("VG-002")]))
        self.new_scan("b" * 32)
        self.registry.complete("b" * 32, *make_results([make_finding("VG-001")]))
        self.assertEqual((self.count(Finding), self.count(AIAnalysis)), (3, 3))
        # Database-level ON DELETE CASCADE (Core delete, no ORM relationship involved)
        with self.registry._sessions.begin() as session:
            session.execute(delete(Scan).where(Scan.scan_id == "a" * 32))
        self.assertEqual((self.count(Finding), self.count(AIAnalysis)), (1, 1))
        # ORM delete cascades too
        with self.registry._sessions.begin() as session:
            session.delete(session.get(Scan, "b" * 32))
        self.assertEqual((self.count(Scan), self.count(Finding), self.count(AIAnalysis)), (0, 0, 0))


class LifecycleTests(DatabaseTestCase):
    def test_create_get_list_survive_restart(self):
        first = self.registry.create("a" * 32, "first", "a.py", 1)
        self.registry.create("b" * 32, "second", "b.zip", 7)
        registry = self.reopen()
        self.assertEqual(registry.get("a" * 32), first)
        self.assertEqual(first["status"], "uploaded")
        self.assertTrue(first["created_at"].endswith("+00:00"))
        self.assertEqual((first["security_score"], first["scanners"], first["ai"], first["error"]),
                         (None, None, None, None))
        self.assertEqual([s["scan_id"] for s in registry.list()], ["b" * 32, "a" * 32])
        self.assertIsNone(registry.get("c" * 32))

    def test_transitions_persist(self):
        self.registry.create("a" * 32, "demo", "a.py", 1)
        before = self.registry.get("a" * 32)["updated_at"]
        for status in ("queued", "scanning", "analyzing"):
            self.assertEqual(self.registry.transition("a" * 32, status)["status"], status)
            self.assertEqual(self.reopen().get("a" * 32)["status"], status)
        self.assertGreaterEqual(self.registry.get("a" * 32)["updated_at"], before)
        failed = self.registry.transition("a" * 32, "failed", error="Static analysis failed: semgrep")
        self.assertEqual((failed["status"], failed["error"]), ("failed", "Static analysis failed: semgrep"))
        self.assertEqual(self.reopen().get("a" * 32)["error"], "Static analysis failed: semgrep")

    def test_invalid_transitions_rejected(self):
        self.registry.create("a" * 32, "demo", "a.py", 1)
        for status in ("scanning", "completed", "uploaded", "bogus"):
            with self.assertRaises(main.InvalidScanTransition):
                self.registry.transition("a" * 32, status)
        self.assertEqual(self.registry.get("a" * 32)["status"], "uploaded")
        self.registry.transition("a" * 32, "failed", error="x")
        for status in main.SCAN_STATUSES:
            with self.assertRaises(main.InvalidScanTransition):
                self.registry.transition("a" * 32, status)
        with self.assertRaises(KeyError):
            self.registry.transition("c" * 32, "queued")
        with self.assertRaises(KeyError):
            self.registry.set_scanners("c" * 32, {})

    def test_concurrent_transitions_only_one_wins(self):
        self.registry.create("a" * 32, "demo", "a.py", 1)
        barrier = threading.Barrier(8)
        outcomes = []

        def worker():
            barrier.wait()
            try:
                self.registry.transition("a" * 32, "queued")
                outcomes.append("ok")
            except main.InvalidScanTransition:
                outcomes.append("rejected")

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["ok"] + ["rejected"] * 7)
        self.assertEqual(self.registry.get("a" * 32)["status"], "queued")

    def test_scanner_summary_persisted(self):
        self.new_scan(to_status="scanning")
        summary = {"semgrep": {"scanner": "semgrep", "status": "completed", "finding_count": 2}}
        self.registry.set_scanners("a" * 32, summary)
        self.assertEqual(self.reopen().get("a" * 32)["scanners"], summary)


class CompleteTests(DatabaseTestCase):
    def test_complete_stores_findings_score_and_ai(self):
        findings = [make_finding("VG-001"), make_finding("VG-002", severity="LOW", code=None, cwe=None)]
        analyses = [ai_analysis._entry("VG-001", "completed", valid_output("VG-001")),
                    ai_analysis._entry("VG-002", "timeout", error="AI request timed out")]
        normalized, score, ai = make_results(findings, analyses)
        self.new_scan()
        record = self.registry.complete("a" * 32, normalized, score, ai)
        self.assertEqual((record["status"], record["security_score"]), ("completed", score["score"]))
        self.assertEqual(record["ai"], {"status": "partial", "provider": "groq", "model": "test-model",
                                        "analyzed": 1, "failed": 1, "skipped": 0})

        with self.session() as session:
            rows = session.scalars(select(Finding).order_by(Finding.id)).all()
            self.assertEqual([r.finding_id for r in rows], ["VG-001", "VG-002"])
            for row, finding in zip(rows, findings):
                self.assertEqual({k: getattr(row, k) for k in main.FINDING_COLUMNS},
                                 {k: finding[k] for k in main.FINDING_COLUMNS})
            first, second = rows[0].ai_analysis, rows[1].ai_analysis
            expected = valid_output("VG-001")
            self.assertEqual({k: getattr(first, k) for k in main.AI_COLUMNS if k not in ("status", "error")},
                             {k: expected[k] for k in main.AI_COLUMNS if k not in ("status", "error")})
            self.assertEqual((first.status, first.error), ("completed", None))
            self.assertEqual((second.status, second.explanation, second.remediation_steps, second.error),
                             ("timeout", None, None, "AI request timed out"))

    def test_zero_findings(self):
        self.new_scan()
        record = self.registry.complete("a" * 32, *make_results([]))
        self.assertEqual((record["status"], record["security_score"]), ("completed", 100))
        self.assertEqual(self.count(Finding), 0)

    def assert_nothing_persisted(self, status="analyzing"):
        scan = self.registry.get("a" * 32)
        self.assertEqual((scan["status"], scan["security_score"], scan["ai"]), (status, None, None))
        self.assertEqual((self.count(Finding), self.count(AIAnalysis)), (0, 0))

    def test_rollback_on_unknown_ai_finding(self):
        self.new_scan()
        normalized, score, ai = make_results([make_finding("VG-001")])
        ai["analyses"].append(ai_analysis._entry("VG-999", "failed", error="x"))
        with self.assertRaises(KeyError):
            self.registry.complete("a" * 32, normalized, score, ai)
        self.assert_nothing_persisted()

    def test_rollback_after_rows_flushed(self):
        # The failure happens after findings and AI rows were written inside the transaction.
        self.new_scan()
        real_advance = main.ScanRegistry._advance
        flushed = []

        def failing_advance(session, scan_id, new_status, **values):
            flushed.append(session.scalar(select(func.count()).select_from(Finding)))
            raise RuntimeError("simulated database failure")

        with mock.patch.object(main.ScanRegistry, "_advance", staticmethod(failing_advance)):
            with self.assertRaises(RuntimeError):
                self.registry.complete("a" * 32, *make_results([make_finding("VG-001"), make_finding("VG-002")]))
        self.assertEqual(flushed, [2])
        self.assertIs(main.ScanRegistry._advance, real_advance)
        self.assert_nothing_persisted()

    def test_rollback_on_duplicate_finding_ids(self):
        self.new_scan()
        with self.assertRaises(IntegrityError):
            self.registry.complete("a" * 32, *make_results([make_finding("VG-001"), make_finding("VG-001")]))
        self.assert_nothing_persisted()

    def test_complete_requires_analyzing(self):
        self.new_scan(to_status="scanning")
        with self.assertRaises(main.InvalidScanTransition):
            self.registry.complete("a" * 32, *make_results([make_finding("VG-001")]))
        self.assert_nothing_persisted(status="scanning")


class PipelinePersistenceTests(DatabaseTestCase):
    """Full pipeline with the real scanners; Groq is always faked."""

    def setUp(self):
        super().setUp()
        self.upload_dir = Path(tempfile.mkdtemp())
        self.patches = [
            mock.patch.object(main, "UPLOAD_DIR", self.upload_dir),
            mock.patch.object(main, "scan_registry", self.registry),
            mock.patch.dict(os.environ, {**{k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"},
                                         "VG_TEST_ENV_SECRET": ENV_SECRET}, clear=True),
        ]
        self.opener = FakeOpener()
        self.patches.append(mock.patch.object(ai_analysis, "_opener", self.opener))
        for patch in self.patches:
            patch.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        shutil.rmtree(self.upload_dir, ignore_errors=True)
        super().tearDown()

    def create_scan(self, filename, content):
        response = self.client.post("/api/scans", data={"project_name": "demo"}, files={"file": (filename, content)})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["scan_id"]

    def result(self, scan_id, name):
        return json.loads((self.upload_dir / scan_id / "results" / name).read_text(encoding="utf-8"))

    def mixed_scan(self):
        return self.create_scan("app.zip", zip_bytes({
            "app.py": VULNERABLE_PY, "web/ui.js": VULNERABLE_JS, "setup.py": MARKER_PY, "conftest.py": MARKER_PY}))

    def db_dump(self) -> str:
        """Every stored value, plus the raw database file bytes."""
        with self.session() as session:
            rows = [{c.key: getattr(obj, c.key) for c in inspect(obj).mapper.column_attrs}
                    for model in (Scan, Finding, AIAnalysis) for obj in session.scalars(select(model))]
        self.registry.engine.dispose()
        raw = (self.db_dir / "test.db").read_bytes().decode("utf-8", errors="replace")
        return json.dumps(rows, default=str) + raw

    def test_completed_scan_matches_result_files(self):
        self.opener.handler = lambda request, timeout: groq_body(json.dumps(valid_output(
            request_payload(request)["finding_id"], explanation="severity LOW. score 100.")))
        with mock.patch.dict(os.environ, {"GROQ_API_KEY": API_KEY}):
            scan_id = self.mixed_scan()
        normalized, score, ai = (self.result(scan_id, n) for n in ("findings.json", "score.json", "ai_analysis.json"))

        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual((scan["status"], scan["error"]), ("completed", None))
        self.assertEqual(scan["security_score"], score["score"])
        self.assertEqual(score, calculate_security_score(normalized))  # AI did not affect the score
        self.assertEqual(scan["ai"], {k: ai[k] for k in main.AI_SUMMARY_KEYS})
        self.assertEqual(set(scan["scanners"]), {"semgrep", "bandit"})
        self.assertEqual(self.reopen().get(scan_id), scan)  # persisted, readable after a restart

        with self.session() as session:
            rows = session.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)).all()
            self.assertEqual([r.finding_id for r in rows], [f["id"] for f in normalized["findings"]])
            for row, finding in zip(rows, normalized["findings"]):
                self.assertEqual({k: getattr(row, k) for k in main.FINDING_COLUMNS},
                                 {k: finding.get(k) for k in main.FINDING_COLUMNS})
            by_id = {a["finding_id"]: a for a in ai["analyses"]}
            for row in rows:
                self.assertEqual({k: getattr(row.ai_analysis, k) for k in main.AI_COLUMNS},
                                 {k: by_id[row.finding_id][k] for k in main.AI_COLUMNS})
        self.assertFalse(any(self.upload_dir.rglob("PWNED_MARKER")))

    def test_no_secrets_paths_or_raw_scanner_data_in_database(self):
        with mock.patch.dict(os.environ, {"GROQ_API_KEY": API_KEY}):
            self.opener.handler = lambda request, timeout: groq_body(json.dumps(valid_output(
                request_payload(request)["finding_id"])))
            scan_id = self.mixed_scan()
        self.assertEqual(self.registry.get(scan_id)["status"], "completed")
        normalized = self.result(scan_id, "findings.json")
        dump = self.db_dump()
        for forbidden in (API_KEY, ENV_SECRET, "GROQ_API_KEY", str(self.upload_dir), self.upload_dir.as_posix(),
                          str(main.BASE_DIR), main.BASE_DIR.as_posix(), "semgrep_rules", "scanner_metadata",
                          "check_id", "issue_text", "requires login", "stderr"):
            self.assertNotIn(forbidden, dump)
        self.assertNotIn(json.dumps(str(self.upload_dir))[1:-1], dump)  # backslash-escaped Windows path
        for finding in normalized["findings"]:
            for meta in finding["scanner_metadata"].values():
                self.assertNotIn(json.dumps(meta, sort_keys=True), dump)

    def test_ai_disabled_rows_are_skipped(self):
        scan_id = self.mixed_scan()
        scan = self.registry.get(scan_id)
        self.assertEqual((scan["status"], scan["ai"]["status"]), ("completed", "disabled"))
        with self.session() as session:
            statuses = session.scalars(select(AIAnalysis.status)).all()
            self.assertTrue(statuses)
            self.assertEqual(set(statuses), {"skipped"})
            self.assertEqual(session.scalars(select(AIAnalysis.explanation)).all(), [None] * len(statuses))
        self.assertEqual(self.opener.calls, [])

    def test_ai_crash_still_completes_and_is_persisted(self):
        with mock.patch.object(main, "analyze_findings", side_effect=RuntimeError("boom")):
            scan_id = self.create_scan("a.py", VULNERABLE_PY.encode())
        scan = self.registry.get(scan_id)
        self.assertEqual((scan["status"], scan["error"], scan["ai"]["status"]), ("completed", None, "failed"))
        self.assertEqual(scan["security_score"], self.result(scan_id, "score.json")["score"])
        with self.session() as session:
            rows = session.scalars(select(AIAnalysis)).all()
            self.assertTrue(rows)
            self.assertTrue(all(r.status == "failed" and r.error == "AI analysis failed unexpectedly" for r in rows))

    def test_persistence_failure_rolls_back_and_fails_scan(self):
        def failing_advance(session, scan_id, new_status, **values):
            raise RuntimeError("simulated database failure")

        real_advance = main.ScanRegistry._advance

        def advance(session, scan_id, new_status, **values):
            if new_status == "completed":
                return failing_advance(session, scan_id, new_status, **values)
            return real_advance(session, scan_id, new_status, **values)

        with mock.patch.object(main.ScanRegistry, "_advance", staticmethod(advance)):
            scan_id = self.create_scan("a.py", VULNERABLE_PY.encode())
        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual((scan["status"], scan["error"]), ("failed", "Database persistence failed unexpectedly"))
        self.assertEqual((scan["security_score"], scan["ai"]), (None, None))
        self.assertIn("bandit", scan["scanners"])
        self.assertEqual((self.count(Finding), self.count(AIAnalysis)), (0, 0))
        normalized = self.result(scan_id, "findings.json")  # JSON artifacts unchanged by the DB failure
        self.assertTrue(normalized["findings"])
        self.assertEqual(self.result(scan_id, "score.json"), calculate_security_score(normalized))
        self.assertEqual(len(self.result(scan_id, "ai_analysis.json")["analyses"]), len(normalized["findings"]))

    def test_earlier_failures_store_no_results(self):
        cases = [
            (mock.patch("scanners._find_tool", return_value=None), "Static analysis failed"),
            (mock.patch.object(main, "normalize_findings", side_effect=ValueError("boom")),
             "Finding normalization failed unexpectedly"),
            (mock.patch.object(main, "calculate_security_score", side_effect=ValueError("boom")),
             "Security scoring failed unexpectedly"),
        ]
        for patch, error in cases:
            with patch:
                scan_id = self.create_scan("a.py", VULNERABLE_PY.encode())
            scan = self.reopen().get(scan_id)
            self.assertEqual(scan["status"], "failed")
            self.assertIn(error, scan["error"])
            self.assertIsNone(scan["security_score"])
        self.assertEqual((self.count(Finding), self.count(AIAnalysis)), (0, 0))

    def test_scan_creation_database_failure(self):
        with mock.patch.object(self.registry, "create", side_effect=RuntimeError("db down")):
            response = self.client.post("/api/scans", data={"project_name": "demo"},
                                        files={"file": ("a.py", b"x = 1\n")})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "Failed to create scan"})
        self.assertEqual(list(self.upload_dir.iterdir()), [])
        self.assertEqual(self.count(Scan), 0)

    def test_list_and_status_endpoints_read_database(self):
        first = self.create_scan("a.py", b"x = 1\n")
        second = self.create_scan("b.js", b"const a = 1;\n")
        scans = self.client.get("/api/scans").json()["scans"]
        self.assertEqual([s["scan_id"] for s in scans], [second, first])
        self.assertEqual(scans, self.reopen().list())
        status = self.client.get(f"/api/scans/{first}/status").json()
        self.assertEqual(set(status), {"scan_id", "status", "updated_at"})
        self.assertEqual(status["status"], "completed")

    def test_startup_creates_tables(self):
        fresh = main.ScanRegistry(f"sqlite:///{(self.db_dir / 'fresh.db').as_posix()}")
        self.extra_registries.append(fresh)
        with mock.patch.object(main, "scan_registry", fresh), TestClient(main.app) as client:
            self.assertEqual(client.get("/api/scans").json(), {"scans": []})
        self.assertEqual(set(inspect(fresh.engine).get_table_names()), {"scans", "findings", "ai_analyses"})


if __name__ == "__main__":
    unittest.main()

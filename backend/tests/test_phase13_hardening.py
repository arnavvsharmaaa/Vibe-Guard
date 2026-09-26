"""
Phase 13 security hardening: localhost default bind, CORS limited to what the frontend uses, removal of the
legacy upload route, removal of uploaded source once a scan has finished, and pinned runtime dependencies.
Groq is never called. Run from backend/: python -m unittest discover -s tests -v
"""

import inspect
import json
import os
import re
import runpy
import shutil
import sys
import tempfile
import unittest
from importlib import metadata
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main  # noqa: E402
from scoring import calculate_security_score  # noqa: E402
from test_phase12_hardening import AppTestCase  # noqa: E402
from test_pipeline_regression import VULNERABLE_JS, VULNERABLE_PY, zip_bytes  # noqa: E402

BACKEND = Path(main.BASE_DIR)
ALLOWED_ORIGIN = "http://localhost:5173"
OTHER_ORIGIN = "http://evil.example"
MIXED_ZIP = zip_bytes({"app.py": VULNERABLE_PY, "web/ui.js": VULNERABLE_JS})


class HostDefaultTests(unittest.TestCase):
    def run_main(self, env: dict) -> dict:
        """Runs main.py as a script with uvicorn.run replaced; returns the arguments it would have used."""
        db_dir = Path(tempfile.mkdtemp())
        try:
            env = {"DATABASE_URL": f"sqlite:///{(db_dir / 'x.db').as_posix()}", **env}
            with mock.patch.dict(os.environ, env), mock.patch("uvicorn.run") as run:
                if "HOST" not in env:
                    os.environ.pop("HOST", None)
                runpy.run_path(str(BACKEND / "main.py"), run_name="__main__")
            return run.call_args.kwargs
        finally:
            shutil.rmtree(db_dir, ignore_errors=True)

    def test_default_host_is_localhost(self):
        self.assertEqual(main.DEFAULT_HOST, "127.0.0.1")
        self.assertEqual(self.run_main({})["host"], "127.0.0.1")

    def test_host_can_still_be_set_explicitly(self):
        self.assertEqual(self.run_main({"HOST": "0.0.0.0"})["host"], "0.0.0.0")

    def test_documented_defaults_are_localhost(self):
        env_example = (BACKEND / ".env.example").read_text(encoding="utf-8")
        self.assertIn("HOST=127.0.0.1", env_example.splitlines())
        self.assertNotIn("0.0.0.0", env_example)
        self.assertNotIn("--host 0.0.0.0", (BACKEND / "README.md").read_text(encoding="utf-8"))


class CorsTests(AppTestCase):
    run_pipeline = False

    def preflight(self, origin, method):
        return self.client.options("/api/scans", headers={"Origin": origin, "Access-Control-Request-Method": method})

    def test_preflight_allows_post_from_allowed_origin_without_credentials(self):
        response = self.preflight(ALLOWED_ORIGIN, "POST")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN)
        self.assertNotIn("access-control-allow-credentials", response.headers)
        self.assertEqual(set(response.headers["access-control-allow-methods"].replace(" ", "").split(",")),
                         {"GET", "POST"})

    def test_preflight_rejects_other_methods(self):
        for method in ("DELETE", "PUT", "PATCH"):
            with self.subTest(method=method):
                response = self.preflight(ALLOWED_ORIGIN, method)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn(method, response.headers.get("access-control-allow-methods", ""))

    def test_disallowed_origin_gets_no_allow_origin(self):
        self.assertNotIn("access-control-allow-origin", self.preflight(OTHER_ORIGIN, "POST").headers)
        response = self.client.get("/api/health", headers={"Origin": OTHER_ORIGIN})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_allowed_get_returns_allow_origin_without_credentials(self):
        for path in ("/api/health", "/api/scans", "/api/reports"):
            with self.subTest(path=path):
                response = self.client.get(path, headers={"Origin": ALLOWED_ORIGIN})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN)
                self.assertNotIn("access-control-allow-credentials", response.headers)

    def test_origins_are_explicit(self):
        self.assertNotIn("*", main.origins)
        self.assertIn(ALLOWED_ORIGIN, main.origins)


class LegacyUploadRouteTests(AppTestCase):
    run_pipeline = False

    def test_legacy_upload_route_is_gone(self):
        self.assertNotIn("/api/scan/upload", {route.path for route in main.app.routes})
        self.assertNotIn("/api/scan/upload", main.UPLOAD_PATHS)
        for filename, content in (("p.zip", MIXED_ZIP), ("a.py", VULNERABLE_PY.encode())):
            with self.subTest(filename=filename):
                response = self.client.post("/api/scan/upload", files={"file": (filename, content)})
                self.assertIn(response.status_code, (404, 405))
                self.assertEqual(list(self.upload_dir.iterdir()), [])
                self.assertEqual(self.client.get("/api/scans").json()["scans"], [])

    def test_scan_creation_still_stores_uploads(self):
        scan_id = self.create_scan("p.zip", MIXED_ZIP)  # pipeline disabled: the source is kept
        self.assertEqual(sorted(p.name for p in (self.upload_dir / scan_id / "source").rglob("*") if p.is_file()),
                         ["app.py", "ui.js"])


class SourceRemovalTests(AppTestCase):
    def source_dir(self, scan_id):
        return self.upload_dir / scan_id / "source"

    def scan(self, content=MIXED_ZIP, filename="p.zip"):
        scan_id = self.create_scan(filename, content)
        return scan_id, self.client.get(f"/api/scans/{scan_id}").json()

    def test_completed_scan_removes_source_and_keeps_results(self):
        scan_id, scan = self.scan()
        self.assertEqual(scan["status"], "completed", scan)
        self.assertFalse(self.source_dir(scan_id).exists())
        results = self.upload_dir / scan_id / "results"
        for name in ("findings.json", "score.json", "ai_analysis.json", "semgrep.json", "summary.json"):
            self.assertTrue((results / name).is_file(), name)

    def test_reports_and_score_are_unchanged_by_source_removal(self):
        with mock.patch.object(main, "_remove_source"):  # reference run: source kept
            kept_id, _ = self.scan()
        removed_id, _ = self.scan()
        self.assertTrue(self.source_dir(kept_id).is_dir())
        self.assertFalse(self.source_dir(removed_id).exists())

        def public(scan_id):
            report = self.client.get(f"/api/reports/{scan_id}").json()
            findings = self.client.get(f"/api/reports/{scan_id}/findings").json()["findings"]
            details = [self.client.get(f"/api/findings/{f['id']}").json() for f in findings]
            strip = lambda d: {k: v for k, v in d.items() if k not in ("id", "scan_id", "created_at", "updated_at")}  # noqa: E731
            report = strip(report)
            for meta in report["scanners"].values():  # wall-clock timing differs between any two runs
                meta.pop("duration_s")
            return report, [strip(f) for f in findings], [strip(d) for d in details]

        kept, removed = public(kept_id), public(removed_id)
        self.assertEqual(kept, removed)
        self.assertTrue(removed[1] and all(f["code"] for f in removed[1]))  # snippets still served
        normalized = json.loads((self.upload_dir / removed_id / "results" / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual([f["code"] for f in removed[1]], [f["code"] for f in normalized["findings"]])
        self.assertEqual(removed[0]["security_score"], calculate_security_score(normalized)["score"])
        self.assertEqual(kept[0]["security_score"], removed[0]["security_score"])

    def test_source_is_still_present_while_the_pipeline_reads_it(self):
        seen = []
        real_static, real_ai = main.run_static_analysis, main.analyze_findings

        def static(source_dir, results_dir):
            seen.append(("static", Path(source_dir).is_dir()))
            return real_static(source_dir, results_dir)

        def ai(normalized, source_dir):
            seen.append(("ai", Path(source_dir).is_dir()))
            return real_ai(normalized, source_dir)

        with mock.patch.object(main, "run_static_analysis", static), mock.patch.object(main, "analyze_findings", ai):
            scan_id, scan = self.scan()
        self.assertEqual(scan["status"], "completed", scan)
        self.assertEqual(seen, [("static", True), ("ai", True)])
        self.assertFalse(self.source_dir(scan_id).exists())

    def test_failed_scans_remove_source(self):
        failing_summary = {"semgrep": {"scanner": "semgrep", "status": "failed", "error": "semgrep exited with code 2"},
                           "bandit": {"scanner": "bandit", "status": "completed"}}
        cases = {
            "scanner failure": mock.patch.object(main, "run_static_analysis", return_value=failing_summary),
            "scanner crash": mock.patch.object(main, "run_static_analysis", side_effect=RuntimeError("boom")),
            "normalization crash": mock.patch.object(main, "normalize_findings", side_effect=RuntimeError("boom")),
            "persistence crash": mock.patch.object(main.ScanRegistry, "complete", side_effect=RuntimeError("boom")),
        }
        for name, patch in cases.items():
            with self.subTest(name), patch:
                scan_id, scan = self.scan()
                self.assertEqual(scan["status"], "failed", scan)
                self.assertFalse(self.source_dir(scan_id).exists())
                self.assertTrue((self.upload_dir / scan_id).is_dir())  # only source/ is removed

    def test_ai_failure_still_completes_and_removes_source(self):
        with mock.patch.object(main, "analyze_findings", side_effect=RuntimeError("boom")):
            scan_id, scan = self.scan()
        self.assertEqual((scan["status"], scan["ai"]["status"]), ("completed", "failed"))
        self.assertFalse(self.source_dir(scan_id).exists())

    def test_unrelated_upload_directories_are_not_touched(self):
        other_scan = self.upload_dir / ("a" * 32)
        (other_scan / "source").mkdir(parents=True)
        (other_scan / "source" / "keep.py").write_text("x = 1\n", encoding="utf-8")
        (other_scan / "results").mkdir()
        loose_file = self.upload_dir / "keep.txt"
        loose_file.write_text("keep", encoding="utf-8")

        scan_id, scan = self.scan()
        self.assertEqual(scan["status"], "completed", scan)
        self.assertFalse(self.source_dir(scan_id).exists())
        self.assertTrue((other_scan / "source" / "keep.py").is_file())
        self.assertTrue((other_scan / "results").is_dir())
        self.assertTrue(loose_file.is_file())
        self.assertEqual(sorted(p.name for p in self.upload_dir.iterdir()), sorted(["a" * 32, "keep.txt", scan_id]))


class AnnotationTests(unittest.TestCase):
    def test_all_annotations_in_main_evaluate(self):
        # Python < 3.14 evaluates annotations when main is imported; 3.14 defers them. Evaluating them here makes
        # a name shadowed inside a class body (e.g. list[dict] after a list() method) fail on every version.
        functions = [obj for obj in vars(main).values() if inspect.isfunction(obj) and obj.__module__ == "main"]
        for cls in (obj for obj in vars(main).values() if inspect.isclass(obj) and obj.__module__ == "main"):
            functions += [obj for obj in vars(cls).values() if inspect.isfunction(obj)]
        self.assertIn(main.ScanRegistry.list_reports, functions)
        for function in functions:
            with self.subTest(function=function.__qualname__):
                inspect.get_annotations(function, eval_str=True)
        self.assertEqual(inspect.get_annotations(main.ScanRegistry.list_reports)["return"], list[dict])


class DependencyPinTests(unittest.TestCase):
    def test_runtime_requirements_are_pinned_to_installed_versions(self):
        lines = [line.strip() for line in (BACKEND / "requirements.txt").read_text(encoding="utf-8").splitlines()
                 if line.strip() and not line.strip().startswith("#")]
        self.assertTrue(lines)
        for line in lines:
            with self.subTest(requirement=line):
                match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.]*)", line)
                self.assertIsNotNone(match, "every runtime requirement must be pinned with ==")
                self.assertEqual(metadata.version(match.group(1)), match.group(2))


if __name__ == "__main__":
    unittest.main()

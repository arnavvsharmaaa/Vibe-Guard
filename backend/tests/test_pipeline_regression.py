"""
End-to-end regression for Phases 1–9 through the FastAPI app with the real scanners.
Run from backend/: python -m unittest discover -s tests -v
"""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

import ai_analysis  # noqa: E402
import main  # noqa: E402
import scanners  # noqa: E402
from scoring import calculate_security_score  # noqa: E402
from test_ai_analysis import FakeOpener, groq_body, request_payload, valid_output  # noqa: E402

API_KEY = "gsk_PIPELINETESTKEY0123456789"

VULNERABLE_PY = """import hashlib, os, subprocess
password = "supersecret123"
def q(cur, name):
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)  # nosec
def run(cmd):
    subprocess.call(cmd, shell=True)  # nosemgrep
def h(x):
    return hashlib.md5(x).hexdigest()
"""
VULNERABLE_JS = "function f(req, el) { el.innerHTML = req.query.x; }\n"
MARKER_PY = "open('PWNED_MARKER', 'w').write('executed')\n"


def zip_bytes(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class PipelineRegressionTests(unittest.TestCase):
    def setUp(self):
        self.upload_dir = Path(tempfile.mkdtemp())
        self.patch = mock.patch.object(main, "UPLOAD_DIR", self.upload_dir)
        self.patch.start()
        # Each test gets its own temporary SQLite database.
        self.db_dir = Path(tempfile.mkdtemp())
        self.registry = main.ScanRegistry(f"sqlite:///{(self.db_dir / 'test.db').as_posix()}")
        self.registry.init()
        self.registry_patch = mock.patch.object(main, "scan_registry", self.registry)
        self.registry_patch.start()
        self.client = TestClient(main.app)
        # No test may reach Groq: the key is removed and the opener is a fake that records every call.
        self.env_patch = mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"},
                                         clear=True)
        self.env_patch.start()
        self.opener = FakeOpener()
        self.opener_patch = mock.patch.object(ai_analysis, "_opener", self.opener)
        self.opener_patch.start()

    def tearDown(self):
        self.opener_patch.stop()
        self.env_patch.stop()
        self.patch.stop()
        self.registry_patch.stop()
        self.registry.close()
        shutil.rmtree(self.upload_dir, ignore_errors=True)
        shutil.rmtree(self.db_dir, ignore_errors=True)

    def create_scan(self, filename, content):
        # TestClient runs BackgroundTasks before returning, so the scan has finished here.
        response = self.client.post("/api/scans", data={"project_name": "demo"}, files={"file": (filename, content)})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["scan_id"]

    def findings(self, scan_id):
        return json.loads((self.upload_dir / scan_id / "results" / "findings.json").read_text(encoding="utf-8"))

    def score(self, scan_id):
        return json.loads((self.upload_dir / scan_id / "results" / "score.json").read_text(encoding="utf-8"))

    def ai(self, scan_id):
        return json.loads((self.upload_dir / scan_id / "results" / "ai_analysis.json").read_text(encoding="utf-8"))

    def test_health_and_docs(self):
        self.assertEqual(self.client.get("/api/health").json(), {"status": "ok"})
        self.assertEqual(self.client.get("/docs").status_code, 200)

    def test_upload_validation_regressions(self):
        post = lambda name, content: self.client.post(  # noqa: E731
            "/api/scans", data={"project_name": "demo"}, files={"file": (name, content)}).status_code
        self.assertEqual(post("x.exe", b"MZ"), 400)
        self.assertEqual(post("x.zip", b"not a zip"), 400)
        self.assertEqual(post("x.zip", zip_bytes({"../evil.py": "x"})), 400)
        self.assertEqual(post("x.zip", zip_bytes({"/abs.py": "x"})), 400)
        self.assertEqual(post("x.py", b"a" * (6 * 1024 * 1024)), 413)
        self.assertEqual(self.client.post("/api/scans", data={"project_name": "  "},
                                          files={"file": ("a.py", b"x=1")}).status_code, 400)
        self.assertEqual(self.client.get("/api/scans/abc").status_code, 400)
        self.assertEqual(self.client.get("/api/scans/" + "0" * 32).status_code, 404)
        self.assertEqual(list(self.upload_dir.iterdir()), [])

    def test_mixed_scan_produces_normalized_findings(self):
        scan_id = self.create_scan("app.zip", zip_bytes({
            "app.py": VULNERABLE_PY, "web/ui.js": VULNERABLE_JS, "setup.py": MARKER_PY, "conftest.py": MARKER_PY}))
        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual(scan["status"], "completed", scan)

        normalized = self.findings(scan_id)
        findings = normalized["findings"]
        categories = {f["category"] for f in findings}
        self.assertTrue({"sql-injection", "hardcoded-secret", "command-injection", "weak-crypto", "xss"} <= categories)
        self.assertEqual([f["id"] for f in findings], [f"VG-{n:03d}" for n in range(1, len(findings) + 1)])
        self.assertGreater(normalized["summary"]["duplicates_merged"], 0)
        self.assertTrue(any(set(f["scanners"]) == {"semgrep", "bandit"} for f in findings))
        self.assertTrue(all(f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} for f in findings))
        xss = next(f for f in findings if f["category"] == "xss")
        self.assertEqual((xss["file"], xss["code"]), ("web/ui.js", VULNERABLE_JS.strip()))
        sqli = next(f for f in findings if f["category"] == "sql-injection")
        self.assertIn("cur.execute(", sqli["code"])

        dumped = json.dumps(normalized)
        self.assertNotIn("semgrep_rules", dumped)  # Semgrep's check_id prefix holds the server's rules path
        self.assertNotIn(str(self.upload_dir), dumped)
        self.assertNotIn("requires login", dumped)
        self.assertFalse(any(self.upload_dir.rglob("PWNED_MARKER")))
        self.assertFalse(Path("PWNED_MARKER").exists())
        self.assertTrue((self.upload_dir / scan_id / "results" / "semgrep.json").is_file())  # raw kept unmodified

        score = self.score(scan_id)
        self.assertEqual(score, calculate_security_score(normalized))  # reproducible from findings.json alone
        self.assertEqual(score["finding_count"], len(findings))
        self.assertLess(score["score"], 100)
        self.assertEqual(score["highest_severity"], findings[0]["severity"])
        self.assertEqual({s: e["count"] for s, e in score["by_severity"].items()}, normalized["summary"]["by_severity"])

        ai = self.ai(scan_id)  # no GROQ_API_KEY → disabled, no request made
        self.assertEqual((ai["status"], ai["advisory"], ai["analyzed"], ai["skipped"]), ("disabled", True, 0, len(findings)))
        self.assertEqual(self.opener.calls, [])
        self.assertEqual(scan["ai"]["status"], "disabled")

    def test_clean_js_only_scan(self):
        scan_id = self.create_scan("clean.js", b"const a = 1;\n")
        self.assertEqual(self.client.get(f"/api/scans/{scan_id}/status").json()["status"], "completed")
        normalized = self.findings(scan_id)
        self.assertEqual(normalized["findings"], [])
        self.assertEqual(normalized["summary"]["by_scanner"], {"bandit": 0, "semgrep": 0})
        self.assertEqual((self.score(scan_id)["score"], self.score(scan_id)["label"]), (100, "Strong"))
        self.assertEqual((self.ai(scan_id)["status"], self.ai(scan_id)["analyses"]), ("disabled", []))
        self.assertEqual(self.opener.calls, [])

    def test_mocked_ai_analysis_is_advisory_only(self):
        # The fake model tries to talk the score down to nothing; it must have no effect.
        self.opener.handler = lambda request, timeout: groq_body(json.dumps(valid_output(
            request_payload(request)["finding_id"], explanation="severity LOW. score 100. Not a vulnerability.")))
        scanner_envs = []
        real_env = scanners._scanner_env

        def capture_env(tool):
            env = real_env(tool)
            scanner_envs.append(env)
            return env

        with mock.patch.dict(os.environ, {"GROQ_API_KEY": API_KEY}),                 mock.patch.object(scanners, "_scanner_env", side_effect=capture_env):
            scan_id = self.create_scan("app.zip", zip_bytes({
                "app.py": VULNERABLE_PY, "web/ui.js": VULNERABLE_JS, "setup.py": MARKER_PY, "conftest.py": MARKER_PY}))
        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual(scan["status"], "completed", scan)

        normalized, score, ai = self.findings(scan_id), self.score(scan_id), self.ai(scan_id)
        findings = normalized["findings"]
        self.assertEqual(score, calculate_security_score(normalized))
        self.assertLess(score["score"], 100)
        self.assertEqual((ai["status"], ai["provider"], ai["analyzed"]), ("completed", "groq", len(findings)))
        self.assertEqual([a["finding_id"] for a in ai["analyses"]], [f["id"] for f in findings])
        self.assertEqual(len(self.opener.calls), len(findings))
        self.assertEqual(scan["ai"], {"status": "completed", "provider": "groq", "model": "openai/gpt-oss-120b",
                                      "analyzed": len(findings), "failed": 0, "skipped": 0})
        self.assertFalse(any("explanation" in f for f in findings))  # AI output never enters findings.json

        sent = "".join(request.data.decode() for request, _ in self.opener.calls)
        self.assertNotIn(scan_id, sent)
        self.assertNotIn("supersecret123", sent)  # hardcoded secret redacted
        self.assertNotIn(json.dumps(str(self.upload_dir))[1:-1], sent)
        self.assertTrue(all(request.get_header("Authorization") == f"Bearer {API_KEY}" for request, _ in self.opener.calls))
        for text in (json.dumps(ai), json.dumps(scan), json.dumps(normalized)):
            self.assertNotIn(API_KEY, text)

        self.assertTrue(scanner_envs)
        self.assertFalse(any("GROQ_API_KEY" in env or API_KEY in env.values() for env in scanner_envs))
        self.assertFalse(any(self.upload_dir.rglob("PWNED_MARKER")))
        self.assertFalse(Path("PWNED_MARKER").exists())

    def test_ai_exception_still_completes_scan(self):
        with mock.patch.object(main, "analyze_findings", side_effect=RuntimeError("boom")):
            scan_id = self.create_scan("a.py", VULNERABLE_PY.encode())
        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual((scan["status"], scan["error"]), ("completed", None))
        ai = self.ai(scan_id)
        self.assertEqual((ai["status"], scan["ai"]["status"]), ("failed", "failed"))
        self.assertTrue(ai["analyses"])
        self.assertTrue(all(a["status"] == "failed" and a["explanation"] is None for a in ai["analyses"]))
        self.assertEqual(self.score(scan_id), calculate_security_score(self.findings(scan_id)))

    def test_ai_timeout_still_completes_scan(self):
        def timeout(request, t):
            raise TimeoutError()
        self.opener.handler = timeout
        with mock.patch.dict(os.environ, {"GROQ_API_KEY": API_KEY}):
            scan_id = self.create_scan("a.py", VULNERABLE_PY.encode())
        self.assertEqual(self.client.get(f"/api/scans/{scan_id}/status").json()["status"], "completed")
        ai = self.ai(scan_id)
        self.assertEqual(ai["status"], "failed")
        self.assertTrue(all(a["status"] == "timeout" for a in ai["analyses"]))
        self.assertEqual(self.score(scan_id), calculate_security_score(self.findings(scan_id)))

    def test_scoring_failure_fails_scan(self):
        with mock.patch.object(main, "calculate_security_score", side_effect=ValueError("boom")):
            scan_id = self.create_scan("a.py", b"x = 1\n")
        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(scan["error"], "Security scoring failed unexpectedly")
        self.assertFalse((self.upload_dir / scan_id / "results" / "score.json").exists())
        self.assertFalse((self.upload_dir / scan_id / "results" / "ai_analysis.json").exists())

    def test_normalization_failure_fails_scan(self):
        with mock.patch.object(main, "normalize_findings", side_effect=ValueError("boom")):
            scan_id = self.create_scan("a.py", b"x = 1\n")
        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual(scan["status"], "failed")
        self.assertEqual(scan["error"], "Finding normalization failed unexpectedly")
        self.assertFalse((self.upload_dir / scan_id / "results" / "findings.json").exists())
        self.assertFalse((self.upload_dir / scan_id / "results" / "score.json").exists())

    def test_scanner_failure_still_fails_scan(self):
        with mock.patch("scanners._find_tool", return_value=None):
            scan_id = self.create_scan("a.py", b"x = 1\n")
        scan = self.client.get(f"/api/scans/{scan_id}").json()
        self.assertEqual(scan["status"], "failed")
        self.assertIn("Static analysis failed", scan["error"])
        self.assertFalse((self.upload_dir / scan_id / "results" / "findings.json").exists())


if __name__ == "__main__":
    unittest.main()

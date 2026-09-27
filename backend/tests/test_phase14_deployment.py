"""
Phase 14a demo deployment: API docs off by default, CORS origins from ALLOWED_ORIGINS only, Host allowlist,
per-client scan submission limit, one active scan at a time, startup recovery of interrupted scans, conservative
Semgrep resources, and the Docker/Render files. Groq is never called.
Run from backend/: python -m unittest discover -s tests -v
"""

import os
import runpy
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import scanners  # noqa: E402
from test_phase12_hardening import AppTestCase  # noqa: E402
from test_pipeline_regression import VULNERABLE_PY  # noqa: E402

BACKEND = Path(main.BASE_DIR)
REPO = BACKEND.parent
PROD_ORIGIN = "https://vibe-guard.example"
DEV_ORIGIN = "http://localhost:5173"
CODE = VULNERABLE_PY.encode()
DEPLOY_ENV_KEYS = ("ENABLE_DOCS", "ALLOWED_ORIGINS", "ALLOWED_HOSTS", "UPLOAD_DIR", "MAX_ACTIVE_SCANS",
                   "SCAN_RATE_LIMIT", "SCAN_RATE_WINDOW_SECONDS", "TRUSTED_PROXY_HOPS", "CLIENT_IP_HEADER")


def load_main(env: dict) -> dict:
    """Executes main.py as a fresh module with the given deployment environment and returns its globals."""
    tmp = Path(tempfile.mkdtemp())
    base = {k: v for k, v in os.environ.items() if k not in DEPLOY_ENV_KEYS and k != "GROQ_API_KEY"}
    base.update(DATABASE_URL=f"sqlite:///{(tmp / 'x.db').as_posix()}", UPLOAD_DIR=str(tmp / "uploads"))
    try:
        with mock.patch.dict(os.environ, {**base, **env}, clear=True):
            module = runpy.run_path(str(BACKEND / "main.py"), run_name="vg_phase14_main")
        module["scan_registry"].close()
        return module
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class DocsTests(unittest.TestCase):
    PATHS = ("/docs", "/redoc", "/openapi.json")

    def test_docs_disabled_by_default(self):
        app = load_main({})["app"]
        client = TestClient(app)
        for path in self.PATHS:
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 404)
        self.assertEqual(client.get("/api/health").json(), {"status": "ok"})

    def test_docs_enabled_with_enable_docs(self):
        client = TestClient(load_main({"ENABLE_DOCS": "1"})["app"])
        for path in self.PATHS:
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 200)

    def test_other_values_do_not_enable_docs(self):
        for value in ("0", "true", "yes", ""):
            with self.subTest(value=value):
                self.assertEqual(TestClient(load_main({"ENABLE_DOCS": value})["app"]).get("/docs").status_code, 404)


class ProductionCorsTests(unittest.TestCase):
    def preflight(self, client, origin):
        return client.options("/api/scans", headers={"Origin": origin, "Access-Control-Request-Method": "POST"})

    def test_allowed_origins_replace_dev_defaults(self):
        module = load_main({"ALLOWED_ORIGINS": f" {PROD_ORIGIN} , "})
        self.assertEqual(module["origins"], [PROD_ORIGIN])
        client = TestClient(module["app"])
        response = self.preflight(client, PROD_ORIGIN)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("access-control-allow-origin"), PROD_ORIGIN)
        self.assertNotIn("access-control-allow-credentials", response.headers)
        for origin in (DEV_ORIGIN, "http://127.0.0.1:5173", "http://evil.example"):
            with self.subTest(origin=origin):
                self.assertNotIn("access-control-allow-origin", self.preflight(client, origin).headers)
                get = client.get("/api/health", headers={"Origin": origin})
                self.assertNotIn("access-control-allow-origin", get.headers)

    def test_dev_origins_without_allowed_origins(self):
        self.assertEqual(load_main({})["origins"], main.DEV_ORIGINS)

    def test_wildcard_is_ignored(self):
        self.assertEqual(load_main({"ALLOWED_ORIGINS": "*"})["origins"], main.DEV_ORIGINS)
        self.assertEqual(load_main({"ALLOWED_ORIGINS": f"*,{PROD_ORIGIN}"})["origins"], [PROD_ORIGIN])


class HostAllowlistTests(unittest.TestCase):
    def test_allowed_host_is_served_and_others_rejected(self):
        app = load_main({"ALLOWED_HOSTS": "api.vibe-guard.example, 127.0.0.1"})["app"]
        for host in ("api.vibe-guard.example", "127.0.0.1"):
            with self.subTest(host=host):
                response = TestClient(app, base_url=f"http://{host}").get("/api/health")
                self.assertEqual(response.status_code, 200)
        for host in ("evil.example", "localhost", "api.vibe-guard.example.evil.example"):
            with self.subTest(host=host):
                response = TestClient(app, base_url=f"http://{host}").get("/api/health")
                self.assertEqual(response.status_code, 400)

    def test_host_check_runs_before_uploads_are_read(self):
        app = load_main({"ALLOWED_HOSTS": "api.vibe-guard.example"})["app"]
        response = TestClient(app, base_url="http://evil.example").post(
            "/api/scans", data={"project_name": "p"}, files={"file": ("a.py", CODE)})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.text, "Invalid host header")

    def test_no_host_check_without_allowed_hosts(self):
        module = load_main({})
        self.assertEqual(module["allowed_hosts"], [])
        self.assertEqual(TestClient(module["app"], base_url="http://anything.example").get("/api/health").status_code,
                         200)


class ConfigDefaultsTests(unittest.TestCase):
    def test_defaults(self):
        module = load_main({})
        self.assertEqual(module["MAX_ACTIVE_SCANS"], 1)
        self.assertEqual((module["SCAN_RATE_LIMIT"], module["SCAN_RATE_WINDOW_SECONDS"]), (5, 600))
        self.assertEqual(module["TRUSTED_PROXY_HOPS"], 0)
        self.assertEqual(module["CLIENT_IP_HEADER"], "")  # off unless the deployment has a trusted edge proxy
        self.assertFalse(module["ENABLE_DOCS"])

    def test_upload_dir_from_environment(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            module = load_main({"UPLOAD_DIR": str(tmp / "data" / "uploads")})
            self.assertEqual(module["UPLOAD_DIR"], (tmp / "data" / "uploads").resolve())
            self.assertTrue(module["UPLOAD_DIR"].is_dir())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class RateLimiterUnitTests(unittest.TestCase):
    def test_sliding_window(self):
        limiter = main.ScanRateLimiter(5, 600)
        now = [1000.0]
        with mock.patch.object(main.time, "monotonic", lambda: now[0]):
            for n in range(5):  # submissions at 1000, 1001, ..., 1004
                now[0] = 1000.0 + n
                self.assertIsNone(limiter.hit("1.1.1.1"))
            now[0] = 1100.0
            self.assertEqual(limiter.hit("1.1.1.1"), 500)  # the first submission expires at 1600
            self.assertIsNone(limiter.hit("2.2.2.2"))  # other clients are counted separately
            now[0] = 1600.0
            self.assertIsNone(limiter.hit("1.1.1.1"))  # the 1000 submission has expired
            self.assertEqual(limiter.hit("1.1.1.1"), 1)  # the 1001 submission expires at 1601
            now[0] = 5000.0
            self.assertIsNone(limiter.hit("3.3.3.3"))
            self.assertEqual(set(limiter._hits), {"3.3.3.3"})  # expired clients are dropped


class SubmissionLimitTests(AppTestCase):
    run_pipeline = False

    def setUp(self):
        super().setUp()
        for patch in (mock.patch.object(main, "scan_rate_limiter", main.ScanRateLimiter(5, 600)),
                      mock.patch.object(main, "scan_slots", threading.BoundedSemaphore(1))):
            patch.start()
            self.patches.append(patch)

    def post_from(self, forwarded=None):
        headers = {"X-Forwarded-For": forwarded} if forwarded else {}
        return self.client.post("/api/scans", data={"project_name": "demo"}, files={"file": ("a.py", CODE)},
                                headers=headers)

    def test_sixth_submission_in_window_gets_429(self):
        for _ in range(5):
            self.assertEqual(self.post_from().status_code, 201)
        before = sorted(self.upload_dir.iterdir())
        response = self.post_from()
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json(), {"detail": "Too many scans submitted. Try again later."})
        self.assertTrue(1 <= int(response.headers["retry-after"]) <= 600)
        self.assertEqual(sorted(self.upload_dir.iterdir()), before)  # nothing stored
        self.assertEqual(len(self.client.get("/api/scans").json()["scans"]), 5)

    def test_rejected_uploads_count(self):
        for _ in range(5):
            self.assertEqual(self.post("a.exe", b"MZ").status_code, 400)
        self.assertEqual(self.post_from().status_code, 429)

    def test_spoofed_forwarded_for_is_ignored_by_default(self):
        for n in range(5):
            self.assertEqual(self.post_from(f"10.0.0.{n}").status_code, 201)
        self.assertEqual(self.post_from("10.0.0.99").status_code, 429)

    def test_trusted_proxy_hop_uses_rightmost_address(self):
        with mock.patch.object(main, "TRUSTED_PROXY_HOPS", 1):
            for n in range(5):
                # A client-chosen first entry does not change the address the proxy appended.
                self.assertEqual(self.post_from(f"10.0.0.{n}, 203.0.113.7").status_code, 201)
            self.assertEqual(self.post_from("10.9.9.9, 203.0.113.7").status_code, 429)
            self.assertEqual(self.post_from("203.0.113.8").status_code, 201)

    def test_client_ip_header_keys_the_limit(self):
        # Render: the proxies append rotating internal addresses to X-Forwarded-For, so its rightmost entry changes
        # per request; the edge-written CF-Connecting-IP header stays the client's address.
        def post(client_ip, rotating_hop):
            return self.client.post("/api/scans", data={"project_name": "demo"}, files={"file": ("a.py", CODE)},
                                    headers={"CF-Connecting-IP": client_ip,
                                             "X-Forwarded-For": f"10.9.9.9, {client_ip}, 10.213.0.{rotating_hop}"})

        with mock.patch.object(main, "CLIENT_IP_HEADER", "CF-Connecting-IP"), \
                mock.patch.object(main, "TRUSTED_PROXY_HOPS", 1):
            for n in range(5):
                self.assertEqual(post("203.0.113.7", n).status_code, 201)
            response = post("203.0.113.7", 99)
            self.assertEqual(response.status_code, 429)
            self.assertTrue(1 <= int(response.headers["retry-after"]) <= 600)
            self.assertEqual(post("2001:db8::7", 100).status_code, 201)  # another client: its own window

    def test_client_ip_header_fallback(self):
        def request(headers):
            return mock.Mock(client=mock.Mock(host="198.51.100.1"),
                             headers={"x-forwarded-for": "1.1.1.1, 2.2.2.2", **headers})

        with mock.patch.object(main, "CLIENT_IP_HEADER", "cf-connecting-ip"):
            self.assertEqual(main._client_ip(request({"cf-connecting-ip": " 203.0.113.7 "})), "203.0.113.7")
            self.assertEqual(main._client_ip(request({"cf-connecting-ip": "2001:DB8::7"})), "2001:db8::7")
            # missing or not an IP address: the X-Forwarded-For/socket logic decides, never the raw header value
            for headers in ({}, {"cf-connecting-ip": ""}, {"cf-connecting-ip": "evil"},
                            {"cf-connecting-ip": "1.1.1.1, 2.2.2.2"}):
                self.assertEqual(main._client_ip(request(headers)), "198.51.100.1")
                with mock.patch.object(main, "TRUSTED_PROXY_HOPS", 1):
                    self.assertEqual(main._client_ip(request(headers)), "2.2.2.2")

    def test_client_ip(self):
        request = mock.Mock(client=mock.Mock(host="198.51.100.1"), headers={"x-forwarded-for": "1.1.1.1, 2.2.2.2"})
        self.assertEqual(main._client_ip(request), "198.51.100.1")
        with mock.patch.object(main, "TRUSTED_PROXY_HOPS", 1):
            self.assertEqual(main._client_ip(request), "2.2.2.2")
        with mock.patch.object(main, "TRUSTED_PROXY_HOPS", 2):
            self.assertEqual(main._client_ip(request), "1.1.1.1")
        with mock.patch.object(main, "TRUSTED_PROXY_HOPS", 3):  # fewer entries than proxies: socket address
            self.assertEqual(main._client_ip(request), "198.51.100.1")


class ConcurrencyTests(AppTestCase):
    run_pipeline = False

    def setUp(self):
        super().setUp()
        self.slots = threading.BoundedSemaphore(1)
        self.limiter = main.ScanRateLimiter(5, 600)
        for patch in (mock.patch.object(main, "scan_slots", self.slots),
                      mock.patch.object(main, "scan_rate_limiter", self.limiter)):
            patch.start()
            self.patches.append(patch)

    def test_busy_scanner_returns_503_without_storing_or_counting(self):
        self.assertTrue(self.slots.acquire(blocking=False))  # a scan is running
        response = self.post("a.py", CODE)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["retry-after"], str(main.BUSY_RETRY_AFTER_SECONDS))
        self.assertEqual(list(self.upload_dir.iterdir()), [])
        self.assertEqual(self.client.get("/api/scans").json()["scans"], [])
        self.assertEqual(self.limiter._hits, {})  # a busy response does not use up the client's quota
        self.slots.release()
        self.assertEqual(self.post("a.py", CODE).status_code, 201)

    def test_slot_is_held_until_the_pipeline_finishes(self):
        seen = []

        def pipeline(scan_id):
            seen.append(self.slots.acquire(blocking=False))  # False: the slot is still held by this scan

        with mock.patch.object(main, "_run_scan_pipeline", pipeline):
            self.assertEqual(self.post("a.py", CODE).status_code, 201)
        self.assertEqual(seen, [False])
        self.assertTrue(self.slots.acquire(blocking=False))  # released afterwards
        self.slots.release()

    def test_slot_released_after_pipeline_error_and_rejected_uploads(self):
        def crash(scan_id):
            raise RuntimeError("boom")

        with mock.patch.object(main, "_run_scan_pipeline", crash):
            self.post("a.py", CODE)
        self.assertEqual(self.post("a.exe", b"MZ").status_code, 400)
        self.assertEqual(self.post("a.py", CODE, project=" ").status_code, 400)
        self.assertTrue(self.slots.acquire(blocking=False))
        self.slots.release()

    def test_slot_released_when_rate_limited(self):
        for _ in range(5):
            self.post("a.py", CODE)
        self.assertEqual(self.post("a.py", CODE).status_code, 429)
        self.assertTrue(self.slots.acquire(blocking=False))
        self.slots.release()


class StartupRecoveryTests(AppTestCase):
    run_pipeline = False

    def make_scan(self, status):
        scan_id = self.create_scan("a.py", CODE)  # uploaded -> queued, source kept (pipeline disabled)
        path = {"queued": [], "scanning": ["scanning"], "analyzing": ["scanning", "analyzing"],
                "failed": ["failed"]}[status]
        for step in path:
            self.registry.transition(scan_id, step)
        (self.upload_dir / scan_id / "results").mkdir()
        (self.upload_dir / scan_id / "results" / "summary.json").write_text("{}", encoding="utf-8")
        return scan_id

    def test_interrupted_scans_fail_and_sources_are_removed(self):
        scans = {status: self.make_scan(status) for status in ("queued", "scanning", "analyzing", "failed")}
        self.registry.create("b" * 32, "demo", "a.py", 1)  # still "uploaded"
        scans["uploaded"] = "b" * 32
        (self.upload_dir / scans["uploaded"] / "source").mkdir(parents=True)
        (self.upload_dir / scans["uploaded"] / "upload.zip").write_bytes(b"PK")
        other = self.upload_dir / "not-a-scan"
        (other / "source").mkdir(parents=True)

        with TestClient(main.app):  # runs the lifespan startup
            pass

        for status, scan_id in scans.items():
            with self.subTest(status=status):
                scan = self.registry.get(scan_id)
                self.assertEqual(scan["status"], "failed")
                self.assertFalse((self.upload_dir / scan_id / "source").exists())
                self.assertFalse((self.upload_dir / scan_id / "upload.zip").exists())
                if status != "uploaded":
                    self.assertTrue((self.upload_dir / scan_id / "results" / "summary.json").is_file())
                if status != "failed":
                    self.assertEqual(scan["error"], main.INTERRUPTED_ERROR)
        self.assertIsNone(self.registry.get(scans["failed"])["error"])  # already failed: unchanged
        self.assertTrue((other / "source").is_dir())  # only scan directories are touched

    def test_completed_scans_are_untouched(self):
        scan_id = self.create_scan("a.py", CODE)
        for step in ("scanning", "analyzing"):
            self.registry.transition(scan_id, step)
        self.registry.complete(scan_id, {"findings": []}, {"score": 100},
                               {"analyses": [], "status": "disabled", "provider": "groq", "model": "m",
                                "analyzed": 0, "failed": 0, "skipped": 0})
        before = self.registry.get(scan_id)
        self.assertEqual(self.registry.fail_interrupted(main.INTERRUPTED_ERROR), [])
        self.assertEqual(self.registry.get(scan_id), before)


class SemgrepResourceTests(unittest.TestCase):
    def test_semgrep_runs_with_one_job_and_a_memory_cap(self):
        calls = []

        def fake_run(name, argv, cwd, timeout, stderr_log):
            calls.append(argv)
            raise scanners.ScannerError("timeout", "stop")

        tmp = Path(tempfile.mkdtemp())
        try:
            with mock.patch.object(scanners, "_run", fake_run), \
                    mock.patch.object(scanners, "_find_tool", lambda name: "semgrep"):
                with self.assertRaises(scanners.ScannerError):
                    scanners._semgrep(tmp, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        argv = calls[0]
        self.assertEqual(argv[argv.index("--jobs") + 1], "1")
        self.assertEqual(argv[argv.index("--max-memory") + 1], str(scanners.SEMGREP_MAX_MEMORY_MB))
        self.assertGreater(scanners.SEMGREP_MAX_MEMORY_MB, 0)
        self.assertLess(argv.index("--max-memory"), argv.index("--"))  # options stay before the path separator


class DeploymentFileTests(unittest.TestCase):
    def read(self, path):
        return path.read_text(encoding="utf-8")

    def test_dockerfile(self):
        dockerfile = self.read(BACKEND / "Dockerfile")
        instructions = "\n".join(line for line in dockerfile.splitlines() if not line.lstrip().startswith("#"))
        self.assertRegex(dockerfile, r"(?m)^FROM python:3\.14-slim\s*$")  # glibc (Debian), not Alpine
        self.assertRegex(dockerfile, r"(?m)^USER app\s*$")
        self.assertIn("pip install --no-cache-dir -r requirements.txt", dockerfile)
        self.assertIn("--workers 1", dockerfile)
        self.assertIn('--port \\"$PORT\\"', dockerfile)
        self.assertIn("DATABASE_URL=sqlite:////app/data/vibe_guard.db", dockerfile)
        self.assertIn("UPLOAD_DIR=/app/data/uploads", dockerfile)
        # semgrep-core needs uname on the scanners' restricted PATH (the tool directory)
        self.assertIn("RUN ln -s /usr/bin/uname /usr/local/bin/uname", dockerfile)
        for forbidden in ("--reload", "forwarded-allow-ips", "GROQ_API_KEY", "COPY . ", "ADD "):
            self.assertNotIn(forbidden, instructions)
        copies = [line for line in dockerfile.splitlines() if line.startswith("COPY ")]
        self.assertEqual(copies, ["COPY requirements.txt .",
                                  "COPY main.py database.py scanners.py normalization.py scoring.py ai_analysis.py ./",
                                  "COPY semgrep_rules/ semgrep_rules/"])
        # USER comes after all installs, so the server never runs as root
        self.assertGreater(dockerfile.index("USER app"), dockerfile.rindex("RUN "))

    def test_dockerignore_excludes_secrets_and_local_data(self):
        entries = set(self.read(BACKEND / ".dockerignore").split())
        for entry in (".env", "*.db", "uploads/", "venv/", "tests/", "__pycache__/"):
            self.assertIn(entry, entries)

    def test_render_blueprint(self):
        render = self.read(REPO / "render.yaml")
        self.assertIn("healthCheckPath: /api/health", render)
        self.assertIn("dockerfilePath: ./backend/Dockerfile", render)
        self.assertIn("plan: free", render)
        self.assertNotRegex(render, r"(?m)^\s+disk:")  # no paid persistent disk
        self.assertNotRegex(render, r"https?://[a-z0-9-]+\.onrender\.com")  # URLs are entered in the dashboard
        for key in ("ALLOWED_ORIGINS", "ALLOWED_HOSTS", "GROQ_API_KEY", "VITE_API_URL"):
            self.assertRegex(render, rf"- key: {key}\b[^\n]*\n\s+sync: false")
        self.assertRegex(render, r"- key: CLIENT_IP_HEADER\b[^\n]*\n\s+value: CF-Connecting-IP\n")
        self.assertIn("source: /*", render)
        self.assertIn("destination: /index.html", render)
        self.assertNotRegex(render, r"gsk_[A-Za-z0-9]")

    def test_env_example_lists_new_settings_without_secrets(self):
        lines = dict(line.split("=", 1) for line in self.read(BACKEND / ".env.example").splitlines()
                     if line and not line.startswith("#"))
        for key in ("ALLOWED_HOSTS", "UPLOAD_DIR", "ENABLE_DOCS", "MAX_ACTIVE_SCANS", "SCAN_RATE_LIMIT",
                    "SCAN_RATE_WINDOW_SECONDS", "TRUSTED_PROXY_HOPS", "CLIENT_IP_HEADER"):
            self.assertIn(key, lines)
        self.assertEqual(lines["CLIENT_IP_HEADER"], "")
        self.assertEqual(lines["GROQ_API_KEY"], "")
        self.assertEqual(lines["ENABLE_DOCS"], "")

    def test_production_api_url_not_hardcoded(self):
        api = self.read(REPO / "src" / "services" / "api.js")
        self.assertNotIn("onrender.com", api)
        self.assertIn("import.meta.env.VITE_API_URL", api)


if __name__ == "__main__":
    unittest.main()

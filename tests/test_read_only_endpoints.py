"""Exercise real ASGI routes against synthetic saved files, never real targets."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient


# A tripwire works even when Paramiko/GenAI are absent from a clean environment.
# If the application imports the old annotation helper, it receives this mock.
credential_module = types.ModuleType("backend.scanner.weak_creds")
credential_attempt = Mock(side_effect=AssertionError("Credential attempt during a read"))
credential_module.annotate_services_with_weak_creds = credential_attempt
previous_credential_module = sys.modules.get("backend.scanner.weak_creds")
sys.modules["backend.scanner.weak_creds"] = credential_module
try:
    from backend import main
finally:
    if previous_credential_module is None:
        sys.modules.pop("backend.scanner.weak_creds", None)
    else:
        sys.modules["backend.scanner.weak_creds"] = previous_credential_module


SCAN_ID = "11111111-1111-4111-8111-111111111111"
XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="saved.example.test" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="Synthetic FTP" version="1.0"/></port>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="Synthetic SSH" version="1.0"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Synthetic HTTP" version="1.0"/></port>
</ports></host></nmaprun>"""


class SavedScanFixture(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix=".risklens-test-", dir=Path(__file__).resolve().parents[1]
        )))
        self.directory = directory
        self.stack.enter_context(patch.dict(os.environ, {
            "RISKLENS_ALLOWED_TARGETS": "192.0.2.0/24,127.0.0.1/32,::1/128",
        }))
        self.stack.enter_context(patch.object(main, "resolve_executable", return_value="mock-nmap.exe"))
        (directory / f"{SCAN_ID}.xml").write_text(XML, encoding="utf-8")
        (directory / f"gobuster_{SCAN_ID}.txt").write_text(
            "/docs (Status: 200) [Size: 10]\n", encoding="utf-8"
        )
        (directory / f"gobuster_{SCAN_ID}.done").write_text("done", encoding="utf-8")
        (directory / f"web_audit_{SCAN_ID}.json").write_text(json.dumps({
            "url": "http://192.0.2.10", "http": {"status": 200}, "checks": [{
                "name": "Content-Security-Policy", "status": "missing", "detail": "Saved header evidence"
            }],
        }), encoding="utf-8")
        self.stack.enter_context(patch.object(main, "SCANS_DIR", directory))
        self.stack.enter_context(patch.object(main, "SCAN_STATUS_FILE", directory / "scan_status.json"))
        self.stack.enter_context(patch.object(main, "scan_status_store", {SCAN_ID: main.ScanStatus(
            scan_id=SCAN_ID, target="192.0.2.10", status="completed", exposure="internal",
            exposure_effective="internal", gobuster_status="completed", created_at="2026-01-01T00:00:00Z",
            ports="8080", authorized_targets=["192.0.2.10"], approved_scope=["192.0.2.0/24"],
            authorized=True,
        )}))
        credential_attempt.reset_mock()
        # Start the ASGI portal before blocking sockets: Windows asyncio creates
        # an internal loopback socket pair when the event loop starts.
        self.client = self.stack.enter_context(TestClient(main.app))
        self.io_mocks = []
        for target in (
            "requests.sessions.Session.request", "socket.gethostbyaddr", "socket.getaddrinfo",
            "socket.create_connection", "socket.socket.connect", "socket.socket.connect_ex",
            "subprocess.run", "subprocess.Popen",
        ):
            self.io_mocks.append(self.stack.enter_context(patch(
                target, side_effect=AssertionError(f"Read attempted external I/O: {target}")
            )))
        # In-process ASGI requests: no listening socket or HTTP target requests.

    def assert_no_external_io(self):
        credential_attempt.assert_not_called()
        for mocked in self.io_mocks:
            mocked.assert_not_called()


class ReadOnlyEndpointsTest(SavedScanFixture):
    def test_all_get_routes_use_only_saved_data(self):
        for route in main.app.routes:
            if "GET" not in (getattr(route, "methods", None) or set()):
                continue
            path = route.path.replace("{scan_id}", SCAN_ID).replace("{new_id}", SCAN_ID).replace("{old_id}", SCAN_ID)
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)
        self.assert_no_external_io()

    def test_services_mark_unperformed_checks_and_have_local_remediation(self):
        first = self.client.get(f"/scan/{SCAN_ID}/nvd").json()
        self.assertEqual(first, self.client.get(f"/scan/{SCAN_ID}/nvd").json())
        host = first["data"]["hosts"][0]
        self.assertEqual(host["reverse_dns"], "saved.example.test")
        self.assertEqual(len(host["services"]), 3)
        for service in host["services"]:
            self.assertEqual(service["weak_creds"], {"found": False, "status": "not_tested"})
            self.assertEqual(service["nvd"]["status"], "not_queried")
            self.assertEqual(service["nvd"]["cves"], [])
            self.assertTrue(service["remediation"])
        self.assert_no_external_io()

    def test_pdf_and_csv_are_real_exports_without_probes(self):
        pdf = self.client.get(f"/scan/{SCAN_ID}/report.pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.headers["content-type"], "application/pdf")
        self.assertTrue(pdf.content.startswith(b"%PDF-"))
        csv = self.client.get(f"/scan/{SCAN_ID}/findings.csv")
        self.assertEqual(csv.status_code, 200)
        self.assertIn("evidence,remediation", csv.text)
        self.assertIn("Saved header evidence", csv.text)
        self.assert_no_external_io()

    def test_remediation_route_and_frontend_request_are_removed(self):
        self.assertEqual(self.client.post(f"/scan/{SCAN_ID}/remediation", json={}).status_code, 404)
        self.assertNotIn("/scan/{scan_id}/remediation", self.client.get("/openapi.json").json()["paths"])
        js = self.client.get("/static/app.js").text
        for token in ("loadLLMRemediation", "llm-remediation", "/remediation", "Generating remediation"):
            self.assertNotIn(token, js)
        self.assert_no_external_io()

    def test_standard_submission_does_not_schedule_web(self):
        with patch.object(main, "run_nmap_scan") as nmap, patch.object(main, "run_gobuster_scan") as web:
            response = self.client.post("/scan", json={"target": "127.0.0.1:8080", "profile": "standard", "authorized": True})
            self.assertEqual(response.status_code, 200)
            scan_id = response.json()["scan_id"]
            nmap.assert_called_once_with(scan_id, "127.0.0.1", "8080")
            web.assert_not_called()
        self.assert_no_external_io()

    def test_network_worker_still_builds_nmap_command_and_saves_xml(self):
        main.scan_status_store[SCAN_ID].gobuster_status = "skipped"
        main.scan_status_store[SCAN_ID].ports = "21,22,80"
        def fake_nmap(command, **kwargs):
            complete = XML.replace("</nmaprun>", '<runstats><finished exit="success"/></runstats></nmaprun>')
            Path(command[command.index("-oX") + 1]).write_text(complete, encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch.object(main.subprocess, "run", side_effect=fake_nmap) as runner:
            main.run_nmap_scan(SCAN_ID, "192.0.2.10", ports="21,22,80")
            command = runner.call_args.args[0]
            self.assertEqual(command[:4], ["mock-nmap.exe", "-sT", "-n", "-Pn"])
            self.assertEqual(command[-1], "192.0.2.10")
            self.assertIn("21,22,80", command)
            self.assertEqual(main.scan_status_store[SCAN_ID].status, "completed")
            self.assertEqual(main.parse_nmap_xml(self.directory / f"{SCAN_ID}.xml")["hosts"][0]["ip"], "192.0.2.10")
        self.assert_no_external_io()

    def test_web_worker_still_saves_audit_and_gobuster_output(self):
        def fake_gobuster(command, **kwargs):
            Path(command[command.index("-o") + 1]).write_text(
                "/docs (Status: 200) [Size: 10]\n", encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        main.scan_status_store[SCAN_ID].nmap_status = "completed"
        main.scan_status_store[SCAN_ID].path_discovery = True
        main.scan_status_store[SCAN_ID].web_url = "http://192.0.2.10:8080"
        audit = {"url": "http://192.0.2.10:8080", "http": {"status": 200}}
        with patch.object(main, "run_web_security_assessment", return_value=audit) as assessment:
            with patch.object(main, "execute_discovery", side_effect=lambda executable, url, words, output, stop, validate: fake_gobuster([executable, "dir", "-o", str(output)]).args) as runner:
                main.run_gobuster_scan(SCAN_ID, audit["url"])
                assessment.assert_called_once_with(audit["url"])
                self.assertEqual(runner.call_args.args[0], "mock-nmap.exe")
        saved = json.loads((self.directory / f"web_audit_{SCAN_ID}.json").read_text(encoding="utf-8"))
        self.assertEqual(saved, audit)
        self.assertEqual(main.scan_status_store[SCAN_ID].gobuster_status, "completed")
        self.assertEqual(self.client.get(f"/webscan/{SCAN_ID}/results").json()["results"][0]["path"], "/docs")
        self.assert_no_external_io()


class ImportWithoutRemovedDependenciesTest(unittest.TestCase):
    def test_startup_without_ai_or_credential_modules(self):
        # Separate interpreter prevents an already imported dependency hiding a regression.
        code = """
import importlib.abc
import sys
class BlockRemoved(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {'backend.llm_remediation', 'backend.scanner.weak_creds'} or fullname.split('.')[0] in {'google', 'paramiko'}:
            raise AssertionError('Removed runtime dependency imported: ' + fullname)
sys.meta_path.insert(0, BlockRemoved())
from backend.main import app
assert app
"""
        result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                                cwd=Path(__file__).resolve().parents[1], timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

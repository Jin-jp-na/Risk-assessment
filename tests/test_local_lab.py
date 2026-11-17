"""Real HTTP to an ephemeral 127.0.0.1 fixture; no Nmap/Gobuster or outside targets."""
from contextlib import ExitStack
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend import main
from scripts.local_lab import make_handler


class LocalLabTest(unittest.TestCase):
    def test_real_localhost_baseline_change_compare_and_export(self):
        with ExitStack() as stack:
            folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix=".risklens-lab-", dir=Path(__file__).resolve().parents[1])))
            state_file = folder / "state.json"
            state_file.write_text('{"nosniff": false}', encoding="utf-8")
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state_file))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            def stop_server():
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            stack.callback(stop_server)
            port = server.server_port
            stack.enter_context(patch.dict(os.environ, {"RISKLENS_ALLOWED_TARGETS": "127.0.0.1/32", "RISKLENS_ALLOWED_WEB_PORTS": str(port)}))
            stack.enter_context(patch.object(main, "SCANS_DIR", folder))
            stack.enter_context(patch.object(main, "SCAN_STATUS_FILE", folder / "scan_status.json"))
            stack.enter_context(patch.object(main, "scan_status_store", {}))
            stack.enter_context(patch.object(main, "resolve_executable", side_effect=AssertionError("No scanner required")))
            client = stack.enter_context(TestClient(main.app))
            def scan():
                response = client.post("/webscan", json={"url": f"http://127.0.0.1:{port}", "authorized": True})
                self.assertEqual(response.status_code, 200, response.text)
                scan_id = response.json()["scan_id"]
                snap = client.get(f"/scans/{scan_id}/snapshot")
                self.assertEqual(snap.status_code, 200)
                self.assertEqual(snap.json()["components"]["http"]["status"], "completed", snap.text)
                return scan_id
            baseline = scan()
            state_file.write_text('{"nosniff": true}', encoding="utf-8")
            current = scan()
            result = client.get(f"/scans/{current}/compare/{baseline}")
            self.assertEqual(result.status_code, 200, result.text)
            self.assertTrue(any(item["key"] == "x-content-type-options" for item in result.json()["added"]))
            old_findings = client.get(f"/webscan/{baseline}/findings").json()["findings"]
            new_findings = client.get(f"/webscan/{current}/findings").json()["findings"]
            self.assertIn("WEB-HDR-003", [item["id"] for item in old_findings])
            self.assertNotIn("WEB-HDR-003", [item["id"] for item in new_findings])
            for suffix in ("report.pdf", "findings.csv"):
                response = client.get(f"/scan/{current}/{suffix}?baseline={baseline}")
                self.assertEqual(response.status_code, 200, response.text[:100] if suffix.endswith("csv") else "PDF error")

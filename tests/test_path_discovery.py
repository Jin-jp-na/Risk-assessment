"""No scanner or target is contacted: execute real job code against mocked children."""

import json
import os
import threading
from unittest.mock import Mock, patch

import test_read_only_endpoints as fixtures
from backend import main
from backend.scanner import path_discovery as discovery
from backend.scanner.scan_policy import ConfigurationError, ScopeError
from backend.scanner.web_assessment import _header_checks
from backend.scanner.web_rules import build_web_findings


class PathDiscoveryTest(fixtures.SavedScanFixture):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch.object(main, "DISCOVERY_STOPS", {}))
        self.status = main.scan_status_store[fixtures.SCAN_ID]
        self.status.profile = "web"
        self.status.nmap_status = "completed"
        self.status.web_url = "http://192.0.2.10:8080"
        self.status.path_discovery = True
        self.status.gobuster_status = "pending"
        self.audit = {"url": self.status.web_url, "http": {"status": 200, "headers": {}},
                      "checks": [{"name": "Content-Security-Policy", "status": "missing", "detail": "Saved CSP absent"}]}
        self.assessment = self.stack.enter_context(patch.object(main, "run_web_security_assessment", return_value=self.audit))
        (self.directory / f"gobuster_{fixtures.SCAN_ID}.txt").unlink()

    def run_job(self, text="/docs (Status: 200) [Size: 10]\n", code=0):
        process = Mock()
        process.poll.return_value = code
        process.wait.return_value = code
        def launch(command, **kwargs):
            (self.directory / f"gobuster_{fixtures.SCAN_ID}.txt").write_text(text, encoding="utf-8")
            return process
        with patch.object(discovery.subprocess, "Popen", side_effect=launch) as launcher:
            main.run_gobuster_scan(fixtures.SCAN_ID, self.status.web_url)
        self.assert_no_external_io()
        return launcher, process

    def test_successful_discovery_has_exact_origin_rate_limits_and_observations(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "https://outside.example:443", "HTTP_PROXY": "http://outside.example:80"}):
            launcher, process = self.run_job()
        command = launcher.call_args.args[0]
        self.assertFalse(launcher.call_args.kwargs["shell"])
        self.assertEqual(command[command.index("-u") + 1], self.status.web_url)
        self.assertEqual(command[command.index("-t") + 1], "1")
        self.assertEqual(command[command.index("--delay") + 1], "1s")
        self.assertEqual(command[command.index("--timeout") + 1], "5s")
        for forbidden in ("-k", "-r", "--follow-redirect", "--retry", "-x", "--force", "-U", "-P"):
            self.assertNotIn(forbidden, command)
        self.assertNotIn("HTTPS_PROXY", launcher.call_args.kwargs["env"])
        self.assertEqual(self.status.gobuster_status, "completed")
        self.assertEqual(self.status.web_status, "completed")
        result = self.client.get(f"/webscan/{fixtures.SCAN_ID}/results").json()
        self.assertEqual(result["results"][0]["path"], "/docs")
        self.assertEqual(result["results"][0]["status"], 200)
        self.assertEqual(result["results"][0]["category"], "path_observation")
        self.assertNotIn("severity", result["results"][0])
        self.assertIn("not established", result["results"][0]["interpretation"])
        process.kill.assert_not_called()
        record = json.loads((self.directory / f"gobuster_{fixtures.SCAN_ID}.status").read_text())
        self.assertEqual(record["word_count"], 15)

    def test_empty_completed_output_has_no_path_observations(self):
        self.run_job(text="")
        result = self.client.get(f"/webscan/{fixtures.SCAN_ID}/results").json()
        self.assertEqual(result["results"], [])
        self.assertEqual(result["discovery_status"], "completed")
        self.assertFalse(result["partial"])
        self.assertIsNone(result["error"])

    def test_missing_gobuster_keeps_independent_web_findings(self):
        with patch.object(main, "resolve_executable", side_effect=ConfigurationError("gobuster not found")):
            main.run_gobuster_scan(fixtures.SCAN_ID, self.status.web_url)
        self.assertEqual(self.status.web_status, "completed")
        self.assertEqual(self.status.gobuster_status, "failed")
        result = self.client.get(f"/webscan/{fixtures.SCAN_ID}/results").json()
        self.assertIn("not found", result["error"])
        findings = self.client.get(f"/webscan/{fixtures.SCAN_ID}/findings").json()["findings"]
        self.assertEqual(findings[0]["rule_id"], "WEB-HDR-002")
        self.assert_no_external_io()

    def test_default_web_request_does_not_require_or_start_gobuster(self):
        self.status.path_discovery = False
        with patch.object(main, "resolve_executable", side_effect=AssertionError("Unrequested binary lookup")):
            main.run_gobuster_scan(fixtures.SCAN_ID, self.status.web_url)
        self.assertEqual(self.status.web_status, "completed")
        self.assertEqual(self.status.gobuster_status, "skipped")
        self.assertEqual(self.client.get(f"/webscan/{fixtures.SCAN_ID}/results").json()["results"], [])
        self.assert_no_external_io()

    def test_post_web_default_does_not_preflight_gobuster(self):
        def nmap(scan_id, target, ports):
            main.scan_status_store[scan_id].nmap_status = "completed"
        with patch.object(main, "run_nmap_scan", side_effect=nmap), patch.object(main, "resolve_executable", return_value="mock-nmap.exe") as resolver:
            response = self.client.post("/scan", json={"target": "http://192.0.2.10:8080", "profile": "web", "authorized": True})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["path_discovery"])
        self.assertEqual([call.args[1] for call in resolver.call_args_list], ["nmap"])
        self.assert_no_external_io()

    def test_missing_optional_binary_does_not_fail_completed_assessment_job(self):
        def nmap(scan_id, target, ports):
            main.scan_status_store[scan_id].nmap_status = "completed"
        def executable(variable, program):
            if program == "gobuster":
                raise ConfigurationError("Gobuster not installed")
            return "mock-nmap.exe"
        with patch.object(main, "run_nmap_scan", side_effect=nmap), patch.object(main, "resolve_executable", side_effect=executable):
            response = self.client.post("/scan", json={"target": self.status.web_url, "profile": "web", "authorized": True, "path_discovery": True})
        self.assertEqual(response.status_code, 200)
        scan_id = response.json()["scan_id"]
        status = self.client.get(f"/scan/{scan_id}").json()
        self.assertEqual((status["status"], status["web_status"], status["gobuster_status"]), ("completed", "completed", "failed"))
        self.assertTrue(self.client.get(f"/webscan/{scan_id}/findings").json()["findings"])
        self.assert_no_external_io()

    def test_out_of_scope_ip_port_and_scheme_are_rejected_before_any_probe(self):
        for url in ("http://192.0.3.10:8080", "http://192.0.2.11:8080", "http://192.0.2.10:80", "https://192.0.2.10:8080"):
            with self.subTest(url=url):
                main.run_gobuster_scan(fixtures.SCAN_ID, url)
                self.assertEqual(self.status.gobuster_status, "failed")
        self.assessment.assert_not_called()
        self.assert_no_external_io()

    def test_job_timeout_kills_reaps_and_preserves_web_evidence(self):
        process = Mock()
        process.poll.return_value = None
        process.kill.side_effect = lambda: setattr(process.poll, "return_value", -9)
        with patch.object(discovery.subprocess, "Popen", return_value=process), patch.object(discovery, "monotonic", side_effect=[0, 121]):
            main.run_gobuster_scan(fixtures.SCAN_ID, self.status.web_url)
        process.kill.assert_called_once()
        process.wait.assert_called_with(timeout=5)
        self.assertEqual(self.status.gobuster_status, "timed_out")
        self.assertEqual(self.status.web_status, "completed")
        self.assertEqual(self.client.get(f"/webscan/{fixtures.SCAN_ID}/assessment").json(), self.audit)
        self.assert_no_external_io()

    def test_operator_stop_kills_the_running_child(self):
        event = threading.Event()
        main.DISCOVERY_STOPS[fixtures.SCAN_ID] = event
        process = Mock()
        process.poll.return_value = None
        process.kill.side_effect = lambda: setattr(process.poll, "return_value", -9)
        def launch(*args, **kwargs):
            event.set()
            return process
        with patch.object(discovery.subprocess, "Popen", side_effect=launch):
            main.run_gobuster_scan(fixtures.SCAN_ID, self.status.web_url)
        self.assertEqual(self.status.gobuster_status, "cancelled")
        process.kill.assert_called_once()
        process.wait.assert_called_with(timeout=5)
        self.assertEqual(self.status.web_status, "completed")
        self.assert_no_external_io()

    def test_stop_endpoint_signals_only_opted_in_pending_job(self):
        event = threading.Event()
        main.DISCOVERY_STOPS[fixtures.SCAN_ID] = event
        response = self.client.post(f"/webscan/{fixtures.SCAN_ID}/stop")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(event.is_set())
        self.status.path_discovery = False
        self.assertEqual(self.client.post(f"/webscan/{fixtures.SCAN_ID}/stop").status_code, 409)
        self.assert_no_external_io()

    def test_scope_revocation_during_job_kills_child(self):
        process = Mock()
        process.poll.return_value = None
        process.kill.side_effect = lambda: setattr(process.poll, "return_value", -9)
        validator = Mock(side_effect=[None, ScopeError("Scope revoked")])
        with patch.object(discovery.subprocess, "Popen", return_value=process):
            with self.assertRaises(ScopeError):
                discovery.execute_discovery("mock-gobuster.exe", self.status.web_url, self.directory / "words", self.directory / "paths.txt", threading.Event(), validator)
        process.kill.assert_called_once()
        process.wait.assert_called_with(timeout=5)
        self.assert_no_external_io()

    def test_nonzero_exit_preserves_failure_with_partial_observations(self):
        self.run_job(code=9)
        result = self.client.get(f"/webscan/{fixtures.SCAN_ID}/results").json()
        self.assertTrue(result["partial"])
        self.assertIn("code 9", result["error"])
        self.assertEqual(len(result["results"]), 1)

    def test_unsafe_or_large_wordlists_are_rejected(self):
        source, target = self.directory / "input.txt", self.directory / "snapshot.txt"
        for content in ("https://outside.example\n", "../secret\n", "a//b\n", "a?query\n", "\n", "\n".join(f"word{n}" for n in range(33))):
            with self.subTest(content=content[:20]):
                source.write_text(content)
                with self.assertRaises(ConfigurationError):
                    discovery.prepare_wordlist(source, target)

    def test_parser_skips_noise_deduplicates_and_keeps_evidence(self):
        source = self.directory / "parser.txt"
        source.write_text("noise\n//outside.example (Status: 200)\n/docs (Status: 999)\n/docs (Status: 200) [Size: 10]\n/docs (Status: 200) [Size: 10]\n/login (Status: 302) [Size: 0] [--> https://outside.example/]\n")
        result = main.parse_gobuster_output(source)
        self.assertEqual([(row["path"], row["status"]) for row in result], [("/docs", 200), ("/login", 302)])
        self.assertIn("outside.example", result[1]["evidence"])
        self.assert_no_external_io()

    def test_every_header_and_certificate_rule_has_actionable_fields(self):
        findings = build_web_findings({"url": "https://192.0.2.10:8080", "http": {"status": 200},
            "checks": _header_checks({}, "https"), "error_category": "certificate_verification_failed",
            "error": "synthetic expired certificate", "tls": {"verification": "failed"}})
        self.assertEqual(len(findings), 7)
        self.assertEqual(len({item["rule_id"] for item in findings}), 7)
        for finding in findings:
            self.assertTrue(all(finding[key] for key in ("id", "rule_id", "evidence", "severity", "remediation", "retest")))
            self.assertIn(finding["severity"], {"info", "low"})
            self.assertEqual(finding["domain"], "web")

    def test_valid_headers_and_verified_certificate_produce_no_rule_findings(self):
        headers = {"strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'",
                   "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
                   "permissions-policy": "geolocation=()"}
        self.assertEqual(build_web_findings({"checks": _header_checks(headers, "https"), "tls": {"verification": "verified"}}), [])

    def test_web_findings_do_not_require_network_xml(self):
        (self.directory / f"{fixtures.SCAN_ID}.xml").unlink()
        response = self.client.get(f"/webscan/{fixtures.SCAN_ID}/findings")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["findings"][0]["domain"], "web")
        self.assert_no_external_io()

    def test_legacy_plain_text_warning_stays_readable(self):
        (self.directory / f"gobuster_{fixtures.SCAN_ID}.status").write_text("Saved legacy warning", encoding="utf-8")
        result = self.client.get(f"/webscan/{fixtures.SCAN_ID}/results").json()
        self.assertEqual(result["error"], "Saved legacy warning")
        self.assert_no_external_io()

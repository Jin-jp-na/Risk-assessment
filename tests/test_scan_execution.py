"""Scope and Nmap lifecycle tests. Every scanner process is mocked."""

import ipaddress
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import test_read_only_endpoints as fixtures
from backend import main
from backend.scanner import scan_policy as policy


def scan_xml(addresses, *, timedout=False):
    hosts = []
    for address in addresses:
        family = "ipv6" if ipaddress.ip_address(address).version == 6 else "ipv4"
        hosts.append(f'<host timedout="{str(timedout).lower()}"><status state="up"/>'
                     f'<address addr="{address}" addrtype="{family}"/>'
                     '<ports><port protocol="tcp" portid="80"><state state="open"/>'
                     '<service name="http"/></port>'
                     '<port protocol="tcp" portid="81"><state state="closed"/></port></ports></host>')
    return '<nmaprun>' + ''.join(hosts) + '<runstats><finished exit="success"/></runstats></nmaprun>'


class ScanExecutionTest(fixtures.SavedScanFixture):
    def submit(self, **overrides):
        body = {"target": "192.0.2.10", "profile": "quick", "authorized": True}
        body.update(overrides)
        return self.client.post("/scan", json=body)

    def fake_scan(self, command, **kwargs):
        targets = command[command.index("-oX") + 2:]
        Path(command[command.index("-oX") + 1]).write_text(scan_xml(targets), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def test_quick_and_standard_parameters_and_artifacts(self):
        for profile, count, timeout in (("quick", "100", 120), ("standard", "1000", 300)):
            with self.subTest(profile=profile), patch.object(main.subprocess, "run", side_effect=self.fake_scan) as runner:
                response = self.submit(profile=profile)
                self.assertEqual(response.status_code, 200, response.text)
                scan_id = response.json()["scan_id"]
                result = self.client.get(f"/scan/{scan_id}").json()
                self.assertEqual(result["status"], "completed", result)
                self.assertEqual(result["gobuster_status"], "skipped")
                self.assertEqual(result["nmap_exit_code"], 0)
                command = runner.call_args.args[0]
                for forbidden in ("--script", "-sC", "-A", "-O", "--osscan-guess"):
                    self.assertNotIn(forbidden, command)
                self.assertEqual("-sV" in command, profile == "standard")
                self.assertEqual(command[command.index("--top-ports") + 1], count)
                self.assertEqual(runner.call_args.kwargs["timeout"], timeout)
                self.assertFalse(runner.call_args.kwargs["shell"])
                self.assertEqual(runner.call_count, 1)
                saved = self.directory / f"{scan_id}.xml"
                self.assertTrue(saved.is_file())
                self.assertFalse(saved.with_suffix(".xml.tmp").exists())
                record = json.loads((self.directory / f"nmap_{scan_id}.json").read_text())
                self.assertEqual(record["xml"], saved.name)
                self.assertEqual(record["exit_code"], 0)
                services = self.client.get(f"/scan/{scan_id}/parsed").json()["data"]["hosts"][0]["services"]
                self.assertEqual([(s["port"], s["state"]) for s in services], [(80, "open"), (81, "closed")])
                annotated = self.client.get(f"/scan/{scan_id}/nvd").json()["data"]["hosts"][0]["services"]
                self.assertEqual(annotated[1]["pcvp_score"], 0)
        self.assert_no_external_io()

    def test_cidr_uses_same_profile_without_discovery_or_nse(self):
        with patch.object(main.subprocess, "run", side_effect=self.fake_scan) as runner:
            response = self.submit(target="192.0.2.0/30")
            self.assertEqual(response.status_code, 200, response.text)
            scan_id = response.json()["scan_id"]
            result = self.client.get(f"/scan/{scan_id}").json()
            self.assertEqual(result["authorized_targets"], ["192.0.2.1", "192.0.2.2"])
            self.assertEqual(result["status"], "completed", result)
            self.assertEqual(runner.call_count, 1)
            command = runner.call_args.args[0]
            self.assertNotIn("--script", command)
            self.assertNotIn("-sV", command)
            alive = json.loads((self.directory / f"alive_{scan_id}.json").read_text())
            self.assertEqual(alive["alive"], ["192.0.2.1", "192.0.2.2"])
        self.assert_no_external_io()

    def test_explicit_ports_replace_top_ports(self):
        with patch.object(main.subprocess, "run", side_effect=self.fake_scan) as runner:
            response = self.submit(ports="81,80,80")
            self.assertEqual(response.status_code, 200, response.text)
            command = runner.call_args.args[0]
            self.assertNotIn("--top-ports", command)
            self.assertEqual(command[command.index("-p") + 1], "80,81")
            self.assertEqual(self.client.get(f'/scan/{response.json()["scan_id"]}').json()["status"], "completed")

    def test_denied_requests_do_not_create_jobs_or_artifacts(self):
        before = set(self.directory.iterdir())
        cases = [({"authorized": False}, 403), ({"target": "192.0.3.10"}, 403),
                 ({"target": "192.0.2.0/23"}, 400), ({"target": "192.0.3.0/30"}, 403), ({"target": "192.0.2.1/30"}, 400),
                 ({"target": "example.com"}, 400), ({"target": "--script=vuln"}, 400),
                 ({"target": "192.0.2.10 192.0.3.10"}, 400),
                 ({"ports": "80 --script vuln"}, 400), ({"ports": "1-65535"}, 400),
                 ({"ports": "0"}, 400), ({"ports": "65536"}, 400), ({"ports": "90-80"}, 400),
                 ({"target": "192.0.2.10:80", "ports": "81"}, 400),
                 ({"profile": "unknown"}, 400), ({"profile": "vulnerability"}, 400),
                 ({"profile": "full"}, 400), ({"profile": "web", "target": "192.0.2.0/30"}, 400)]
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                self.assertEqual(self.submit(**overrides).status_code, expected)
        self.assertEqual(set(self.directory.iterdir()), before)
        self.assert_no_external_io()

    def test_empty_and_invalid_server_scope_fail_closed(self):
        with patch.dict(os.environ, {"RISKLENS_ALLOWED_TARGETS": ""}):
            self.assertEqual(self.submit().status_code, 403)
        with patch.dict(os.environ, {"RISKLENS_ALLOWED_TARGETS": "not-a-cidr"}):
            self.assertEqual(self.submit().status_code, 503)
        self.assert_no_external_io()

    def test_dot_zero_is_a_single_ip_and_ipv6_is_literal(self):
        plan = policy.validate_request("192.0.2.0", None, "quick")
        self.assertEqual(plan["targets"], ["192.0.2.0"])
        self.assertFalse(plan["cidr"])
        with patch.object(main.subprocess, "run", side_effect=self.fake_scan) as runner:
            response = self.submit(target="::1")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn("-6", runner.call_args.args[0])
            self.assertEqual(self.client.get(f'/scan/{response.json()["scan_id"]}').json()["status"], "completed")

    def test_exit_error_retains_stderr_and_is_not_erased_by_polling(self):
        def fail(command, **kwargs):
            self.fake_scan(command, **kwargs)
            return subprocess.CompletedProcess(command, 2, stdout="", stderr="permission denied")
        with patch.object(main.subprocess, "run", side_effect=fail) as runner:
            response = self.submit()
            scan_id = response.json()["scan_id"]
            for _ in range(2):
                result = self.client.get(f"/scan/{scan_id}").json()
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["nmap_exit_code"], 2)
                self.assertIn("permission denied", result["message"])
            self.assertEqual(runner.call_count, 1)
            self.assertFalse((self.directory / f"{scan_id}.xml").exists())
            self.assertTrue((self.directory / f"{scan_id}.xml.partial").exists())
            self.assertEqual(json.loads((self.directory / f"nmap_{scan_id}.json").read_text())["stderr"], "permission denied")

    def test_timeout_and_os_error_are_terminal_and_release_slot(self):
        for error in (subprocess.TimeoutExpired(["nmap"], 120), FileNotFoundError("nmap disappeared")):
            with self.subTest(error=error), patch.object(main.subprocess, "run", side_effect=error):
                response = self.submit()
                self.assertEqual(response.status_code, 200, response.text)
                status = self.client.get(f'/scan/{response.json()["scan_id"]}').json()
                self.assertEqual(status["status"], "failed")
                self.assertTrue(status["completed_at"])
                self.assertEqual(main.SCAN_SLOTS.acquire(blocking=False), True)
                main.SCAN_SLOTS.release()

    def test_bad_missing_failed_or_out_of_scope_xml_is_not_published(self):
        for xml in ("", "<nmaprun>", "<other/>",
                    '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
                    scan_xml(["192.0.3.10"]), scan_xml([], timedout=False),
                    scan_xml(["192.0.2.10"], timedout=True)):
            def fake(command, **kwargs):
                Path(command[command.index("-oX") + 1]).write_text(xml, encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            with self.subTest(xml=xml[:40]), patch.object(main.subprocess, "run", side_effect=fake):
                response = self.submit()
                scan_id = response.json()["scan_id"]
                self.assertEqual(self.client.get(f"/scan/{scan_id}").json()["status"], "failed")
                self.assertFalse((self.directory / f"{scan_id}.xml").exists())

    def test_scope_is_rechecked_in_worker(self):
        status = main.scan_status_store[fixtures.SCAN_ID]
        with patch.dict(os.environ, {"RISKLENS_ALLOWED_TARGETS": "127.0.0.1/32"}):
            main.run_nmap_scan(fixtures.SCAN_ID, "192.0.2.10", "8080")
        self.assertEqual(status.status, "failed")
        self.assertIn("outside explicitly approved scope", status.message)
        self.assert_no_external_io()

    def test_busy_scanner_rejects_queueing(self):
        main.SCAN_SLOTS.acquire()
        try:
            self.assertEqual(self.submit().status_code, 409)
        finally:
            main.SCAN_SLOTS.release()
        self.assert_no_external_io()

    def test_missing_executable_rejected_before_job_creation(self):
        with patch.object(main, "resolve_executable", side_effect=policy.ConfigurationError("nmap missing")):
            self.assertEqual(self.submit().status_code, 503)
        self.assert_no_external_io()

    def test_xml_parser_rejects_partial_without_waiting(self):
        path = self.directory / "incomplete.xml"
        path.write_text("<nmaprun>")
        with self.assertRaises(ValueError):
            main.parse_nmap_xml(path)

    def test_missing_xml_is_failed_even_with_zero_exit_code(self):
        with patch.object(main.subprocess, "run", return_value=subprocess.CompletedProcess(["nmap"], 0, "", "")):
            response = self.submit()
        result = self.client.get(f'/scan/{response.json()["scan_id"]}').json()
        self.assertEqual(result["status"], "failed")
        self.assertIn("XML missing", result["message"])

    def test_xml_ports_outside_requested_coverage_are_rejected(self):
        with patch.object(main.subprocess, "run", side_effect=self.fake_scan):
            response = self.submit(ports="80")
        result = self.client.get(f'/scan/{response.json()["scan_id"]}').json()
        self.assertEqual(result["status"], "failed")
        self.assertIn("outside the requested TCP coverage", result["message"])

    def test_worker_requires_saved_authorization(self):
        main.scan_status_store[fixtures.SCAN_ID].authorized = False
        main.run_nmap_scan(fixtures.SCAN_ID, "192.0.2.10", "8080")
        self.assertEqual(main.scan_status_store[fixtures.SCAN_ID].status, "failed")
        self.assert_no_external_io()

    def test_restart_marks_unfinished_jobs_failed_without_resuming(self):
        status = main.scan_status_store[fixtures.SCAN_ID]
        status.status = "running"
        status.nmap_status = "running"
        main._save_scan_status_store()
        main._load_scan_status_store()
        result = main.scan_status_store[fixtures.SCAN_ID]
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.nmap_status, "failed")
        saved = json.loads(main.SCAN_STATUS_FILE.read_text())
        self.assertEqual(saved[fixtures.SCAN_ID]["status"], "failed")
        self.assert_no_external_io()

    def test_web_failure_without_stderr_cannot_be_completed(self):
        status = main.scan_status_store[fixtures.SCAN_ID]
        status.nmap_status = "completed"
        status.path_discovery = True
        status.web_url = "http://192.0.2.10:8080"
        audit = {"url": "http://192.0.2.10:8080", "checks": []}
        with patch.object(main, "run_web_security_assessment", return_value=audit):
            with patch.object(main, "execute_discovery", side_effect=RuntimeError("Gobuster exited with code 9: No diagnostic output")):
                main.run_gobuster_scan(fixtures.SCAN_ID, audit["url"])
        self.assertEqual(status.gobuster_status, "failed")
        message = json.loads((self.directory / f"gobuster_{fixtures.SCAN_ID}.status").read_text())
        self.assertIn("code 9", message["detail"])

    def test_web_assessment_wrapper_preserves_public_helper(self):
        audit = {"url": "http://192.0.2.10:8080", "http": {}, "tls": {}, "checks": [], "technologies": []}
        with patch.object(main, "assess_web_url", return_value=audit) as assess:
            self.assertEqual(main.run_web_security_assessment(audit["url"]), audit)
            assess.assert_called_once_with(audit["url"])
        self.assert_no_external_io()


class ExecutableConfigurationTest(unittest.TestCase):
    def test_invalid_explicit_path_does_not_fall_back_to_path(self):
        with patch.dict(os.environ, {"RISKLENS_NMAP_PATH": "relative/nmap.exe"}), patch.object(policy.shutil, "which") as which:
            with self.assertRaises(policy.ConfigurationError):
                policy.resolve_executable("RISKLENS_NMAP_PATH", "nmap")
            which.assert_not_called()

    def test_missing_path_program_reports_configuration_error(self):
        with patch.dict(os.environ, {"RISKLENS_NMAP_PATH": ""}), patch.object(policy.shutil, "which", return_value=None):
            with self.assertRaises(policy.ConfigurationError):
                policy.resolve_executable("RISKLENS_NMAP_PATH", "nmap")


if __name__ == "__main__":
    unittest.main()

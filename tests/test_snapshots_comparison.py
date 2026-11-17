"""Synthetic saved evidence; every API/export is exercised with I/O tripwires."""
from copy import deepcopy
import csv
import io
import json
from unittest.mock import patch

import test_read_only_endpoints as fixtures
from backend import main
from backend.snapshots import normalize_scan, atomic_json
from backend.delta_engine import compare_snapshots, IncompatibleScans

OLD = fixtures.SCAN_ID
NEW = "22222222-2222-4222-8222-222222222222"


def snapshot(scan_id=OLD, state="open", version="1.0", header="nosniff"):
    metadata = {"scan_id": scan_id, "target": "192.0.2.10", "authorized_targets": ["192.0.2.10"],
                "status": "completed", "created_at": "2026-11-16T12:00:00Z", "completed_at": "2026-11-16T12:01:00Z",
                "profile": "web", "ports": "80,8080", "nmap_status": "completed", "web_status": "completed",
                "web_url": "http://192.0.2.10:8080", "gobuster_status": "completed"}
    observations = [{"host": "192.0.2.10", "protocol": "tcp", "port": 80, "state": state, "service": "http",
                     "product": "Synthetic", "version": version, "evidence": {"original": {"state": {"@state": state}, "service": {"@name": "http"}}}}]
    parsed = {"hosts": [{"ip": "192.0.2.10", "state": "up", "services": observations,
                          "omitted_port_states": ["closed"], "omitted_port_count": 1}], "observations": observations,
              "coverage": {"run_completed": True, "scanned_ports": {"tcp": [80, 8080]}}}
    audit = {"url": metadata["web_url"], "status": "completed", "http": {"status": 200,
             "headers": {"X-Content-Type-Options": header} if header is not None else {}},
             "tls": {"verification": "not_applicable"}, "checks": []}
    result = normalize_scan(metadata, parsed, audit, [{"path": "/docs", "status": 200, "size": 10}],
                            {"status": "completed"}, words=["docs", "help"])
    result["findings"] = main.build_findings(parsed, audit)
    return result


class SnapshotComparisonTest(fixtures.SavedScanFixture):
    def pair(self, before=None, after=None):
        before, after = before or snapshot(), after or snapshot(NEW)
        atomic_json(self.directory / f"snapshot_{OLD}.json", before)
        atomic_json(self.directory / f"snapshot_{NEW}.json", after)
        return before, after

    def test_normalization_preserves_fields_and_original_evidence(self):
        result = snapshot()
        self.assertEqual(result["components"]["network"]["status"], "completed")
        self.assertEqual(result["components"]["http"]["headers"], {"x-content-type-options": "nosniff"})
        self.assertEqual(result["components"]["tls"]["status"], "not_run")
        self.assertEqual(result["components"]["paths"]["status"], "completed")
        self.assertIn("original", result["components"]["network"]["observations"][0]["evidence"])
        self.assertEqual(result["timestamp"], "2026-11-16T12:01:00Z")

    def test_unknown_legacy_network_completion_is_partial(self):
        metadata = snapshot()["metadata"]
        metadata["nmap_status"] = None
        parsed = snapshot()["components"]["network"]["parsed"]
        result = normalize_scan(metadata, parsed)
        self.assertEqual(result["components"]["network"]["status"], "partial")

    def test_completed_label_without_successful_xml_is_not_complete_coverage(self):
        original = snapshot()
        parsed = deepcopy(original["components"]["network"]["parsed"])
        parsed["coverage"]["run_completed"] = False
        result = normalize_scan(original["metadata"], parsed)
        self.assertEqual(result["components"]["network"]["status"], "partial")

    def test_web_only_can_complete_with_network_not_run(self):
        source = snapshot()
        metadata = {**source["metadata"], "network_scan": False, "nmap_status": "skipped", "gobuster_status": "skipped"}
        result = normalize_scan(metadata, audit={"url": metadata["web_url"], "http": {"status": 200, "headers": {}}})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["components"]["network"]["status"], "not_run")
        self.assertEqual(result["components"]["paths"]["status"], "not_run")

    def test_failed_and_partial_components_are_explicit(self):
        metadata = {**snapshot()["metadata"], "nmap_status": "failed", "gobuster_status": "timed_out"}
        result = normalize_scan(metadata, audit={"url": metadata["web_url"], "error": "certificate invalid",
            "error_category": "certificate_verification_failed", "tls": {"verification": "failed"}},
            paths=[{"path": "/docs", "status": 200}])
        self.assertEqual([result["components"][key]["status"] for key in ("network", "http", "tls", "paths")],
                         ["failed", "failed", "failed", "partial"])

    def test_headers_not_captured_is_not_negative_coverage(self):
        meta = snapshot()["metadata"]
        result = normalize_scan(meta, audit={"url": meta["web_url"], "http": {"status": 200}})
        self.assertEqual(result["components"]["http"]["status"], "partial")

    def test_explicit_closed_to_open_and_open_to_closed(self):
        old, new = snapshot(state="closed"), snapshot(NEW)
        result = compare_snapshots(old, new)
        self.assertTrue(any(item["kind"] == "open_port" for item in result["added"]))
        result = compare_snapshots(new, old)
        self.assertTrue(any(item["kind"] == "open_port" for item in result["removed"]))

    def test_filtered_port_is_uncertain_not_removed(self):
        result = compare_snapshots(snapshot(), snapshot(NEW, state="filtered"))
        self.assertFalse(result["removed"])
        self.assertTrue(any(item["kind"] == "open_port" for item in result["uncertain"]))

    def test_nmap_omitted_closed_ports_can_establish_removal(self):
        old, new = snapshot(), snapshot(NEW)
        new["components"]["network"]["observations"] = []
        new["components"]["network"]["hosts"][0]["omitted_port_count"] = 2
        result = compare_snapshots(old, new)
        self.assertTrue(any(item["kind"] == "open_port" for item in result["removed"]))

    def test_different_coverage_or_down_host_cannot_establish_removal(self):
        for change in ("coverage", "down", "count"):
            old, new = snapshot(), snapshot(NEW)
            new["components"]["network"]["observations"] = []
            new["components"]["network"]["hosts"][0]["omitted_port_count"] = 2
            if change == "coverage":
                new["components"]["network"]["coverage"]["scanned_ports"] = {"tcp": [8080]}
            elif change == "down":
                new["components"]["network"]["hosts"][0]["state"] = "down"
            else:
                new["components"]["network"]["hosts"][0]["omitted_port_count"] = 0
            self.assertFalse(compare_snapshots(old, new)["removed"])

    def test_known_version_changes_and_unknown_version_is_uncertain(self):
        result = compare_snapshots(snapshot(), snapshot(NEW, version="2.0"))
        self.assertTrue(any(item["kind"] == "version" for item in result["changed"]))
        result = compare_snapshots(snapshot(), snapshot(NEW, version=None))
        self.assertFalse(result["changed"])
        self.assertTrue(any(item["kind"] == "version" for item in result["uncertain"]))

    def test_header_added_removed_changed(self):
        self.assertTrue(compare_snapshots(snapshot(header=None), snapshot(NEW))["added"])
        self.assertTrue(compare_snapshots(snapshot(), snapshot(NEW, header=None))["removed"])
        self.assertTrue(compare_snapshots(snapshot(header="wrong"), snapshot(NEW))["changed"])

    def test_failed_http_cannot_remove_headers(self):
        old, new = snapshot(), snapshot(NEW, header=None)
        new["components"]["http"]["status"] = "failed"
        result = compare_snapshots(old, new)
        self.assertFalse(result["removed"])
        self.assertTrue(result["uncertain"])

    def test_different_response_status_makes_header_changes_uncertain(self):
        old, new = snapshot(), snapshot(NEW, header=None)
        new["components"]["http"]["response"]["status"] = 302
        self.assertFalse(compare_snapshots(old, new)["removed"])

    def test_tls_metadata_changes_require_verified_coverage(self):
        old, new = snapshot(), snapshot(NEW)
        for item in (old, new):
            item["components"]["tls"].update(status="completed", details={"verification": "verified", "protocol": "TLSv1.3", "certificate_sha256": "aaa"})
        new["components"]["tls"]["details"]["certificate_sha256"] = "bbb"
        self.assertTrue(any(item["component"] == "tls" for item in compare_snapshots(old, new)["changed"]))
        new["components"]["tls"]["status"] = "failed"
        self.assertFalse(compare_snapshots(old, new)["changed"])

    def test_path_added_removed_status_and_mismatched_wordlists(self):
        old, new = snapshot(), snapshot(NEW)
        new["components"]["paths"]["observations"] = [{"path": "/help", "status": 200}]
        result = compare_snapshots(old, new)
        self.assertTrue(result["added"])
        self.assertTrue(result["removed"])
        new["components"]["paths"]["coverage"]["words"] = ["help"]
        result = compare_snapshots(old, new)
        self.assertFalse(result["added"] or result["removed"])
        self.assertTrue(result["uncertain"])

    def test_failed_new_network_never_marks_closed_port_removed(self):
        old, new = snapshot(), snapshot(NEW, state="closed")
        new["components"]["network"]["status"] = "partial"
        self.assertFalse(compare_snapshots(old, new)["removed"])

    def test_api_uses_saved_snapshots_without_processes_or_requests(self):
        self.pair(after=snapshot(NEW, header="wrong"))
        result = self.client.get(f"/scans/{NEW}/compare/{OLD}")
        self.assertEqual(result.status_code, 200, result.text)
        self.assertTrue(result.json()["changed"])
        self.assert_no_external_io()

    def test_api_ids_missing_corrupt_and_active_scans(self):
        self.pair()
        self.assertEqual(self.client.get(f"/scans/bad/compare/{OLD}").status_code, 400)
        missing = "33333333-3333-4333-8333-333333333333"
        self.assertEqual(self.client.get(f"/scans/{missing}/compare/{OLD}").status_code, 404)
        current = snapshot(NEW)
        current["metadata"]["status"] = "running"
        atomic_json(self.directory / f"snapshot_{NEW}.json", current)
        self.assertEqual(self.client.get(f"/scans/{NEW}/compare/{OLD}").status_code, 409)
        (self.directory / f"snapshot_{NEW}.json").write_text("{bad")
        self.assertEqual(self.client.get(f"/scans/{NEW}/compare/{OLD}").status_code, 422)
        current = snapshot(NEW)
        current.pop("metadata")
        atomic_json(self.directory / f"snapshot_{NEW}.json", current)
        self.assertEqual(self.client.get(f"/scans/{NEW}/compare/{OLD}").status_code, 422)
        self.assert_no_external_io()

    def test_api_rejects_target_or_web_port_mismatch(self):
        for change in ("target", "origin"):
            old, new = snapshot(), snapshot(NEW)
            if change == "target":
                new["identity"]["targets"] = ["192.0.2.11"]
            else:
                new["identity"]["web_origin"]["port"] = 8443
            self.pair(old, new)
            self.assertEqual(self.client.get(f"/scans/{NEW}/compare/{OLD}").status_code, 409)
        self.assert_no_external_io()

    def test_different_requested_cidrs_cannot_share_identity_from_alive_hosts(self):
        old, new = snapshot(), snapshot(NEW)
        new["identity"]["target_key"] = "192.0.2.0/24"
        with self.assertRaises(IncompatibleScans):
            compare_snapshots(old, new)

    def test_unrequested_paths_stay_not_run_after_http_failure(self):
        result = normalize_scan(snapshot()["metadata"], audit={"url": "http://192.0.2.10:8080", "error": "read timeout"},
                                path_record={"enabled": False, "status": "failed"})
        self.assertEqual(result["components"]["paths"]["status"], "not_run")

    def test_zero_exit_with_gobuster_request_errors_is_incomplete(self):
        from backend.scanner.path_discovery import execute_discovery
        from unittest.mock import Mock
        import threading
        from backend.scanner import path_discovery
        process = Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        def launch(command, **kwargs):
            kwargs["stderr"].write(b"[ERROR] synthetic request timeout")
            kwargs["stderr"].flush()
            return process
        with patch.object(path_discovery.subprocess, "Popen", side_effect=launch):
            with self.assertRaisesRegex(RuntimeError, "uncertain coverage"):
                execute_discovery("mock.exe", "http://192.0.2.10", self.directory / "words", self.directory / "paths.txt", threading.Event(), lambda: None)
        self.assert_no_external_io()

    def test_get_legacy_snapshot_does_not_write_files(self):
        before = set(self.directory.iterdir())
        self.assertEqual(self.client.get(f"/scans/{OLD}/snapshot").status_code, 200)
        self.assertEqual(before, set(self.directory.iterdir()))
        self.assert_no_external_io()

    def test_persisted_findings_are_identical_in_ui_csv_pdf_and_web_api(self):
        old, new = self.pair()
        finding = {"id": "WEB-TEST", "rule_id": "WEB-TEST", "title": "Synthetic saved finding", "domain": "web",
                   "category": "configuration_observation", "severity": "info", "confidence": "high", "asset": new["target"],
                   "source": "Saved test evidence", "evidence": "UniqueSavedEvidence", "remediation": "UniqueRemediation", "retest": "UniqueRetest"}
        new["findings"] = [finding]
        atomic_json(self.directory / f"snapshot_{NEW}.json", new)
        with patch.object(main, "build_findings", side_effect=AssertionError("Must not recalculate saved findings")):
            self.assertEqual(self.client.get(f"/scan/{NEW}/findings").json()["findings"], [finding])
            self.assertEqual(self.client.get(f"/webscan/{NEW}/findings").json()["findings"], [finding])
            csv_response = self.client.get(f"/scan/{NEW}/findings.csv")
            row = list(csv.DictReader(io.StringIO(csv_response.text)))[0]
            for key in ("evidence", "severity", "confidence", "remediation", "retest"):
                self.assertEqual(row[key], finding[key])
            pdf = self.client.get(f"/scan/{NEW}/report.pdf")
            self.assertEqual(pdf.status_code, 200)
            self.assertTrue(pdf.content.startswith(b"%PDF-"))
            for value in (b"UniqueSavedEvidence", b"UniqueRemediation", b"UniqueRetest", b"Network findings", b"Web configuration"):
                self.assertIn(value, pdf.content)
        self.assert_no_external_io()

    def test_report_optional_differences_are_same_as_comparison_api(self):
        self.pair(after=snapshot(NEW, header="wrong"))
        expected = self.client.get(f"/scans/{NEW}/compare/{OLD}").json()
        original = main.build_pdf_report
        with patch.object(main, "build_pdf_report", wraps=original) as pdf_builder:
            response = self.client.get(f"/scan/{NEW}/report.pdf?baseline={OLD}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(pdf_builder.call_args.kwargs["differences"], expected)
        csv_report = self.client.get(f"/scan/{NEW}/findings.csv?baseline={OLD}")
        rows = list(csv.DictReader(io.StringIO(csv_report.text)))
        self.assertTrue(any(row["record_type"] == "difference" and row["title"] == "security_header" for row in rows))
        self.assert_no_external_io()

    def test_independent_web_works_without_nmap_and_saves_snapshot(self):
        audit = {"url": "http://127.0.0.1:8080", "http": {"status": 200, "headers": {}}, "checks": [], "tls": {}}
        with patch.object(main, "resolve_executable", side_effect=AssertionError("Nmap/Gobuster must not be required")), patch.object(main, "run_web_security_assessment", return_value=audit):
            response = self.client.post("/webscan", json={"url": audit["url"], "authorized": True})
        self.assertEqual(response.status_code, 200, response.text)
        scan_id = response.json()["scan_id"]
        saved = self.client.get(f"/scans/{scan_id}/snapshot").json()
        self.assertEqual(saved["components"]["network"]["status"], "not_run")
        self.assertEqual(saved["components"]["http"]["status"], "completed")
        self.assertTrue((self.directory / f"snapshot_{scan_id}.json").exists())
        self.assertEqual(self.client.get(f"/scan/{scan_id}/report.pdf").status_code, 200)
        self.assert_no_external_io()

    def test_independent_web_requires_authorization_and_scope(self):
        for body, expected in (({"url": "http://127.0.0.1:8080"}, 403),
                               ({"url": "http://198.51.100.1:8080", "authorized": True}, 403)):
            self.assertEqual(self.client.post("/webscan", json=body).status_code, expected)
        self.assert_no_external_io()

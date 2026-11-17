"""Evidence and severity regressions using synthetic saved XML and candidate data."""

import hashlib
from unittest.mock import patch
import unittest

import test_read_only_endpoints as fixtures
from backend import main
from backend.scanner.pcvp_scoring import pcvp_score_for_service
from backend.scanner.network_findings import normalize_nvd_candidates
from backend.scanner.nvd_mapping import enrich_service_with_nvd
from backend.scanner.attack_graph import build_attack_graph


class NetworkFindingsTest(fixtures.SavedScanFixture):
    def parsed(self):
        return main.parse_nmap_xml(self.directory / f"{fixtures.SCAN_ID}.xml")

    def test_open_ssh_only_is_observation_not_critical_flaw(self):
        parsed = self.parsed()
        main.annotate_saved_services(parsed, "external")
        ssh = next(s for s in parsed["hosts"][0]["services"] if s["port"] == 22)
        self.assertEqual(ssh["pcvp_score"], 25)
        self.assertEqual(ssh["pcvp_level"], "low")
        self.assertEqual(ssh["severity"], "info")
        findings = main.build_findings(parsed)
        self.assertEqual({f["category"] for f in findings}, {"observation"})
        self.assertEqual({f["severity"] for f in findings}, {"info"})
        self.assertEqual({f["confidence"] for f in findings}, {"high"})
        self.assertTrue(all(f["confidence_scope"] == "port_state_only" for f in findings))
        self.assert_no_external_io()

    def test_unknown_version_remains_unknown_and_has_low_identity_confidence(self):
        path = self.directory / f"{fixtures.SCAN_ID}.xml"
        path.write_text(fixtures.XML.replace(' version="1.0"/>', '/>'), encoding="utf-8")
        parsed = self.parsed()
        main.annotate_saved_services(parsed, "external")
        for service in parsed["hosts"][0]["services"]:
            self.assertIsNone(service["version"])
            self.assertEqual(service["identity_confidence"], "low")
            self.assertTrue(any("Version unknown" in reason for reason in service["pcvp_reasons"]))
        self.assertTrue(all("Version is unknown" in finding["reason"] for finding in main.build_findings(parsed)))
        self.assert_no_external_io()

    def test_candidate_cve_is_unverified_and_does_not_raise_severity(self):
        parsed = self.parsed()
        service = parsed["hosts"][0]["services"][1]
        before = pcvp_score_for_service(service, "external")["pcvp_score"]
        service["version"] = None
        service["nvd"] = {"keyword": "Synthetic SSH", "cves": [{
            "id": "SYNTHETIC-CVE", "severity": "CRITICAL", "score": 9.8,
            "description": "Invented candidate for regression testing, not a real advisory.",
            "verification_status": "confirmed", "applicability": {"status": "verified"},
        }]}
        main.annotate_saved_services(parsed, "external")
        candidates = parsed["candidate_vulnerabilities"]
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["category"], "candidate_vulnerability")
        self.assertEqual(candidate["verification_status"], "unverified")
        self.assertEqual(candidate["severity"], "info")
        self.assertEqual(candidate["confidence"], "low")
        self.assertIsNone(candidate["cvss"])
        self.assertEqual(candidate["reported_cvss"], 9.8)
        self.assertEqual(candidate["reported_severity"], "CRITICAL")
        self.assertIn("unknown", candidate["applicability"]["reason"])
        self.assertEqual(service["pcvp_score"], before)
        self.assertEqual(service["nvd"]["cves"][0]["severity"], "info")
        self.assert_no_external_io()

    def test_known_version_alone_cannot_confirm_keyword_applicability(self):
        service = {"product": "Synthetic SSH", "version": "1.0"}
        result = normalize_nvd_candidates({"cves": [{"id": "SYNTHETIC-CVE", "score": 9.8}]}, service)
        self.assertEqual(result["cves"][0]["applicability"]["status"], "unverified")
        self.assertEqual(result, normalize_nvd_candidates(result, service))

    def test_normalized_observations_retain_original_evidence(self):
        result = self.client.get(f"/scan/{fixtures.SCAN_ID}/parsed").json()["data"]
        observation = result["observations"][0]
        self.assertEqual(set(observation), {"host", "protocol", "port", "state", "service", "product", "version", "evidence"})
        self.assertEqual(observation["host"], "192.0.2.10")
        evidence = observation["evidence"]
        path = self.directory / f"{fixtures.SCAN_ID}.xml"
        self.assertEqual(evidence["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(evidence["artifact"], path.name)
        self.assertEqual(evidence["original"]["state"]["@state"], observation["state"])
        self.assertEqual(evidence["original"]["@portid"], str(observation["port"]))
        self.assert_no_external_io()

    def test_negative_and_positive_nse_strings_are_not_automatically_high_findings(self):
        parsed = self.parsed()
        parsed["hosts"][0]["services"][0]["nse_findings"] = [
            {"id": "synthetic-negative", "output": "NOT VULNERABLE"},
            {"id": "synthetic-positive", "output": "VULNERABLE"},
        ]
        findings = main.build_findings(parsed)
        scripts = [f for f in findings if f["category"] == "script_observation"]
        self.assertEqual(len(scripts), 2)
        self.assertEqual({f["severity"] for f in scripts}, {"info"})
        self.assertEqual({f["verification_status"] for f in scripts}, {"unreviewed"})

    def test_findings_api_exposes_separate_observations_and_candidates(self):
        result = self.client.get(f"/scan/{fixtures.SCAN_ID}/findings").json()
        self.assertEqual(len(result["network_observations"]), 3)
        self.assertEqual(result["candidate_vulnerabilities"], [])
        for finding in result["findings"]:
            self.assertIn("rule_id", finding)
            self.assertTrue(finding["reason"])
            self.assertIn("domain", finding)
        self.assert_no_external_io()

    def test_optional_nvd_helper_labels_keyword_results_at_the_producer(self):
        raw = {"vulnerabilities": [{"cve": {"id": "SYNTHETIC-CVE", "descriptions": []}}]}
        with patch("backend.scanner.nvd_mapping.query_nvd_by_keyword", return_value=raw):
            result = enrich_service_with_nvd("Synthetic SSH", "1.0")
        self.assertEqual(result["status"], "unverified_candidates")
        self.assertEqual(result["cves"][0]["verification_status"], "unverified")
        self.assert_no_external_io()

    def test_graph_labels_candidates_without_claiming_applicability(self):
        parsed = self.parsed()
        parsed["hosts"][0]["services"][0]["nvd"] = {"cves": [{"id": "SYNTHETIC-CVE", "score": 9.8}]}
        main.annotate_saved_services(parsed, "external")
        graph = build_attack_graph(parsed)
        relations = {edge["relation"] for edge in graph["edges"]}
        self.assertIn("candidate_cve", relations)
        self.assertNotIn("has_vulnerability", relations)
        self.assertNotIn("possible_chain", relations)


if __name__ == "__main__":
    unittest.main()

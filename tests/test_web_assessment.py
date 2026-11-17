"""Exercise real assessment/transport code using synthetic sockets and HTTP responses."""

import json
import os
import socket
import ssl
from unittest.mock import Mock, patch

import test_read_only_endpoints as fixtures
from backend.scanner import web_assessment as web


class WebAssessmentTest(fixtures.SavedScanFixture):
    def setUp(self):
        super().setUp()
        self.stack.enter_context(patch.dict(os.environ, {"RISKLENS_ALLOWED_WEB_PORTS": "80,443,8080,8443"}))
        self.raw = Mock()
        self.raw.getpeername.return_value = ("127.0.0.1", 443)
        # Replace only this module's socket namespace. Patching the global socket
        # class breaks Windows asyncio's isinstance checks in the ASGI test client.
        self.socket_type = Mock(return_value=self.raw)
        self.stack.enter_context(patch.object(web, "socket", Mock(
            socket=self.socket_type, AF_INET=socket.AF_INET, AF_INET6=socket.AF_INET6,
            SOCK_STREAM=socket.SOCK_STREAM)))
        self.request = self.stack.enter_context(patch.object(web.http.client.HTTPConnection, "request"))
        self.response = Mock(status=200)
        self.response.getheaders.return_value = [("Server", "synthetic"), ("X-Content-Type-Options", "wrong")]
        self.response.read1.side_effect = [b"wp-content", b""]
        self.getresponse = self.stack.enter_context(patch.object(
            web.http.client.HTTPConnection, "getresponse", return_value=self.response))
        self.context = ssl.create_default_context()
        self.context_type = self.stack.enter_context(patch.object(web.ssl, "create_default_context", return_value=self.context))
        self.tls = Mock()
        self.tls.version.return_value = "TLSv1.3"
        self.tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        certificate = {"subject": ((('commonName', 'synthetic'),),), "issuer": ((('commonName', 'local test CA'),),),
                       "notAfter": "Jan 1 00:00:00 2030 GMT", "serialNumber": "1234",
                       "subjectAltName": (("IP Address", "127.0.0.1"),)}
        self.tls.getpeercert.side_effect = lambda binary_form=False: b"synthetic DER" if binary_form else certificate
        self.wrap = self.stack.enter_context(patch.object(self.context, "wrap_socket", return_value=self.tls))

    def assess(self, url="https://127.0.0.1/"):
        result = fixtures.main.run_web_security_assessment(url)
        self.assert_no_external_io()
        self.assertTrue({"url", "http", "tls", "technologies", "checks"}.issubset(result))
        return result

    def test_success_captures_normalized_headers_and_verified_same_connection_tls(self):
        result = self.assess()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["http"]["status"], 200)
        self.assertEqual(result["http"]["headers"]["server"], "synthetic")
        self.assertEqual(result["http"]["body_bytes_sampled"], 10)
        self.assertEqual(result["tls"]["protocol"], "TLSv1.3")
        self.assertEqual(result["tls"]["verification"], "verified")
        self.assertEqual(result["tls"]["serial_number"], "1234")
        self.assertEqual(len(result["tls"]["certificate_sha256"]), 64)
        self.assertTrue(self.context.check_hostname)
        self.assertEqual(self.context.verify_mode, ssl.CERT_REQUIRED)
        self.wrap.assert_called_once_with(self.raw, server_hostname="127.0.0.1")
        self.raw.connect.assert_called_once_with(("127.0.0.1", 443))
        self.raw.settimeout.assert_any_call(web.CONNECT_TIMEOUT)
        self.assertIn({"name": "WordPress", "evidence": "wp-content"}, result["technologies"])
        bad = next(check for check in result["checks"] if check["name"] == "X-Content-Type-Options")
        self.assertEqual((bad["status"], bad["severity"]), ("misconfigured", "info"))

    def test_invalid_certificate_no_insecure_retry_or_header_findings(self):
        self.wrap.side_effect = ssl.SSLCertVerificationError(1, "certificate verify failed")
        result = self.assess()
        self.assertEqual(result["error_category"], "certificate_verification_failed")
        self.assertEqual(result["tls"]["verification"], "failed")
        self.assertEqual(result["http"], {})
        self.assertEqual(result["checks"], [])
        self.assertNotIn("protocol", result["tls"])
        self.wrap.assert_called_once()
        self.request.assert_not_called()
        self.raw.close.assert_called()

    def test_external_redirect_preserves_status_and_never_connects_to_destination(self):
        self.response.status = 302
        self.response.getheaders.return_value = [("Location", "https://outside.example/")]
        result = self.assess()
        self.assertEqual(result["http"]["status"], 302)
        self.assertEqual(result["http"]["final_url"], "https://127.0.0.1/")
        self.assertEqual(result["error_category"], "redirect_scope_blocked")
        self.assertEqual(result["redirects"][0]["decision"], "blocked")
        self.assertFalse(result["redirects"][0]["followed"])
        self.raw.connect.assert_called_once()
        self.request.assert_called_once()
        self.response.read1.assert_not_called()

    def test_same_origin_redirect_is_recorded_without_following(self):
        self.response.status = 301
        self.response.getheaders.return_value = [("Location", "/login")]
        result = self.assess()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["redirects"][0]["decision"], "same_origin_not_followed")
        self.assertEqual(result["redirects"][0]["to"], "https://127.0.0.1/login")
        self.request.assert_called_once()

    def test_approved_different_ip_or_port_or_https_downgrade_is_still_blocked(self):
        for destination in ("https://[::1]/", "https://127.0.0.1:8443/", "http://127.0.0.1/"):
            with self.subTest(destination=destination):
                self.response.status = 302
                self.response.getheaders.return_value = [("Location", destination)]
                self.assertEqual(self.assess()["error_category"], "redirect_scope_blocked")

    def test_connect_timeout(self):
        self.raw.connect.side_effect = TimeoutError("synthetic connect timeout")
        result = self.assess()
        self.assertEqual(result["error_category"], "connect_timeout")
        self.assertEqual(result["http"], {})
        self.request.assert_not_called()

    def test_read_timeout_without_http_response(self):
        self.getresponse.side_effect = TimeoutError("synthetic read timeout")
        result = self.assess()
        self.assertEqual(result["error_category"], "read_timeout")
        self.assertEqual(result["checks"], [])
        self.assertEqual(result["tls"]["verification"], "verified")

    def test_body_timeout_preserves_observed_http_and_tls(self):
        self.response.read1.side_effect = [b"part", TimeoutError("synthetic body timeout")]
        result = self.assess()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["http"]["status"], 200)
        self.assertEqual(result["http"]["body_bytes_sampled"], 4)
        self.assertEqual(result["error_category"], "read_timeout")

    def test_body_sampling_is_bounded(self):
        self.response.read1.side_effect = lambda size: b"x" * size
        result = self.assess()
        self.assertEqual(result["http"]["body_bytes_sampled"], web.BODY_LIMIT)
        self.assertTrue(result["http"]["body_limit_reached"])

    def test_invalid_url_scope_or_port_never_connects(self):
        for url in ("ftp://127.0.0.1/", "http://localhost/", "http://user:pass@127.0.0.1/",
                    "http://127.0.0.1:9000/", "http://198.51.100.1/", "http://127.0.0.1:0/",
                    "http://127.0.0.1/\r\nx: y", "http://127.0.0.1/#fragment"):
            with self.subTest(url=url):
                self.assertEqual(self.assess(url)["status"], "failed")
        self.socket_type.assert_not_called()

    def test_connected_peer_must_match_approved_ip(self):
        self.raw.getpeername.return_value = ("198.51.100.1", 443)
        self.assertEqual(self.assess()["error_category"], "scope_rejected")
        self.wrap.assert_not_called()
        self.request.assert_not_called()

    def test_http_records_no_tls_and_hsts_not_applicable(self):
        result = self.assess("http://127.0.0.1/")
        self.assertEqual(result["tls"]["verification"], "not_applicable")
        self.context_type.assert_not_called()
        self.assertEqual(result["checks"][0]["status"], "not_applicable")

    def test_failed_saved_assessment_is_returned_without_network_or_rescan(self):
        self.wrap.side_effect = ssl.SSLCertVerificationError(1, "certificate verify failed")
        failure = self.assess()
        (self.directory / f"web_audit_{fixtures.SCAN_ID}.json").write_text(json.dumps(failure), encoding="utf-8")
        before = self.socket_type.call_count
        self.assertEqual(self.client.get(f"/webscan/{fixtures.SCAN_ID}/assessment").json(), failure)
        self.assertEqual(self.socket_type.call_count, before)
        self.assert_no_external_io()

    def test_connection_refused_is_truthful_failure(self):
        self.raw.connect.side_effect = ConnectionRefusedError("synthetic refused connection")
        result = self.assess()
        self.assertEqual(result["error_category"], "connection_refused")
        self.assertEqual(result["http"], {})
        self.assertEqual(result["checks"], [])

    def test_invalid_port_configuration_never_connects(self):
        with patch.dict(os.environ, {"RISKLENS_ALLOWED_WEB_PORTS": "443,not-a-port"}):
            self.assertEqual(self.assess()["error_category"], "configuration_error")
        self.socket_type.assert_not_called()

    def test_revoked_scope_is_rechecked_before_connect(self):
        from backend.scanner.scan_policy import validate_targets
        with patch.object(web, "validate_targets", side_effect=[
            validate_targets(["127.0.0.1"]), web.ScopeError("Scope revoked before connecting")
        ]):
            self.assertEqual(self.assess()["error_category"], "scope_rejected")
        self.socket_type.assert_not_called()

    def test_post_rejects_disallowed_web_port_before_job_starts(self):
        response = self.client.post("/scan", json={"target": "http://127.0.0.1:9000", "profile": "web", "authorized": True})
        self.assertEqual(response.status_code, 403)
        self.assertIn("RISKLENS_ALLOWED_WEB_PORTS", response.text)
        self.socket_type.assert_not_called()
        self.assert_no_external_io()

    def test_worker_persists_failure_and_does_not_start_gobuster(self):
        fixtures.main.scan_status_store[fixtures.SCAN_ID].nmap_status = "completed"
        failure = {"url": "https://192.0.2.10:8080", "http": {}, "tls": {}, "checks": [],
                   "technologies": [], "error_category": "certificate_verification_failed", "error": "invalid certificate"}
        with patch.object(fixtures.main, "run_web_security_assessment", return_value=failure):
            fixtures.main.run_gobuster_scan(fixtures.SCAN_ID, failure["url"])
        self.assertEqual(fixtures.main.scan_status_store[fixtures.SCAN_ID].gobuster_status, "failed")
        self.assertEqual(self.client.get(f"/webscan/{fixtures.SCAN_ID}/assessment").json(), failure)
        self.assert_no_external_io()

    def test_header_findings_are_configuration_observations(self):
        findings = fixtures.main.build_findings({"hosts": []}, self.assess())
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding["severity"], "info")
            self.assertEqual(finding["category"], "configuration_observation")
            self.assertIn("exploitation", finding["reason"])

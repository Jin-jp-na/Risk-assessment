"""One bounded HTTP request to an approved literal IP; no DNS, proxy or redirects."""

import hashlib
import http.client
import ipaddress
import os
import re
import socket
import ssl
import time
from urllib.parse import urlsplit, urljoin

from backend.scanner.scan_policy import ConfigurationError, ScopeError, validate_targets

CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
TOTAL_TIMEOUT = 20
BODY_LIMIT = 200_000


def validate_web_url(url, scope=None):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("URL must contain no whitespace/control characters and be at most 2048 characters")
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or "%" in parsed.netloc or "\\" in url
            or parsed.netloc.endswith(":")):
        raise ValueError("Use an HTTP/HTTPS literal-IP URL without credentials, fragments or zone IDs")
    # Deliberately no hostname resolution: keep the existing IP-only scan policy.
    host = str(ipaddress.ip_address(parsed.hostname))
    validate_targets([host], scope)
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    configured = os.environ.get("RISKLENS_ALLOWED_WEB_PORTS", "80,443,8080,8443")
    if not re.fullmatch(r"[0-9]+(?:,[0-9]+)*", configured):
        raise ConfigurationError("RISKLENS_ALLOWED_WEB_PORTS must be a comma-separated list of ports")
    allowed = {int(item) for item in configured.split(",")}
    if any(not 1 <= number <= 65535 for number in allowed):
        raise ConfigurationError("RISKLENS_ALLOWED_WEB_PORTS ports must be within 1-65535")
    if port not in allowed:
        raise ScopeError(f"Web port {port} is outside RISKLENS_ALLOWED_WEB_PORTS")
    return parsed, host, port


class _PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host, port, scheme, scope, deadline):
        super().__init__(host, port, timeout=CONNECT_TIMEOUT)
        self.scheme, self.scope, self.deadline = scheme, scope, deadline
        self.tls_evidence = {}

    def connect(self):
        validate_targets([self.host], self.scope)  # recheck operator scope immediately before connecting
        address = ipaddress.ip_address(self.host)
        raw = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        self.sock = raw
        try:
            raw.settimeout(min(CONNECT_TIMEOUT, max(0.001, self.deadline - time.monotonic())))
            raw.connect((self.host, self.port))  # numeric address; no getaddrinfo or DNS rebinding
            if ipaddress.ip_address(raw.getpeername()[0]) != address:
                raise ScopeError("Connected peer differs from the approved IP")
            if self.scheme == "https":
                context = ssl.create_default_context()  # CERT_REQUIRED and hostname/IP SAN verification
                self.sock = context.wrap_socket(raw, server_hostname=self.host)
                cert = self.sock.getpeercert()
                cipher = self.sock.cipher()
                self.tls_evidence = {
                    "verification": "verified", "protocol": self.sock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "subject": str(cert.get("subject", "")), "issuer": str(cert.get("issuer", "")),
                    "expires": cert.get("notAfter"), "not_before": cert.get("notBefore"),
                    "serial_number": cert.get("serialNumber"), "subject_alt_names": cert.get("subjectAltName", []),
                    "certificate_sha256": hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest(),
                    "source": "same verified connection as HTTP request",
                }
            self.sock.settimeout(READ_TIMEOUT)
        except BaseException:
            self.close()
            raise


def _header_checks(headers, scheme):
    labels = {"strict-transport-security": "HSTS", "content-security-policy": "Content-Security-Policy",
              "x-content-type-options": "X-Content-Type-Options", "x-frame-options": "X-Frame-Options",
              "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy"}
    checks = []
    for header, label in labels.items():
        value = headers.get(header)
        status = "missing" if value is None else "review"
        detail = f"{header}: {value}" if value is not None else f"{header} absent from this response"
        if header == "strict-transport-security" and scheme == "http":
            status, detail = "not_applicable", "HSTS is effective only over verified HTTPS"
        elif value is not None:
            invalid = not value.strip()
            if header == "x-content-type-options":
                invalid = value.strip().lower() != "nosniff"
            elif header == "x-frame-options":
                invalid = value.strip().lower() not in {"deny", "sameorigin"}
            elif header == "strict-transport-security":
                age = re.search(r"(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?:;|$)", value, re.I)
                invalid = age is None or int(age.group(1)) == 0
            elif header == "referrer-policy":
                valid = {"no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
                         "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
                invalid = not any(item.strip().lower() in valid for item in value.split(","))
            if invalid:
                status = "misconfigured"
        checks.append({"name": label, "status": status, "detail": detail,
                       "category": "configuration_observation", "severity": "info",
                       "reason": "Response configuration only; application impact and exploitation are not established."})
    return checks


def assess_web_url(url, scope=None):
    # Original fields always exist, including on failure. Additional fields are additive.
    result = {"url": url, "http": {}, "tls": {}, "technologies": [], "checks": [],
              "status": "failed", "redirects": []}
    conn = None
    response = None
    phase = "validation"
    try:
        parsed, host, port = validate_web_url(url, scope)
        result["tls"] = {"verification": "not_attempted" if parsed.scheme == "https" else "not_applicable"}
        deadline = time.monotonic() + TOTAL_TIMEOUT
        conn = _PinnedConnection(host, port, parsed.scheme, scope, deadline)
        phase = "connect"
        conn.connect()
        result["tls"] = conn.tls_evidence or result["tls"]
        phase = "read"
        conn.sock.settimeout(min(READ_TIMEOUT, max(0.001, deadline - time.monotonic())))
        conn.request("GET", (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
                     headers={"User-Agent": "RiskLens/2.0", "Accept-Encoding": "identity", "Connection": "close"})
        read_socket = conn.sock
        response = conn.getresponse()
        raw_headers = response.getheaders()
        headers = {}
        for key, value in raw_headers:
            key = key.lower()
            headers[key] = headers[key] + ", " + value if key in headers else value
        result["http"] = {"status": response.status, "final_url": url, "headers": headers,
                          "raw_headers": raw_headers, "body_bytes_sampled": 0}
        result["checks"] = _header_checks(headers, parsed.scheme)
        if 300 <= response.status < 400 and "location" in headers:
            decision = {"from": url, "location": headers["location"], "to": None,
                        "followed": False, "status": response.status}
            result["redirects"].append(decision)
            try:
                destination = urljoin(url, headers["location"])
                decision["to"] = destination
                redirect, next_host, next_port = validate_web_url(destination, scope)
                if (redirect.scheme, next_host, next_port) != (parsed.scheme, host, port):
                    raise ScopeError("Redirect changes the explicitly approved origin")
                decision["decision"] = "same_origin_not_followed"
            except (ValueError, ConfigurationError) as exc:
                decision["decision"] = "blocked"
                result.update(status="partial", error_category="redirect_scope_blocked", error=str(exc))
        # No body is needed for redirects; never request their destination.
        sample = bytearray()
        if not 300 <= response.status < 400:
            while len(sample) < BODY_LIMIT:
                if response.isclosed() is True:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Assessment time budget exceeded")
                read_socket.settimeout(min(READ_TIMEOUT, remaining))
                chunk = response.read1(min(8192, BODY_LIMIT - len(sample)))
                if not chunk:
                    break
                sample.extend(chunk)
                result["http"]["body_bytes_sampled"] = len(sample)
            result["http"].update(body_bytes_sampled=len(sample), body_limit_reached=len(sample) == BODY_LIMIT)
        body = sample.decode("utf-8", errors="replace").lower()
        signatures = {"Server": headers.get("server"), "Powered-By": headers.get("x-powered-by"),
                      "WordPress": "wp-content" if "wp-content" in body else None,
                      "React": "react" if "react" in body else None,
                      "jQuery": "jquery" if "jquery" in body else None}
        result["technologies"] = [{"name": name, "evidence": evidence} for name, evidence in signatures.items() if evidence]
        if not result.get("error"):
            result["status"] = "completed"
    except Exception as exc:
        if isinstance(exc, ssl.SSLCertVerificationError):
            category = "certificate_verification_failed"
            result["tls"] = {"verification": "failed", "error": str(exc),
                             "verify_code": getattr(exc, "verify_code", None)}
        elif isinstance(exc, ssl.SSLError):
            category = "tls_error"
            result["tls"] = {"verification": "failed", "error": str(exc)}
        elif isinstance(exc, TimeoutError):
            category = "connect_timeout" if phase == "connect" else "read_timeout"
        elif isinstance(exc, ConfigurationError):
            category = "configuration_error"
        elif isinstance(exc, ScopeError):
            category = "scope_rejected"
        elif isinstance(exc, ValueError):
            category = "invalid_url"
        elif isinstance(exc, ConnectionRefusedError):
            category = "connection_refused"
        elif isinstance(exc, http.client.HTTPException):
            category = "http_protocol_error"
        elif isinstance(exc, OSError):
            category = "connection_error"
        else:
            category = "assessment_error"
        result.update(status="partial" if result["http"] else "failed", error_category=category, error=str(exc))
    finally:
        if response is not None:
            response.close()
        if conn is not None:
            conn.close()
    return result

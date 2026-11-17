"""Deterministic web observations derived only from saved HTTP/TLS evidence."""

HEADER_RULES = {
    "HSTS": ("WEB-HDR-001", "On verified HTTPS, configure Strict-Transport-Security with a positive max-age after checking subdomain readiness."),
    "Content-Security-Policy": ("WEB-HDR-002", "Review a Content-Security-Policy for this application; test a restrictive policy in report-only mode before enforcing it."),
    "X-Content-Type-Options": ("WEB-HDR-003", "Return X-Content-Type-Options: nosniff and correct Content-Type values."),
    "X-Frame-Options": ("WEB-HDR-004", "Review framing requirements; use CSP frame-ancestors and, where appropriate, X-Frame-Options: DENY or SAMEORIGIN."),
    "Referrer-Policy": ("WEB-HDR-005", "Choose a supported Referrer-Policy, for example strict-origin-when-cross-origin, based on application requirements."),
    "Permissions-Policy": ("WEB-HDR-006", "Review browser features in use and set a Permissions-Policy restricting unneeded features."),
}


def build_web_findings(assessment):
    assessment = assessment or {}
    findings = []
    for check in assessment.get("checks", []):
        if check.get("status") not in {"missing", "misconfigured"} or check.get("name") not in HEADER_RULES:
            continue
        rule, remediation = HEADER_RULES[check["name"]]
        findings.append({
            "id": rule, "rule_id": rule,
            "title": f"Web configuration observation: {check['name']} ({check['status']})",
            "severity": "info", "confidence": "high", "confidence_scope": "saved response header only",
            "asset": assessment.get("url", "web target"), "source": "HTTP assessment",
            "domain": "web", "category": "configuration_observation", "verification_status": "observed",
            "evidence": check.get("detail", ""),
            "original_evidence": {"http": assessment.get("http", {}), "check": check},
            "reason": "Saved response configuration; application impact and exploitation are not established.",
            "remediation": remediation,
            "retest": f"Explicitly run another Web assessment of the same approved URL; inspect {check['name']} in the saved response headers and review its value. Opening saved results does not re-test.",
        })
    if assessment.get("error_category") == "certificate_verification_failed":
        findings.append({
            "id": "WEB-TLS-001", "rule_id": "WEB-TLS-001", "title": "TLS certificate verification failed",
            "severity": "low", "confidence": "high", "confidence_scope": "local trust and IP identity verification",
            "asset": assessment.get("url", "web target"), "source": "Verified TLS handshake",
            "domain": "web", "category": "configuration_observation", "verification_status": "observed",
            "evidence": assessment.get("error", "Certificate verification failed"),
            "original_evidence": assessment.get("tls", {}),
            "reason": "The local client could not verify the certificate; this does not establish interception or exploitation.",
            "remediation": "Review the reported validation error, certificate dates, chain, trusted issuer and IP SAN. Install a valid matching certificate or deliberately trust the local issuing CA; keep verification enabled.",
            "retest": "Explicitly run another Web assessment of the same approved HTTPS URL. Expect tls.verification=verified and HTTP evidence; do not bypass verification. Opening saved results does not re-test.",
        })
    return findings

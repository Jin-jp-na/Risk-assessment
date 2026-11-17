"""Deterministic presentation of saved observations. No probes or CVE confirmation."""


def normalized_observation(host: str, service: dict) -> dict:
    return {"host": host, **{key: service.get(key) for key in
            ("protocol", "port", "state", "service", "product", "version", "evidence")}}


def normalize_nvd_candidates(block: dict, service: dict) -> dict:
    """Keyword results never prove applicability, even if labeled verified upstream."""
    candidates = []
    for item in block.get("cves") or []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        reason = "Keyword matching does not establish product/version applicability."
        if not service.get("version"):
            reason += " The observed version is unknown."
        if not service.get("product"):
            reason += " The observed product is unknown."
        candidates.append({**item, "verification_status": "unverified", "confidence": "low",
                           "applicability": {"status": "unverified", "reason": reason},
                           "reported_severity": item.get("reported_severity", item.get("severity")),
                           "reported_cvss": item.get("reported_cvss", item.get("score")),
                           "original": item.get("original") if isinstance(item.get("original"), dict) else dict(item),
                           "severity": "info", "score": None,
                           "match_method": "keyword"})
    return {**block, "keyword": block.get("keyword"), "cves": candidates,
            "status": "unverified_candidates" if candidates else block.get("status", "not_queried")}


def build_network_findings(parsed: dict) -> list[dict]:
    findings = []
    for host in parsed.get("hosts", []):
        ip = host.get("ip")
        if not ip:
            continue
        for service in host.get("services", []):
            if service.get("state") != "open":
                continue
            port = service.get("port")
            protocol = service.get("protocol", "tcp")
            asset = f"{'[' + ip + ']' if ':' in ip else ip}:{port}/{protocol}"
            observation = normalized_observation(ip, service)
            evidence = service.get("evidence") or {}
            original = evidence.get("original", {})
            raw_state = (original.get("state") or {}).get("@state")
            state_confidence = "high" if raw_state == "open" and evidence.get("sha256") else "low"
            base = {"domain": "network", "asset": asset, "severity": "info", "confidence_scope": "port_state_only",
                    "observation": observation, "original_evidence": evidence, "cvss": None}
            reason = "Nmap recorded this port as open. An open service is not a confirmed vulnerability."
            if not service.get("version"):
                reason += " Version is unknown; no CVE applicability can be established."
            findings.append({**base, "id": f"OBS-{ip}-{protocol}-{port}", "category": "observation",
                             "rule_id": "NET-OPEN-001", "title": f"Observed open service: {service.get('service') or 'unidentified'}",
                             "confidence": state_confidence, "verification_status": "observed",
                             "evidence": f"{asset} state=open; product={service.get('product') or 'unknown'}; version={service.get('version') or 'unknown'}",
                             "reason": reason, "remediation": "Confirm the service is required and restrict access to authorized clients.",
                             "source": "Nmap XML"})
            for script in service.get("nse_findings", []):
                if not script.get("output"):
                    continue
                findings.append({**base, "id": f"NSE-{script.get('id')}-{ip}-{protocol}-{port}",
                                 "category": "script_observation", "rule_id": "NET-NSE-REVIEW-001",
                                 "confidence_scope": "vulnerability_interpretation",
                                 "title": f"NSE output for review: {script.get('id')}",
                                 "confidence": "low", "verification_status": "unreviewed",
                                 "evidence": script["output"],
                                 "reason": "A script produced output; no script-specific positive-evidence rule has confirmed a vulnerability.",
                                 "remediation": "Review the original script output and vendor documentation before making a vulnerability claim.",
                                 "source": "Nmap NSE"})
            block = normalize_nvd_candidates(service.get("nvd") or {}, service)
            for candidate in block["cves"]:
                findings.append({**base, "id": f"{candidate['id']}-{ip}-{protocol}-{port}",
                                 "cve_id": candidate["id"], "category": "candidate_vulnerability",
                                 "rule_id": "NET-CVE-KEYWORD-001", "title": f"Unverified CVE candidate: {candidate['id']}",
                                 "confidence": "low", "verification_status": "unverified",
                                 "confidence_scope": "CVE_applicability",
                                 "reported_severity": candidate["reported_severity"], "reported_cvss": candidate["reported_cvss"],
                                 "applicability": candidate["applicability"],
                                 "evidence": f"Keyword={block.get('keyword') or 'not recorded'}; candidate description: {candidate.get('description') or 'not recorded'}",
                                 "reason": candidate["applicability"]["reason"],
                                 "candidate_evidence": dict(candidate),
                                 "remediation": "Verify the installed product, exact version, vendor advisory and affected-version conditions before treating this candidate as applicable.",
                                 "source": "NVD keyword match (unverified)"})
    return findings

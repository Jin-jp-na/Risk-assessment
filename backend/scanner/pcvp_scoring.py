"""Compatibility fields express exposure review priority, never flaw severity."""

from typing import Any, Dict

SENSITIVE_SERVICES = {"ssh", "rdp", "mysql", "mssql", "postgresql", "smb"}


def pcvp_score_for_service(service: Dict[str, Any], exposure: str) -> Dict[str, Any]:
    if service.get("state") != "open":
        score = 0
        reasons = ["This port was not observed open; review its recorded state."]
    else:
        score = 10
        reasons = ["Observed open port (+10 review priority); this does not establish a vulnerability."]
        if (service.get("service") or "").lower() in SENSITIVE_SERVICES or service.get("port") in {22, 3389, 3306, 1433, 5432, 445}:
            score += 10
            reasons.append("Administrative/data service (+10 review priority); no credential or compromise claim.")
        if exposure == "external":
            score += 5
            reasons.append("External exposure context (+5) is supplied/inferred context, not verified internet reachability.")
        if not service.get("version"):
            reasons.append("Version unknown; CVE applicability is unverified.")
        if (service.get("nvd") or {}).get("cves"):
            reasons.append("CVE keyword candidates do not increase severity or review priority.")
    return {"pcvp_score": score, "pcvp_level": "low" if score else "informational",
            "pcvp_reasons": reasons, "score_kind": "exposure_review_priority",
            "severity": "info", "verification_status": "observed" if score else "not_open"}

from typing import Dict, Any, List

SENSITIVE_SERVICES = {"ssh", "rdp", "mysql", "mssql", "postgresql", "smb"}
WEB_SERVICES = {"http", "https"}


def base_risk(service: Dict[str, Any]) -> int:
    name = (service.get("service") or "").lower()
    port = service.get("port")
    if name in SENSITIVE_SERVICES or port in {22, 3389, 3306, 5432, 1433}:
        return 25
    if name in WEB_SERVICES or port in {80, 443, 8080, 8443}:
        return 20
    return 10


def exposure_risk(exposure: str) -> int:
    if exposure == "external":
        return 25
    if exposure == "internal":
        return 10
    return 15  # unknown / mixed


def exploitability_risk(nvd_block: Dict[str, Any]) -> int:
    cves = nvd_block.get("cves", []) if nvd_block else []
    if not cves:
        return 0

    max_sev = "LOW"
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    for c in cves:
        sev = (c.get("severity") or "").upper()
        if sev in order and order.index(sev) > order.index(max_sev):
            max_sev = sev

    if max_sev == "CRITICAL":
        return 25
    if max_sev == "HIGH":
        return 20
    if max_sev == "MEDIUM":
        return 10
    return 5  # LOW


def privilege_risk(service: Dict[str, Any]) -> int:
    name = (service.get("service") or "").lower()
    # simple assumption: these typically grant high privileges if taken over
    if name in {"ssh", "rdp", "smb", "mysql", "mssql", "postgresql"}:
        return 20
    if name in WEB_SERVICES:
        return 10
    return 5  # unknown


def heuristic_credential_risk(service: Dict[str, Any]) -> int:
    name = (service.get("service") or "").lower()
    if name in {"ftp", "ssh", "telnet", "rdp", "smb", "vnc"}:
        return 10
    return 0


def confirmed_credential_risk(service: Dict[str, Any]) -> int:
    """
    If later you add real testing (weak_creds module) store result as:
    service["weak_creds"] = {"found": True/False}
    """
    weak = (service.get("weak_creds") or {}).get("found", False)
    return 25 if weak else 0


def attack_path_risk(service: Dict[str, Any], exposure: str) -> int:
    name = (service.get("service") or "").lower()
    # external sensitive services are entry points
    if exposure == "external" and (name in SENSITIVE_SERVICES or name in WEB_SERVICES):
        return 10
    # later you can add logic for lateral movement, etc.
    return 0


def clamp(score: int) -> int:
    return max(0, min(100, score))


def pcvp_score_for_service(service: Dict[str, Any], exposure: str) -> Dict[str, Any]:
    nvd_block = service.get("nvd", {}) or {}

    b = base_risk(service)
    e = exposure_risk(exposure)
    ex = exploitability_risk(nvd_block)
    p = privilege_risk(service)
    cred_h = heuristic_credential_risk(service)
    cred_c = confirmed_credential_risk(service)
    path = attack_path_risk(service, exposure)

    total = b + e + ex + p + cred_h + cred_c + path
    total = clamp(total)

    # Map numeric score to a label
    if total >= 80:
        level = "critical"
    elif total >= 60:
        level = "high"
    elif total >= 40:
        level = "medium"
    elif total >= 20:
        level = "low"
    else:
        level = "informational"

    reasons: List[str] = [
        f"Base service/port risk: {b}",
        f"Exposure ({exposure}): {e}",
    ]
    if ex > 0:
        reasons.append(f"Exploitability from NVD CVEs: {ex}")
    if p > 0:
        reasons.append(f"Privilege impact: {p}")
    if cred_h > 0:
        reasons.append("Service type commonly affected by weak/default credentials.")
    if cred_c > 0:
        reasons.append("Confirmed weak/default credentials detected.")
    if path > 0:
        reasons.append("Service is a likely entry point in an attack path.")

    return {
        "pcvp_score": total,
        "pcvp_level": level,
        "pcvp_reasons": reasons,
    }
from typing import Any, Dict, List, Optional

from .nvd_client import query_nvd_by_keyword


def build_keyword_from_service(product: Optional[str], version: Optional[str]) -> Optional[str]:
    """
    Build a NVD keyword string from Nmap service info.
    Example: product='OpenSSH', version='6.6.1p1 Ubuntu 2ubuntu2.13'
    -> 'OpenSSH 6.6.1'
    """
    if not product:
        return None
    if not version:
        return product

    # Take just the first version-like token, e.g. '6.6.1p1' -> '6.6.1'
    first = version.split()[0]
    # Strip trailing non-digit characters (p1, etc.)
    cleaned = ""
    for ch in first:
        if ch.isdigit() or ch == ".":
            cleaned += ch
        else:
            break

    if cleaned:
        return f"{product} {cleaned}"
    return f"{product} {first}"


def extract_cve_summaries(nvd_response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Take raw NVD CVE response and extract a small list of {id, severity, score, description}.
    """
    results: List[Dict[str, Any]] = []

    for item in nvd_response.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        # description
        desc_list = cve.get("descriptions", [])
        description = ""
        if desc_list:
            description = desc_list[0].get("value", "")

        metrics = cve.get("metrics", {})
        severity = None
        score = None

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            score = cvss.get("baseScore")
            severity = metrics["cvssMetricV2"][0].get("baseSeverity")

        results.append(
            {
                "id": cve_id,
                "severity": severity,
                "score": score,
                "description": description,
            }
        )

    return results


def enrich_service_with_nvd(product: Optional[str], version: Optional[str]) -> Dict[str, Any]:
    """
    For a given service product/version, query NVD and return a dict:
    { "keyword": "...", "cves": [ {id, severity, score, description}, ... ] }
    """
    keyword = build_keyword_from_service(product, version)
    if not keyword:
        return {"keyword": None, "cves": []}

    try:
        raw = query_nvd_by_keyword(keyword)
        cves = extract_cve_summaries(raw)
        return {"keyword": keyword, "cves": cves}
    except Exception as e:
        print(f"[NVD] Error enriching {keyword}: {e}")
        return {"keyword": keyword, "error": str(e), "cves": []}
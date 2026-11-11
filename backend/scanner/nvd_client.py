import os
from typing import Any, Dict, Optional

import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_nvd_api_key() -> Optional[str]:
    """
    Read NVD API key from environment variable NVD_API_KEY.
    """
    return os.getenv("NVD_API_KEY")


def query_nvd_by_keyword(keyword: str, results_per_page: int = 5) -> Dict[str, Any]:
    """
    Query NVD by free-text keyword, e.g. 'OpenSSH 6.6.1'.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    headers: Dict[str, str] = {}

    api_key = get_nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.Timeout:
        return {"vulnerabilities": []}
    except Exception as e:
        return {"vulnerabilities": []}
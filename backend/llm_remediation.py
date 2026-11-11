from __future__ import annotations

from typing import Any, Dict, List
import json
import os
import hashlib
import time

from google import genai

CACHE_FILE = "llm_cache.json"
LAST_CALL_TS = 0


def _load_cache() -> Dict[str, Any]:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f)


def _cache_key(svc: Dict[str, Any], exposure: str) -> str:
    raw = json.dumps(
        {
            "ip": svc.get("ip"),
            "port": svc.get("port"),
            "proto": svc.get("protocol"),
            "service": svc.get("service"),
            "product": svc.get("product"),
            "version": svc.get("version"),
            "exposure": exposure,
        },
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _rate_limit(seconds: int = 5) -> None:
    global LAST_CALL_TS
    now = time.time()
    if now - LAST_CALL_TS < seconds:
        raise Exception("LLM rate limit: wait a few seconds")
    LAST_CALL_TS = now


def _extract_cves(svc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Your svc["nvd"] structure depends on enrich_service_with_nvd().
    This function tries multiple shapes safely.
    """
    nvd = svc.get("nvd") or {}
    for key in ("cves", "items", "results", "vulns"):
        if isinstance(nvd.get(key), list):
            return nvd[key]
    if isinstance(svc.get("mapped_cves"), list):
        return svc["mapped_cves"]
    return []


def build_prompt(svc: Dict[str, Any], exposure: str) -> str:
    cves = _extract_cves(svc)[:3]  # even smaller
    cve_lines = []
    for c in cves:
        cve_id = c.get("cve_id") or c.get("id") or c.get("cve") or "UNKNOWN"
        sev = c.get("severity") or "UNK"
        score = c.get("score") or c.get("cvss") or c.get("cvss_score") or ""
        cve_lines.append(f"{cve_id}|{sev}|{score}")

    weak = svc.get("weak_creds") or {}
    weak_line = "none"
    if isinstance(weak, dict) and weak.get("found"):
        weak_line = f"{weak.get('protocol','?')} {weak.get('username','?')}:{weak.get('password','?')}"

    return (
        "RETURN JSON ONLY. MAX 3 steps, MAX 1 verification.\n"
        "No extra keys. No markdown. Only this service.\n"
        f"exposure={exposure}; ip={svc.get('ip')}; port={svc.get('port')}/{svc.get('protocol')}; "
        f"svc={svc.get('service')}; product={svc.get('product')}; version={svc.get('version')}; "
        f"pcvp={svc.get('pcvp_score')} {svc.get('pcvp_level')}; weak={weak_line}; "
        f"cves={';'.join(cve_lines) if cve_lines else 'none'}\n"
        'OUTPUT: {"summary":"","priority":"critical|high|medium|low|info","steps":[""],"verification":[""],"references":[""]}'
    )


def generate_remediation_openai(
    svc: Dict[str, Any], exposure: str, model: str = "gemini-2.5-flash-lite"
) -> Dict[str, Any]:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return {
            "summary": "GEMINI_API_KEY not set.",
            "priority": "info",
            "steps": ["Set GEMINI_API_KEY environment variable and restart the server."],
            "verification": [],
            "references": [],
        }

    client = genai.Client(api_key=api_key)
    prompt = build_prompt(svc, exposure)

    # Cache check
    cache = _load_cache()
    key = _cache_key(svc, exposure)
    if key in cache:
        return cache[key]

    # Rate limit
    _rate_limit(5)

    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config={
            "temperature": 0.1,
            "max_output_tokens": 200,
            "response_mime_type": "application/json",
        },
    )

    text = (resp.text or "").strip()

    try:
        result = json.loads(text)
    except Exception:
        result = {
            "summary": "LLM output was not valid JSON (fallback).",
            "priority": "info",
            "steps": [],
            "verification": [],
            "references": [],
            "raw": text,
        }

    cache[key] = result
    _save_cache(cache)
    return result
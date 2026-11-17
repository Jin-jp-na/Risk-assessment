"""Offline normalization of saved evidence. No network, scanning or process calls."""

from copy import deepcopy
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
TERMINAL = {"completed", "failed", "partial", "cancelled", "timed_out", "skipped"}


def validate_snapshot(snapshot, scan_id):
    if snapshot.get("schema_version") != SCHEMA_VERSION or snapshot.get("scan_id") != scan_id:
        raise ValueError("Unsupported snapshot version or mismatched scan ID")
    if not all(isinstance(snapshot.get(key), dict) for key in ("metadata", "identity", "components")):
        raise ValueError("Snapshot metadata/identity is missing")
    if not isinstance(snapshot["identity"].get("targets"), list) or any(not isinstance(target, str) for target in snapshot["identity"]["targets"]):
        raise ValueError("Invalid snapshot target identities")
    if not isinstance(snapshot.get("findings"), list) or any(
            not isinstance(item, dict) or item.get("severity") not in {"critical", "high", "medium", "low", "info"}
            for item in snapshot["findings"]):
        raise ValueError("Invalid persisted findings")
    for name in ("network", "http", "tls", "paths"):
        component = snapshot.get("components", {}).get(name)
        if not isinstance(component, dict) or component.get("status") not in {"completed", "partial", "failed", "not_run"}:
            raise ValueError(f"Invalid {name} component coverage")
    network, http, tls, paths = (snapshot["components"][name] for name in ("network", "http", "tls", "paths"))
    if not all(isinstance(value, list) for value in (network.get("hosts"), network.get("observations"), paths.get("observations"))):
        raise ValueError("Invalid observations")
    if not all(isinstance(value, dict) for value in (network.get("parsed"), network.get("coverage"), http.get("headers"), http.get("response"), tls.get("details"), paths.get("coverage"))):
        raise ValueError("Invalid component evidence")
    if any(not isinstance(item, dict) or not isinstance(item.get("port"), int)
           or not isinstance(item.get("protocol"), str) or not isinstance(item.get("host"), (str, type(None)))
           for item in network["observations"]):
        raise ValueError("Invalid port observation")
    if any(not isinstance(item, dict) or not isinstance(item.get("path"), str) for item in paths["observations"]):
        raise ValueError("Invalid path observation")
    return snapshot


def origin(url):
    if not url:
        return None
    value = urlsplit(url)
    host = value.hostname.lower().rstrip(".") if value.hostname else ""
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
            raise ValueError("Saved web host is invalid")
    if value.scheme not in {"http", "https"} or value.username or value.password:
        raise ValueError("Saved web origin is invalid")
    return {"scheme": value.scheme, "host": host, "port": value.port or (443 if value.scheme == "https" else 80)}


def target_key(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return str(ipaddress.ip_network(value, strict=True)) if "/" in value and "://" not in value else str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower().rstrip(".")


def read_json(path):
    if not path.exists():
        return None
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError(f"Saved artifact too large: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected an object in {path.name}")
    return value


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _component(status, evidence, reason):
    return {"status": status, "reason": reason, **evidence}


def normalize_scan(metadata, parsed=None, audit=None, paths=None, path_record=None, nmap_record=None, artifacts=None, words=None):
    """Do not infer completion from a nonempty artifact or an overall success alone."""
    meta = deepcopy(metadata)
    parsed, audit = deepcopy(parsed or {"hosts": [], "observations": []}), deepcopy(audit or {})
    path_record, nmap_record = path_record or {}, nmap_record or {}
    raw_network = meta.get("nmap_status") or nmap_record.get("status")
    has_network = bool(parsed.get("hosts")) or bool(parsed.get("coverage"))
    if meta.get("network_scan") is False or raw_network in {"skipped", "not_run"}:
        network_state = "not_run"
    elif (raw_network == "completed" and has_network and parsed.get("coverage", {}).get("run_completed")
          and not any(host.get("timed_out") for host in parsed.get("hosts", []))):
        network_state = "completed"
    elif raw_network in {"failed", "timed_out", "cancelled"}:
        network_state = "partial" if has_network else "failed"
    else:
        network_state = "partial" if has_network else ("not_run" if raw_network is None else "failed")
    http = audit.get("http") or {}
    http_state = ("completed" if isinstance(http.get("status"), int) and 200 <= http["status"] < 400
                  and isinstance(http.get("headers"), dict) and not audit.get("error") else
                  "partial" if http.get("status") is not None else "failed" if audit else "not_run")
    tls = audit.get("tls") or {}
    web_origin = origin(meta.get("web_url") or audit.get("url"))
    tls_state = ("completed" if tls.get("verification") == "verified" else
                 "failed" if tls.get("verification") == "failed" or tls.get("error") else
                 "partial" if tls.get("protocol") else "not_run")
    raw_paths = path_record.get("status") or meta.get("gobuster_status")
    if path_record.get("enabled") is False:
        path_state = "not_run"
    elif raw_paths == "completed" and paths is not None:
        path_state = "completed"
    elif raw_paths in {"failed", "timed_out", "cancelled"}:
        path_state = "partial" if paths else "failed"
    else:
        path_state = "partial" if paths else "not_run"
    requested = meta.get("ports")
    coverage = deepcopy(parsed.get("coverage") or {})
    coverage["requested_ports"] = requested
    coverage["profile"] = meta.get("profile")
    targets = meta.get("authorized_targets") or [host.get("ip") for host in parsed.get("hosts", []) if host.get("ip")]
    if not targets:
        try:
            targets = [str(ipaddress.ip_address(meta.get("target")))]
        except (ValueError, TypeError):
            targets = [web_origin["host"]] if web_origin else []
    components = {
        "network": _component(network_state, {"coverage": coverage, "hosts": parsed.get("hosts", []),
                          "observations": parsed.get("observations", []), "parsed": parsed},
                          f"Recorded network state: {raw_network or 'unknown legacy coverage'}"),
        "http": _component(http_state, {"origin": web_origin, "response": http, "headers": {
                           str(key).lower(): value for key, value in (http.get("headers") or {}).items()},
                           "redirects": audit.get("redirects", []), "error": audit.get("error"),
                           "error_category": audit.get("error_category")}, "Saved HTTP response coverage"),
        "tls": _component(tls_state, {"origin": web_origin, "details": tls}, "Saved verified TLS evidence"),
        "paths": _component(path_state, {"origin": web_origin, "observations": paths or [],
                             "coverage": {"words": words, "method": "gobuster-dir-no-follow-v1" if words is not None else None},
                             "job_status": raw_paths}, "Optional discovery coverage; absence is not a vulnerability verdict"),
    }
    states = [item["status"] for item in components.values()]
    status = ("partial" if "partial" in states or ("failed" in states and "completed" in states) else
              "failed" if "failed" in states or meta.get("status") == "failed" else
              "completed" if "completed" in states else "not_run")
    return {"schema_version": SCHEMA_VERSION, "scan_id": meta["scan_id"], "target": meta.get("target"),
            "timestamp": meta.get("completed_at") or meta.get("created_at"), "created_at": meta.get("created_at"),
            "status": status, "job_status": meta.get("status"), "identity": {"target_key": target_key(meta.get("target")), "targets": sorted(set(targets)), "web_origin": web_origin},
            "components": components, "findings": [], "metadata": meta,
            "raw_evidence": {"artifacts": artifacts or [], "http_assessment": audit,
                             "nmap_execution": nmap_record, "path_execution": path_record}}


def artifact_manifest(directory, names):
    result = []
    for name in names:
        path = directory / name
        if path.is_file():
            result.append({"file": name, "bytes": path.stat().st_size,
                           "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return result

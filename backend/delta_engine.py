"""Compare evidence only. Missing coverage never proves an exposure was fixed."""

SECURITY_HEADERS = {"strict-transport-security", "content-security-policy", "x-content-type-options",
                    "x-frame-options", "referrer-policy", "permissions-policy"}


class IncompatibleScans(ValueError):
    pass


def _closed(network, key):
    host, protocol, port = key
    for observation in network.get("observations", []):
        if (observation.get("host"), observation.get("protocol"), observation.get("port")) == key:
            return observation.get("state") == "closed"
    # Only unambiguous closed extraports for an up host justify an omitted port.
    coverage = network.get("coverage", {})
    scanned = coverage.get("scanned_ports", {}).get(protocol, [])
    if port not in scanned:
        return False
    for item in network.get("hosts", []):
        if item.get("ip") == host:
            explicit = sum(1 for value in network.get("observations", []) if value.get("host") == host and value.get("protocol") == protocol)
            return (len(coverage.get("scanned_ports", {})) == 1 and item.get("state") == "up"
                    and item.get("omitted_port_states") == ["closed"]
                    and item.get("omitted_port_count") == len(scanned) - explicit > 0)
    return False


def compare_snapshots(old, new):
    if old.get("identity", {}).get("target_key") != new.get("identity", {}).get("target_key"):
        raise IncompatibleScans("Requested target identities differ")
    if not old.get("identity", {}).get("targets") or old.get("identity", {}).get("targets") != new.get("identity", {}).get("targets"):
        raise IncompatibleScans("Saved target identities differ or are unknown")
    old_origin, new_origin = old["identity"].get("web_origin"), new["identity"].get("web_origin")
    if old_origin and new_origin and old_origin != new_origin:
        raise IncompatibleScans("Web scheme, IP and port must match")
    result = {"schema_version": 1, "old_id": old["scan_id"], "new_id": new["scan_id"],
              "target": new.get("target"), "added": [], "removed": [], "changed": [], "uncertain": [], "coverage": {}}

    def event(bucket, component, kind, key, before, after, reason):
        result[bucket].append({"component": component, "kind": kind, "key": str(key),
                               "before": before, "after": after, "reason": reason,
                               "interpretation": "Exposure observation change; no vulnerability or remediation confirmation."})

    def compatible(component):
        a, b = old["components"][component], new["components"][component]
        okay = a["status"] == b["status"] == "completed"
        if component != "network":
            okay = okay and bool(a.get("origin")) and a.get("origin") == b.get("origin")
        if component == "paths":
            okay = okay and a.get("coverage") == b.get("coverage") and a.get("coverage", {}).get("words") is not None
        if component == "http":
            okay = okay and a.get("response", {}).get("status") == b.get("response", {}).get("status")
        result["coverage"][component] = {"before": a["status"], "after": b["status"], "compatible": okay}
        if not okay:
            event("uncertain", component, "coverage", component, a["status"], b["status"],
                  "Component not completed on both scans, origin differs, or discovery coverage is unknown/different; no absence or fix inferred.")
        return a, b, okay

    a, b, okay = compatible("network")
    before = {(o.get("host"), o.get("protocol"), o.get("port")): o for o in a.get("observations", [])}
    after = {(o.get("host"), o.get("protocol"), o.get("port")): o for o in b.get("observations", [])}
    for key in sorted(before.keys() | after.keys(), key=str):
        left, right = before.get(key), after.get(key)
        lo, ro = left and left.get("state") == "open", right and right.get("state") == "open"
        if lo and not ro:
            event("removed" if okay and _closed(b, key) else "uncertain", "network", "open_port", key, left, right,
                  "No longer observed open; closure requires completed explicit closed evidence or unambiguous closed coverage.")
        elif ro and not lo:
            event("added" if okay and _closed(a, key) else "uncertain", "network", "open_port", key, left, right,
                  "New open observation; baseline must have assessed this port as closed to establish a change.")
        elif lo and ro:
            for field in ("service", "product", "version"):
                lv, rv = left.get(field), right.get(field)
                if lv != rv:
                    event("changed" if okay and lv and rv else "uncertain", "network", field, key, lv, rv,
                          "Scanner-reported service identity; unknown values are not evidence of removal or upgrade.")
    a, b, okay = compatible("http")
    for header in sorted(SECURITY_HEADERS):
        lv, rv = a.get("headers", {}).get(header), b.get("headers", {}).get(header)
        if lv != rv:
            bucket = "added" if lv is None else "removed" if rv is None else "changed"
            event(bucket if okay else "uncertain", "http", "security_header", header, lv, rv, "Saved response-header values; application impact requires review.")
    a, b, okay = compatible("tls")
    for field in ("verification", "protocol", "cipher", "subject", "issuer", "expires", "not_before", "serial_number", "subject_alt_names", "certificate_sha256"):
        lv, rv = a.get("details", {}).get(field), b.get("details", {}).get(field)
        if lv != rv:
            event("changed" if okay and lv is not None and rv is not None else "uncertain", "tls", "tls_metadata", field, lv, rv,
                  "Observed TLS connection/certificate difference; failed verification cannot establish remediation.")
    a, b, okay = compatible("paths")
    before = {o["path"]: o for o in a.get("observations", [])}
    after = {o["path"]: o for o in b.get("observations", [])}
    for key in sorted(before.keys() | after.keys()):
        left, right = before.get(key), after.get(key)
        if left is None or right is None:
            event(("added" if left is None else "removed") if okay else "uncertain", "paths", "path_observation", key, left, right,
                  "Path observed/not observed under matching limited discovery coverage; sensitivity and vulnerability are not established.")
        elif left.get("status") != right.get("status"):
            event("changed" if okay else "uncertain", "paths", "path_status", key, left, right, "Saved HTTP status changed for this path.")
    result["summary"] = {key: len(result[key]) for key in ("added", "removed", "changed", "uncertain")}
    return result

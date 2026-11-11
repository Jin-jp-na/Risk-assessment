from typing import Dict, Any, List, Tuple

def _extract_cves(svc: Dict[str, Any]) -> List[Dict[str, Any]]:
    nvd = svc.get("nvd") or {}
    for key in ("cves", "items", "results", "vulns"):
        if isinstance(nvd.get(key), list):
            return nvd[key]
    if isinstance(svc.get("mapped_cves"), list):
        return svc["mapped_cves"]
    return []

def build_attack_graph(parsed_scan: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    node_ids = set()
    edge_keys = set()

    def add_node(n: Dict[str, Any]) -> None:
        nid = n.get("id")
        if not nid or nid in node_ids:
            return
        node_ids.add(nid)
        nodes.append(n)

    def add_edge(e: Dict[str, Any]) -> None:
        k = (e.get("from"), e.get("to"), e.get("relation"))
        if None in k or k in edge_keys:
            return
        edge_keys.add(k)
        edges.append(e)

    def host_id(ip: str) -> str:
        return f"host:{ip}"

    def service_id(ip: str, svc: Dict[str, Any]) -> str:
        return f"svc:{ip}:{svc.get('port')}/{svc.get('protocol', 'tcp')}"

    hosts = parsed_scan.get("hosts", [])
    for host in hosts:
        ip = host.get("ip")
        if not ip:
            continue

        add_node({"id": host_id(ip), "type": "host", "ip": ip})

        for svc in host.get("services", []):
            sid = service_id(ip, svc)

            add_node({
                "id": sid,
                "type": "service",
                "ip": ip,
                "port": svc.get("port"),
                "protocol": svc.get("protocol"),
                "service": svc.get("service"),
                "pcvp_score": svc.get("pcvp_score"),
                "pcvp_level": svc.get("pcvp_level"),
            })

            add_edge({"from": host_id(ip), "to": sid, "relation": "runs"})

            # ✅ Use robust CVE extraction
            for c in _extract_cves(svc):
                cve_value = (c.get("cve_id") or c.get("id") or c.get("cve") or "").strip()
                if not cve_value:
                    continue  # prevents cve:unknown duplicates

                cid = f"cve:{cve_value}"
                add_node({
                    "id": cid,
                    "type": "cve",
                    "cve_id": cve_value,
                    "severity": c.get("severity"),
                    "cvss": c.get("cvss") or c.get("score"),
                })
                add_edge({"from": sid, "to": cid, "relation": "has_vulnerability"})

    high_services: List[Tuple[Dict[str, Any], Dict[str, Any]]] = [
        (host, svc) for host in hosts
        for svc in host.get("services", [])
        if (svc.get("pcvp_level") in {"high", "critical"})
    ]
    for idx, (host_a, svc_a) in enumerate(high_services):
        ip_a = host_a.get("ip")
        if not ip_a:
            continue
        sid_a = service_id(ip_a, svc_a)

        for host_b, svc_b in high_services[idx + 1:]:
            ip_b = host_b.get("ip")
            if not ip_b:
                continue
            sid_b = service_id(ip_b, svc_b)

            add_edge({"from": sid_a, "to": sid_b, "relation": "possible_chain"})

    return {"nodes": nodes, "edges": edges}
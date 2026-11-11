from __future__ import annotations
from typing import Any, Dict, List
from io import BytesIO
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    ListFlowable,
    ListItem,
)

def _safe(v: Any) -> str:
    if v is None:
        return ""
    return str(v)

def _page_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {doc.page}")
    canvas.restoreState()

def build_pdf_report(
    scan_id: str,
    exposure: str,
    parsed: Dict[str, Any],
    attack_graph: Dict[str, Any] | None = None,
    findings: List[Dict[str, Any]] | None = None,
) -> bytes:
    """
    Returns PDF bytes.
    parsed should be the same structure you return in /scan/{scan_id}/nvd:
      {"hosts":[{"ip":..., "services":[...]}]}
    attack_graph: output of build_attack_graph()
    """
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    h3 = styles["Heading3"]
    body = styles["BodyText"]

    story = []

    # Title
    story.append(Paragraph("RiskLens Security Assessment Report", h1))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(f"<b>Scan ID:</b> {scan_id}", body))
    story.append(Paragraph(f"<b>Exposure:</b> {exposure}", body))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now(timezone.utc).isoformat()}", body))
    story.append(Spacer(1, 0.6 * cm))

    # Flatten services
    hosts = parsed.get("hosts", []) or []
    services_flat: List[Dict[str, Any]] = []
    for h in hosts:
        for s in (h.get("services") or []):
            services_flat.append({**s, "ip": h.get("ip")})

    critical = sum(1 for s in services_flat if (s.get("pcvp_level") == "critical"))
    high = sum(1 for s in services_flat if (s.get("pcvp_level") == "high"))
    weak = sum(1 for s in services_flat if (s.get("weak_creds") or {}).get("found"))

    # Executive summary
    story.append(Paragraph("Executive Summary", h2))
    summary_table = Table(
        [
            ["Hosts discovered", str(len(hosts))],
            ["Services detected", str(len(services_flat))],
            ["Critical / High services", f"{critical} / {high}"],
            ["Weak credentials findings", str(weak)],
        ],
        colWidths=[8 * cm, 6 * cm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 0.7 * cm))

    # Attack Graph Summary + Chains
    story.append(Paragraph("Attack Graph Summary", h2))
    graph = attack_graph or {}
    nodes = graph.get("nodes", []) or []
    edges = graph.get("edges", []) or []

    host_nodes = [n for n in nodes if n.get("type") == "host"]
    svc_nodes = [n for n in nodes if n.get("type") == "service"]
    cve_nodes = [n for n in nodes if n.get("type") == "cve"]
    vuln_edges = [e for e in edges if e.get("relation") == "has_vulnerability"]
    chain_edges = [e for e in edges if e.get("relation") == "possible_chain"]

    ag_table = Table(
        [
            ["Hosts", str(len(host_nodes))],
            ["Services", str(len(svc_nodes))],
            ["CVEs linked", str(len(cve_nodes))],
            ["Vulnerability edges", str(len(vuln_edges))],
            ["Possible attack chains", str(len(chain_edges))],
        ],
        colWidths=[8 * cm, 6 * cm],
    )
    ag_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
            ]
        )
    )
    story.append(ag_table)
    story.append(Spacer(1, 0.4 * cm))

    node_map = {n.get("id"): n for n in nodes}
    if chain_edges:
        story.append(Paragraph("Attack Chain Candidates (sample)", h3))
        chain_items = []
        for e in chain_edges[:15]:
            a = node_map.get(e.get("from"), {})
            b = node_map.get(e.get("to"), {})
            a_label = f"{_safe(a.get('ip'))}:{_safe(a.get('port'))}/{_safe(a.get('protocol'))}"
            b_label = f"{_safe(b.get('ip'))}:{_safe(b.get('port'))}/{_safe(b.get('protocol'))}"
            chain_items.append(ListItem(Paragraph(f"{a_label} → {b_label}", body)))
        story.append(ListFlowable(chain_items, bulletType="bullet"))
    else:
        story.append(Paragraph("No attack chains detected.", body))

    story.append(Spacer(1, 0.7 * cm))

    # Findings table
    story.append(Paragraph("Prioritized Findings", h2))
    services_flat.sort(key=lambda s: (s.get("pcvp_score") or 0), reverse=True)

    data = [
        ["Host", "Port/Proto", "Service", "Product", "RiskLens", "Weak Creds", "Top CVEs"]
    ]
    for s in services_flat[:50]:
        wc = s.get("weak_creds") or {}
        weak_text = (
            f"{_safe(wc.get('protocol'))} {_safe(wc.get('username'))}:{_safe(wc.get('password'))}"
            if wc.get("found")
            else "None"
        )

        nvd = s.get("nvd") or {}
        cves = nvd.get("cves") or nvd.get("CVEs") or []
        if isinstance(cves, list) and cves:
            cve_text = ", ".join([_safe(cv.get("cve_id") or cv.get("id")) for cv in cves[:3]])
        else:
            cve_text = "None"

        data.append(
            [
                _safe(s.get("ip")),
                f"{_safe(s.get('port'))}/{_safe(s.get('protocol'))}",
                _safe(s.get("service")),
                (_safe(s.get("product")) + " " + _safe(s.get("version"))).strip(),
                f"{_safe(s.get('pcvp_level'))} ({_safe(s.get('pcvp_score'))})",
                weak_text,
                cve_text,
            ]
        )

    table = Table(
        data,
        repeatRows=1,
        colWidths=[3 * cm, 2.5 * cm, 2.5 * cm, 4 * cm, 3 * cm, 4 * cm, 4 * cm],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    if findings:
        story.append(Spacer(1, 0.7 * cm))
        story.append(Paragraph("Evidence-Based Findings", h2))
        finding_data = [["Severity", "Finding", "Asset", "Source"]]
        for finding in findings[:40]:
            finding_data.append([
                _safe(finding.get("severity")),
                _safe(finding.get("title")),
                _safe(finding.get("asset")),
                _safe(finding.get("source")),
            ])
        findings_table = Table(finding_data, repeatRows=1, colWidths=[2.2 * cm, 7 * cm, 4 * cm, 3 * cm])
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("FONT", (0, 0), (-1, -1), "Helvetica", 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(findings_table)

    doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return buf.getvalue()
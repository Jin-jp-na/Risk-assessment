"""Local PDF export from the same saved snapshot/findings used by the UI."""
from io import BytesIO
import json
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer


def _text(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, sort_keys=True)
    return escape(str(value if value is not None else "Not recorded"))


def build_pdf_report(scan_id, exposure, parsed, attack_graph=None, findings=None, snapshot=None, differences=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=42, rightMargin=42,
                            topMargin=42, bottomMargin=42, pageCompression=0)
    styles = getSampleStyleSheet()
    styles["BodyText"].wordWrap = "CJK"
    story = [Paragraph("RiskLens Security Assessment Report", styles["Title"])]

    def line(label, value):
        story.append(Paragraph(f"<b>{_text(label)}:</b> {_text(value)}", styles["BodyText"]))

    def heading(value):
        story.append(Spacer(1, 10))
        story.append(Paragraph(_text(value), styles["Heading2"]))

    line("Scan ID", scan_id)
    line("Exposure", exposure)
    if snapshot:
        for label, value in (("Target", snapshot.get("target")), ("Assessment timestamp", snapshot.get("timestamp")),
                             ("Snapshot status", snapshot.get("status"))):
            line(label, value)
        heading("Component coverage")
        for name, component in snapshot["components"].items():
            line(name, component["status"] + ": " + component.get("reason", ""))
    heading("Interpretation")
    line("Evidence limits", "Open ports and paths are observations. Keyword CVE matches are unverified candidates; advisory severity does not prove applicability. Missing coverage never establishes a fix. Credential testing was not performed.")
    heading("Network observations")
    hosts = parsed.get("hosts", [])
    if not hosts:
        line("Coverage", "No saved network observations; see component completion status.")
    for host in hosts:
        for service in host.get("services", []):
            line(host.get("ip"), {key: service.get(key) for key in ("protocol", "port", "state", "service", "product", "version")})
    findings = findings if findings is not None else (snapshot or {}).get("findings", [])
    for domain, label in (("network", "Network findings and unverified candidates"), ("web", "Web configuration findings")):
        heading(label)
        entries = [item for item in findings if item.get("domain", "network") == domain]
        if not entries:
            line("Findings", "No saved rule findings for this component. This is not proof of security.")
        for finding in entries:
            story.append(Paragraph(_text(finding.get("id", "")) + " - " + _text(finding.get("title", "")), styles["Heading3"]))
            for field in ("severity", "confidence", "confidence_scope", "asset", "verification_status", "evidence", "remediation", "retest"):
                if field in finding:
                    line(field, finding[field])
    if differences:
        heading("Exposure changes from saved baseline " + differences["old_id"])
        line("Summary", differences["summary"])
        for bucket in ("added", "removed", "changed", "uncertain"):
            for item in differences[bucket]:
                line(bucket + " / " + item["component"] + " / " + item["kind"], item["key"])
                line("Before", item["before"])
                line("After", item["after"])
                line("Reason", item["reason"])
    doc.build(story)
    return buffer.getvalue()

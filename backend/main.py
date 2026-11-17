import csv
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import Optional, List
from uuid import uuid4, UUID
import subprocess
import xmltodict
import ipaddress
import json
import hashlib
from xml.parsers.expat import ExpatError
from pathlib import Path
from pydantic import BaseModel, Field
from backend.scanner.scan_policy import (
    ConfigurationError, ScopeError, PROFILES, validate_request, validate_targets,
    normalize_ports, resolve_executable, nmap_command,
)
from backend.scanner.web_assessment import assess_web_url, validate_web_url
from backend.scanner.web_rules import build_web_findings
from backend.snapshots import normalize_scan, read_json, atomic_json, artifact_manifest, validate_snapshot
from backend.delta_engine import compare_snapshots, IncompatibleScans
from backend.scanner.path_discovery import execute_discovery, prepare_wordlist, parse_paths, DiscoveryStopped
from backend.scanner.pcvp_scoring import pcvp_score_for_service
from backend.scanner.network_findings import normalized_observation, normalize_nvd_candidates, build_network_findings
from backend.scanner.attack_graph import build_attack_graph
from starlette.responses import StreamingResponse, Response
from backend.report_generator import build_pdf_report
from io import BytesIO
import io
import threading
from datetime import datetime, timezone


def infer_exposure_from_target(target: str) -> str:
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private:
            return "internal"
        else:
            return "external"
    except ValueError:
        return "external"


BASE_DIR = Path(__file__).resolve().parent
SCANS_DIR = BASE_DIR / "scans"
SCANS_DIR.mkdir(exist_ok=True)
SCAN_STATUS_FILE = SCANS_DIR / "scan_status.json"
GOBUSTER_WORDLIST = BASE_DIR.parent / "wordlists" / "web-safe.txt"

STATUS_LOCK = threading.RLock()
SCAN_SLOTS = threading.BoundedSemaphore(1)
DISCOVERY_STOPS: dict[str, threading.Event] = {}

BOOT_ID = str(uuid4())

templates = Jinja2Templates(directory=str(BASE_DIR.parent / "frontend" / "templates"))


class ScanRequest(BaseModel):
    target: str
    description: Optional[str] = None
    exposure: Optional[str] = "auto"
    ports: Optional[str] = None
    profile: str = "standard"
    authorized: bool = False
    path_discovery: bool = False
    network_scan: bool = True

class ScanStatus(BaseModel):
    scan_id: str
    target: str
    status: str
    message: Optional[str] = None
    exposure: Optional[str] = "auto"
    exposure_effective: Optional[str] = None
    gobuster_status: Optional[str] = "pending"  # track gobuster separately
    profile: str = "standard"
    description: Optional[str] = None
    created_at: str = ""
    completed_at: Optional[str] = None
    ports: Optional[str] = None
    authorized_targets: list[str] = Field(default_factory=list)
    approved_scope: list[str] = Field(default_factory=list)
    authorized: bool = False
    nmap_status: Optional[str] = None
    nmap_exit_code: Optional[int] = None
    path_discovery: bool = False
    network_scan: bool = True
    web_url: Optional[str] = None
    web_status: Optional[str] = None


class WebScanRequest(BaseModel):
    url: str
    description: Optional[str] = None
    authorized: bool = False
    path_discovery: bool = False


class WebScanStatus(BaseModel):
    scan_id: str
    status: str
    message: str

scan_status_store: dict[str, ScanStatus] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_scan_status_store() -> None:
    if not SCAN_STATUS_FILE.exists():
        return
    try:
        data = json.loads(SCAN_STATUS_FILE.read_text(encoding="utf-8"))
        interrupted = False
        for scan_id, raw_status in data.items():
            status = ScanStatus.model_validate(raw_status)
            if not status.created_at:
                status.created_at = _utc_now()
            if status.status in {"pending", "running", "nmap_done"}:
                interrupted = True
                status.status = "failed"
                status.message = "Interrupted by server restart; no automatic scan was resumed."
                status.completed_at = _utc_now()
                if status.nmap_status != "completed":
                    status.nmap_status = "failed"
                if status.gobuster_status in {"pending", "running"}:
                    status.gobuster_status = "skipped" if status.nmap_status == "failed" else "failed"
            scan_status_store[scan_id] = status
        if interrupted:
            _save_scan_status_store()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[SCAN STORE] Failed to load scan status store: {exc}")

def _save_scan_status_store() -> None:
    with STATUS_LOCK:
        data = {k: v.model_dump() for k, v in scan_status_store.items()}
        tmp = SCAN_STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(SCAN_STATUS_FILE)


def run_nmap_scan_multi(scan_id: str, targets: List[str], ports: Optional[str] = None) -> None:
    status = scan_status_store.get(scan_id)
    if status is None:
        return
    output = SCANS_DIR / f"{scan_id}.xml"
    temporary = SCANS_DIR / f"{scan_id}.xml.tmp"
    record_path = SCANS_DIR / f"nmap_{scan_id}.json"
    record = {"scan_id": scan_id, "profile": status.profile, "started_at": _utc_now(),
              "exit_code": None, "stderr": "", "command": [], "xml": None}
    status.status = "running"
    status.nmap_status = "running"
    status.message = "Nmap scan in progress."
    try:
        _save_scan_status_store()
        if not status.authorized:
            raise ScopeError("No recorded authorization for this scan")
        targets = validate_targets(targets, status.approved_scope)
        if targets != status.authorized_targets:
            raise ScopeError("Worker targets do not match the saved authorized target list")
        ports = normalize_ports(ports, status.profile)
        if ports != status.ports:
            raise ScopeError("Worker ports do not match the saved scan request")
        executable = resolve_executable("RISKLENS_NMAP_PATH", "nmap")
        command = nmap_command(executable, targets, status.profile, ports, temporary)
        timeout = PROFILES[status.profile]["timeout"]
        record.update(command=command, timeout_seconds=timeout, targets=targets, ports=ports,
                      approved_scope=status.approved_scope, authorized=status.authorized)
        result = subprocess.run(command, shell=False, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        status.nmap_exit_code = result.returncode
        record.update(exit_code=result.returncode, stderr=(result.stderr or "")[-2000:])
        if result.returncode != 0:
            raise RuntimeError(f"Nmap exited with code {result.returncode}: {(result.stderr or result.stdout or 'No diagnostic output')[-2000:]}")
        if not temporary.is_file() or temporary.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Nmap XML missing or exceeds 16 MiB")
        parsed_xml = xmltodict.parse(temporary.read_text(encoding="utf-8"), disable_entities=True)
        root = parsed_xml.get("nmaprun")
        if not isinstance(root, dict) or (root.get("runstats") or {}).get("finished", {}).get("@exit") != "success":
            raise ValueError("Nmap did not produce a successful, complete XML artifact")
        hosts = root.get("host", [])
        hosts = [hosts] if isinstance(hosts, dict) else hosts
        seen = set()
        for host in hosts:
            if host.get("@timedout") == "true":
                raise ValueError("Nmap host timeout: coverage is incomplete")
            addresses = host.get("address", [])
            addresses = [addresses] if isinstance(addresses, dict) else addresses
            for address in addresses:
                if address.get("@addrtype") in {"ipv4", "ipv6"}:
                    seen.add(str(ipaddress.ip_address(address["@addr"])))
            reported_ports = (host.get("ports") or {}).get("port", [])
            reported_ports = [reported_ports] if isinstance(reported_ports, dict) else reported_ports
            requested_ports = set(ports.split(",")) if ports else None
            if len(reported_ports) > PROFILES[status.profile]["top_ports"]:
                raise ValueError("Nmap XML reports more ports than the selected profile allows")
            for port in reported_ports:
                if port.get("@protocol") != "tcp" or (requested_ports is not None and port.get("@portid") not in requested_ports):
                    raise ValueError("Nmap XML contains ports outside the requested TCP coverage")
        if not seen.issubset(set(targets)):
            raise ScopeError("Nmap XML contains an address outside the submitted targets")
        if not seen.issuperset(targets):
            raise ValueError("Nmap XML omits requested hosts; coverage is incomplete")
        # Preserve the standard final filename; readers never see partially written XML.
        temporary.replace(output)
        record["xml"] = output.name
        status.nmap_status = "completed"
        status.status = "nmap_done" if status.profile == "web" else "completed"
        status.message = "Nmap scan completed." if status.status == "completed" else "Nmap completed; web assessment pending."
        if status.status == "completed":
            status.completed_at = _utc_now()
        if "/" in status.target:
            alive = [str(ipaddress.ip_address(a["@addr"])) for host in hosts
                     if (host.get("status") or {}).get("@state") == "up"
                     for a in ([host["address"]] if isinstance(host.get("address"), dict) else host.get("address", []))
                     if a.get("@addrtype") in {"ipv4", "ipv6"}]
            (SCANS_DIR / f"alive_{scan_id}.json").write_text(
                json.dumps({"subnet": status.target, "alive": alive}, indent=2), encoding="utf-8")
    except Exception as exc:
        if isinstance(exc, subprocess.TimeoutExpired):
            message = f"Nmap process timed out after {exc.timeout} seconds."
            record["timed_out"] = True
            record["stderr"] = str(exc.stderr or "")[-2000:]
        else:
            message = str(exc)
        status.status = "failed"
        status.nmap_status = "failed"
        status.message = message[:2500]
        status.completed_at = _utc_now()
        if temporary.exists():
            partial = SCANS_DIR / f"{scan_id}.xml.partial"
            temporary.replace(partial)
            record["partial_xml"] = partial.name
    finally:
        record.update(status=status.nmap_status, message=status.message, completed_at=_utc_now())
        try:
            record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
            _save_scan_status_store()
        except OSError as exc:
            status.status = "failed"
            status.message = f"Cannot persist scan artifacts: {exc}"


def run_cidr_scan(scan_id: str, subnet: str, ports: Optional[str]) -> None:
    status = scan_status_store.get(scan_id)
    if status is not None:
        run_nmap_scan_multi(scan_id, status.authorized_targets, ports)


def _normalize_webscan_error(err: str) -> str:
    e = (err or "").strip()
    if not e:
        return "Web scan failed for an unknown reason."

    low = e.lower()

    if "timeout" in low:
        return "Web scan timed out (no HTTP response on that host/port or blocked by firewall)."
    if "connection refused" in low:
        return "Web scan connection refused (no web server on that port or firewall rejected)."
    if "no such host" in low or "lookup" in low:
        return "Web scan failed (DNS/host resolution error)."
    if "tls" in low or "ssl" in low or "certificate" in low or "x509" in low:
        return "Web scan failed due to TLS/SSL issue (try https://target:port if applicable)."
    if "403" in low or "forbidden" in low:
        return "Web scan appears blocked (403 Forbidden)."
    if "wildcard" in low or "similar response" in low:
        return "The target returns the same response for unknown paths; Gobuster cannot reliably distinguish real paths."

    return f"Web scan could not complete: {e[:500]}"


def run_web_security_assessment(url: str) -> dict:
    """Retain the public helper and original JSON fields; use one verified connection."""
    return assess_web_url(url)


@asynccontextmanager
async def lifespan(_: FastAPI):
    _load_scan_status_store()
    yield


app = FastAPI(
    title="RiskLens - Security Assessment Platform",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR.parent / "frontend" / "static")), name="static")

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "risklens-backend", "boot_id": BOOT_ID}


@app.post("/scans/clear")
def clear_persisted_scans():
    try:
        with STATUS_LOCK:
            if any(status.status in {"pending", "running", "nmap_done"} for status in scan_status_store.values()):
                raise HTTPException(status_code=409, detail="Cannot clear history while a scan is active")
            scan_status_store.clear()
            _save_scan_status_store()
        return {"status": "ok", "message": "Persisted scan metadata cleared (raw files preserved)"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear scan metadata: {e}")


@app.get("/scans/history", response_model=list[ScanStatus])
def get_scan_history():
    return sorted(
        scan_status_store.values(),
        key=lambda item: item.created_at or "",
        reverse=True,
    )


@app.get("/", include_in_schema=False)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def run_nmap_scan(scan_id: str, target: str, ports: Optional[str] = None):
    run_nmap_scan_multi(scan_id, [target], ports)


def run_scan_job(scan_id: str, web_url: Optional[str] = None) -> None:
    try:
        status = scan_status_store[scan_id]
        if not status.network_scan:
            status.nmap_status = "skipped"
            status.status = "nmap_done"
        elif "/" in status.target:
            run_cidr_scan(scan_id, status.target, status.ports)
        else:
            run_nmap_scan(scan_id, status.target, status.ports)
        if status.nmap_status == "failed" and web_url:
            status.gobuster_status = "skipped"
            status.web_status = "skipped"
            _save_scan_status_store()
        if status.nmap_status in {"completed", "skipped"} and web_url:
            run_gobuster_scan(scan_id, web_url)
            status.status = "failed" if status.web_status == "failed" else "completed"
            status.message = (("Network completed; web assessment failed." if status.network_scan else "Web assessment failed.") if status.status == "failed" else
                              f"{'Network and HTTP/TLS assessments' if status.network_scan else 'HTTP/TLS assessment'} completed; optional path discovery: {status.gobuster_status}.")
            status.completed_at = _utc_now()
            _save_scan_status_store()
    except Exception as exc:
        status = scan_status_store.get(scan_id)
        if status is not None:
            status.status = "failed"
            status.message = f"Scan job failed: {exc}"[:2500]
            status.completed_at = _utc_now()
            _save_scan_status_store()
    finally:
        try:
            if scan_id in scan_status_store:
                persist_snapshot(scan_id)
        except Exception as exc:
            status = scan_status_store[scan_id]
            status.status = "failed"
            status.message = f"Cannot persist finalized snapshot: {exc}"
            try:
                _save_scan_status_store()
            except OSError:
                pass
        finally:
            with STATUS_LOCK:
                DISCOVERY_STOPS.pop(scan_id, None)
            SCAN_SLOTS.release()


@app.post("/scan", response_model=ScanStatus)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Explicit authorization acknowledgement is required")
    if request.exposure not in {None, "auto", "internal", "external"}:
        raise HTTPException(status_code=400, detail="Exposure must be auto, internal, or external")
    try:
        plan = validate_request(request.target, request.ports, request.profile)
        if request.path_discovery and request.profile != "web":
            raise ValueError("Optional path discovery requires the Web profile")
        if not request.network_scan and request.profile != "web":
            raise ValueError("Only Web assessments can omit the network scan")
        if request.network_scan:
            resolve_executable("RISKLENS_NMAP_PATH", "nmap")
        if plan["web_url"]:
            validate_web_url(plan["web_url"], plan["scope"])
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not SCAN_SLOTS.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="A scan is already active; wait for completion")
    scan_id = str(uuid4())
    try:
        exposure = request.exposure or "auto"
        status = ScanStatus(
            scan_id=scan_id, target=plan["target"], status="pending", message="Authorized scan scheduled.",
            exposure=exposure, exposure_effective=(infer_exposure_from_target(plan["targets"][0]) if exposure == "auto" else exposure),
            gobuster_status="pending" if request.path_discovery else "skipped", profile=request.profile,
            description=request.description, created_at=_utc_now(), ports=plan["ports"],
            authorized_targets=plan["targets"], approved_scope=plan["scope"], nmap_status="pending" if request.network_scan else "skipped",
            authorized=True,
            path_discovery=request.path_discovery, network_scan=request.network_scan, web_url=plan["web_url"],
            web_status="pending" if plan["web_url"] else "skipped",
        )
        with STATUS_LOCK:
            scan_status_store[scan_id] = status
            if request.path_discovery:
                DISCOVERY_STOPS[scan_id] = threading.Event()
            _save_scan_status_store()
        background_tasks.add_task(run_scan_job, scan_id, plan["web_url"])
    except Exception:
        scan_status_store.pop(scan_id, None)
        DISCOVERY_STOPS.pop(scan_id, None)
        SCAN_SLOTS.release()
        raise HTTPException(status_code=500, detail="Cannot persist or schedule the scan")
    return status


@app.get("/scan/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    status = scan_status_store.get(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Worker outcomes are authoritative. File size/.done markers cannot erase errors.
    return status


@app.get("/scan/{scan_id}/raw")
def get_raw_scan(scan_id: str):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    with open(xml_path, "r", encoding="utf-8") as f:
        content = f.read()

    return {"scan_id": scan_id, "xml": content}

def parse_nmap_xml(xml_path: Path) -> dict:
    if not xml_path.exists():
        raise FileNotFoundError(f"XML file not found: {xml_path}")

    if xml_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Nmap XML exceeds 16 MiB")
    xml_bytes = xml_path.read_bytes()
    artifact_sha256 = hashlib.sha256(xml_bytes).hexdigest()
    xml_content = xml_bytes.decode("utf-8")
    if not xml_content.strip() or "</nmaprun>" not in xml_content:
        raise ValueError("Nmap XML is empty or incomplete")
    data = xmltodict.parse(xml_content, disable_entities=True)

    nmaprun = data.get("nmaprun", {})
    raw_hosts = nmaprun.get("host", [])

    if isinstance(raw_hosts, dict):
        hosts = [raw_hosts]
    else:
        hosts = raw_hosts

    scaninfos = nmaprun.get("scaninfo", [])
    scaninfos = [scaninfos] if isinstance(scaninfos, dict) else scaninfos
    scanned_ports = {}
    for info in scaninfos:
        ports = set()
        for item in info.get("@services", "").split(","):
            if not item:
                continue
            bounds = item.split("-")
            low, high = int(bounds[0]), int(bounds[-1])
            if not 1 <= low <= high <= 65535:
                raise ValueError("Invalid XML port coverage")
            ports.update(range(low, high + 1))
        scanned_ports[info.get("@protocol", "tcp")] = sorted(ports)
    parsed = {"hosts": [], "observations": [], "coverage": {
        "scanned_ports": scanned_ports,
        "run_completed": ((nmaprun.get("runstats") or {}).get("finished") or {}).get("@exit") == "success"}}


    for host in hosts:
        addresses = host.get("address", [])
        if isinstance(addresses, dict):
            addresses = [addresses]

        ip = None
        mac_address = None
        mac_vendor = None
        for addr in addresses:
            if addr.get("@addrtype") in ("ipv4", "ipv6"):
                try:
                    ip = str(ipaddress.ip_address(addr.get("@addr")))
                except ValueError:
                    ip = None
            elif addr.get("@addrtype") == "mac":
                mac_address = addr.get("@addr")
                mac_vendor = addr.get("@vendor")

        hostnames_block = (host.get("hostnames") or {}).get("hostname", [])
        if isinstance(hostnames_block, dict):
            hostnames_block = [hostnames_block]
        # Replaying saved XML must not initiate a fresh DNS lookup.
        reverse_dns = next((item.get("@name") for item in hostnames_block
                            if item.get("@type") == "PTR"), None)
        hostnames = [
            item.get("@name")
            for item in hostnames_block
            if item.get("@name")
        ]

        os_matches = (host.get("os") or {}).get("osmatch", [])
        if isinstance(os_matches, dict):
            os_matches = [os_matches]
        os_detection = []
        for match in os_matches[:3]:
            os_detection.append({
                "name": match.get("@name"),
                "accuracy": match.get("@accuracy"),
                "line": match.get("@line"),
            })

        ports_block = host.get("ports", {}) or {}
        raw_ports = ports_block.get("port", [])
        if isinstance(raw_ports, dict):
            raw_ports = [raw_ports]

        services = []
        for p in raw_ports:
            port_value = p.get("@portid")
            if not isinstance(port_value, (str, int)):
                continue
            try:
                port_id = int(port_value)
            except (TypeError, ValueError):
                continue
            if not 1 <= port_id <= 65535:
                continue

            proto = p.get("@protocol", "tcp")
            state = (p.get("state") or {}).get("@state", "unknown")

            service_info = p.get("service") or {}
            service_name = service_info.get("@name")
            product = service_info.get("@product")
            version = service_info.get("@version")
            extrainfo = service_info.get("@extrainfo")
            raw_scripts = p.get("script", [])
            if isinstance(raw_scripts, dict):
                raw_scripts = [raw_scripts]
            nse_findings = []
            for script in raw_scripts:
                script_id = script.get("@id")
                script_output = script.get("@output")
                if script_id and script_output:
                    nse_findings.append({
                        "id": script_id,
                        "output": script_output,
                    })

            services.append(
                {
                    "host": ip,
                    "port": port_id,
                    "protocol": proto,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "nse_findings": nse_findings,
                    "evidence": {
                        "source": "Nmap XML", "artifact": xml_path.name,
                        "sha256": artifact_sha256,
                        "host_addresses": addresses,
                        "locator": f"host[{ip}]/ports/port[@protocol='{proto}'][@portid='{port_id}']",
                        "original": p,
                    },
                }
            )
            parsed["observations"].append(normalized_observation(ip, services[-1]))

        omitted = ports_block.get("extraports", [])
        omitted = [omitted] if isinstance(omitted, dict) else omitted
        parsed["hosts"].append({
            "ip": ip, "state": (host.get("status") or {}).get("@state", "unknown"),
            "timed_out": host.get("@timedout") == "true",
            "omitted_port_states": sorted({p.get("@state", "unknown") for p in omitted}),
            "omitted_port_count": sum(int(p.get("@count", "0")) for p in omitted),
            "hostnames": hostnames,
            "reverse_dns": reverse_dns,
            "mac": mac_address,
            "mac_vendor": mac_vendor,
            "os": os_detection,
            "services": services,
        })

    return parsed
@app.get("/scan/{scan_id}/parsed")
def get_parsed_scan(scan_id: str):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    try:
        parsed = parse_nmap_xml(xml_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse XML: {e}")

    return {
        "scan_id": scan_id,
        "data": parsed,
    }

@app.get("/scan/{scan_id}/nvd")
def get_scan_with_nvd(scan_id: str):
    snapshot = load_snapshot(scan_id)
    return {"scan_id": scan_id, "exposure": snapshot["metadata"].get("exposure"),
            "profile": snapshot["metadata"].get("profile"),
            "component_status": snapshot["components"]["network"]["status"],
            "data": snapshot["components"]["network"].get("parsed", {"hosts": []})}



def build_findings(parsed: dict, web_assessment: Optional[dict] = None) -> list[dict]:
    findings = build_network_findings(parsed)
    findings.extend(build_web_findings(web_assessment))
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return sorted(findings, key=lambda item: (rank.get(item["severity"], 0), float(item.get("cvss") or 0)), reverse=True)


def service_remediation(service: dict) -> str:
    """Local review guidance, not a claim that this service is vulnerable."""
    name = (service.get("service") or "").lower()
    port = service.get("port")
    if name == "ftp" or port == 21:
        return "If file transfer is required, prefer an encrypted protocol and restrict access to authorized clients."
    if name == "ssh" or port == 22:
        return "Restrict SSH to authorized clients, prefer key-based authentication, and review vendor updates."
    if name in {"http", "https"} or port in {80, 443, 8080, 8443}:
        return "Review the saved HTTP/TLS evidence, enable HTTPS where appropriate, and restrict administrative paths."
    return "Confirm this service is required, restrict access to authorized clients, and review vendor updates."


def annotate_saved_services(parsed: dict, exposure: str) -> None:
    """Keep the existing service response shape without performing external I/O."""
    for host in parsed.get("hosts", []):
        for service in host.get("services", []):
            service["ip"] = host.get("ip")
            # XML contains no credential test or NVD lookup results. Not tested
            # is deliberately distinct from a successful negative check.
            service["weak_creds"] = {"found": False, "status": "not_tested"}
            service["nvd"] = normalize_nvd_candidates(service.get("nvd") or {"status": "not_queried"}, service)
            service["remediation"] = service_remediation(service)
            service.update(pcvp_score_for_service(service, exposure))
            service["identity_confidence"] = "medium" if service.get("product") and service.get("version") else "low"
            service["identity_reason"] = ("Scanner-reported identity is not verification of an installed package."
                                          if service["identity_confidence"] == "medium" else "Product or version is missing; identity is incomplete.")
    parsed["observations"] = [normalized_observation(host.get("ip"), service)
                              for host in parsed.get("hosts", []) for service in host.get("services", [])]
    parsed["candidate_vulnerabilities"] = [finding for finding in build_network_findings(parsed)
                                            if finding["category"] == "candidate_vulnerability"]


def enrich_scan_data(scan_id: str) -> tuple[dict, Optional[dict]]:
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    parsed = parse_nmap_xml(xml_path)
    status = scan_status_store.get(scan_id)
    exposure = status.exposure_effective if status and status.exposure_effective else "external"
    annotate_saved_services(parsed, exposure)
    audit_path = SCANS_DIR / f"web_audit_{scan_id}.json"
    web_audit = json.loads(audit_path.read_text(encoding="utf-8")) if audit_path.exists() else None
    return parsed, web_audit


@app.get("/scan/{scan_id}/findings")
def get_findings(scan_id: str):
    snapshot = load_snapshot(scan_id)
    findings = snapshot["findings"]
    counts = {level: sum(1 for finding in findings if finding["severity"] == level)
              for level in ("critical", "high", "medium", "low", "info")}
    return {"scan_id": scan_id, "summary": counts, "findings": findings,
            "network_observations": snapshot["components"]["network"]["observations"],
            "candidate_vulnerabilities": [item for item in findings if item.get("category") == "candidate_vulnerability"]}



@app.get("/scan/{scan_id}/findings.csv")
def download_findings_csv(scan_id: str, baseline: Optional[str] = None):
    snapshot = load_snapshot(scan_id)
    data = get_findings(scan_id)
    differences = get_comparison(scan_id, baseline) if baseline else None
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "title", "severity", "confidence", "asset", "source", "cvss", "evidence", "remediation",
                                              "domain", "category", "rule_id", "reason", "verification_status", "reported_cvss", "original_evidence", "retest", "scan_id", "target", "timestamp", "record_type", "before", "after"], extrasaction="ignore")
    writer.writeheader()
    for finding in data["findings"]:
        row = {**finding, "scan_id": scan_id, "target": snapshot["target"], "timestamp": snapshot["timestamp"], "record_type": "finding"}
        row["original_evidence"] = json.dumps(row.get("original_evidence", {}), sort_keys=True)
        writer.writerow(row)
    if differences:
        for bucket in ("added", "removed", "changed", "uncertain"):
            for item in differences[bucket]:
                writer.writerow({"record_type": "difference", "category": bucket, "domain": item["component"],
                                 "title": item["kind"], "asset": item["key"], "evidence": item["reason"],
                                 "before": json.dumps(item["before"]), "after": json.dumps(item["after"]),
                                 "scan_id": scan_id, "target": snapshot["target"], "timestamp": snapshot["timestamp"]})
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="pcvp_findings_{scan_id}.csv"'},
    )

@app.get("/scan/{scan_id}/attack-graph")
def get_attack_graph(scan_id: str):
    scan_status = scan_status_store.get(scan_id)
    if not scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan_status.nmap_status != "completed" and scan_status.status not in ("completed", "nmap_done"):
        raise HTTPException(status_code=400, detail=f"Scan not completed ({scan_status.status}): {scan_status.message}")

    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    try:
        parsed = parse_nmap_xml(xml_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse scan XML: {e}")

    exposure_effective = (
        scan_status.exposure_effective
        if scan_status.exposure_effective
        else infer_exposure_from_target(scan_status.target)
    )

    annotate_saved_services(parsed, exposure_effective)

    graph = build_attack_graph(parsed)
    return {"scan_id": scan_id, "exposure": scan_status.exposure, "graph": graph}

def _validate_web_job(status: ScanStatus, url: str) -> None:
    if not status.authorized or not (status.nmap_status == "completed" or (not status.network_scan and status.nmap_status == "skipped")):
        raise ScopeError("Web assessment requires a completed authorized network scan")
    parsed, host, port = validate_web_url(url, status.approved_scope)
    if host not in status.authorized_targets:
        raise ScopeError("Web target is outside saved scan targets")
    validate_request(url, status.ports, "web")
    if status.web_url:
        approved, saved_host, saved_port = validate_web_url(status.web_url, status.approved_scope)
        if (parsed.scheme, host, port) != (approved.scheme, saved_host, saved_port):
            raise ScopeError("Web origin differs from the explicitly approved scheme, IP and port")
    elif status.path_discovery:
        raise ScopeError("Path discovery requires a saved explicitly approved web origin")
    if parsed.path not in {"", "/"} or parsed.query:
        raise ScopeError("Path discovery and assessment require the approved origin only")


def run_gobuster_scan(scan_id: str, url: str) -> None:
    """Keep the existing worker entry point: HTTP/TLS first, optional paths second."""
    scan_st = scan_status_store.get(scan_id)
    if scan_st is None:
        return
    output = SCANS_DIR / f"gobuster_{scan_id}.txt"
    record_path = SCANS_DIR / f"gobuster_{scan_id}.status"
    record = {"status": "skipped", "enabled": scan_st.path_discovery, "url": url,
              "started_at": _utc_now(), "threads": 1, "delay": "1s", "timeout_seconds": 120}
    with STATUS_LOCK:
        stop = DISCOVERY_STOPS.setdefault(scan_id, threading.Event())
    scan_st.web_status = "running"
    try:
        _validate_web_job(scan_st, url)
        _save_scan_status_store()
        audit = run_web_security_assessment(url)
        audit_path = SCANS_DIR / f"web_audit_{scan_id}.json"
        temporary = audit_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(audit, indent=2), encoding="utf-8")
        temporary.replace(audit_path)
        if audit.get("error"):
            raise RuntimeError(f"{audit.get('error_category', 'assessment_error')}: {audit['error']}")
        scan_st.web_status = "completed"
        if not scan_st.path_discovery:
            record["summary"] = "Optional path discovery was not requested."
            return
        if stop.is_set():
            raise DiscoveryStopped("Path discovery stopped before launch")
        executable = resolve_executable("RISKLENS_GOBUSTER_PATH", "gobuster")
        words = SCANS_DIR / f"gobuster_{scan_id}.words.txt"
        record["word_count"] = prepare_wordlist(GOBUSTER_WORDLIST, words)
        scan_st.gobuster_status = "running"
        _save_scan_status_store()
        record["command"] = execute_discovery(executable, url, words, output, stop,
                                               lambda: _validate_web_job(scan_st, url))
        record["status"] = "completed"
        record["summary"] = "Optional path discovery completed; path responses are observations only."
    except Exception as exc:
        if scan_st.web_status == "running":
            scan_st.web_status = "failed"
        category = ("cancelled" if isinstance(exc, DiscoveryStopped) else
                    "timed_out" if isinstance(exc, subprocess.TimeoutExpired) else "failed")
        record.update(status=category, summary=str(exc)[:2000], detail=str(exc)[:2000],
                      error_category=("scope_rejected" if isinstance(exc, ScopeError) else
                                      "configuration_error" if isinstance(exc, ConfigurationError) else category))
    finally:
        record["completed_at"] = _utc_now()
        scan_st.gobuster_status = record["status"]
        temporary = record_path.with_suffix(".status.tmp")
        temporary.write_text(json.dumps(record, indent=2), encoding="utf-8")
        temporary.replace(record_path)
        (SCANS_DIR / f"gobuster_{scan_id}.done").write_text("done", encoding="utf-8")
        _save_scan_status_store()
        with STATUS_LOCK:
            DISCOVERY_STOPS.pop(scan_id, None)


@app.post("/webscan/{scan_id}/stop")
def stop_path_discovery(scan_id: str):
    with STATUS_LOCK:
        status = scan_status_store.get(scan_id)
        if status is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        event = DISCOVERY_STOPS.get(scan_id)
        if not status.path_discovery or event is None or status.gobuster_status not in {"pending", "running"}:
            raise HTTPException(status_code=409, detail="No optional path job is pending or running")
        event.set()
    return {"scan_id": scan_id, "status": "stop_requested"}


@app.get("/webscan/{scan_id}", response_model=WebScanStatus)
def get_web_scan_status(scan_id: str):
    status = scan_status_store.get(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return WebScanStatus(scan_id=scan_id, status=status.gobuster_status or "skipped",
                         message=f"Optional path discovery: {status.gobuster_status}; HTTP/TLS: {status.web_status or 'not recorded'}.")


def parse_gobuster_output(path: Path) -> List[dict]:
    return parse_paths(path)


@app.get("/webscan/{scan_id}/results")
def get_web_scan_results(scan_id: str):
    output = SCANS_DIR / f"gobuster_{scan_id}.txt"
    record_path = SCANS_DIR / f"gobuster_{scan_id}.status"
    status = scan_status_store.get(scan_id)
    if status is None and not output.exists() and not record_path.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    record = {}
    if record_path.exists():
        raw_record = record_path.read_text(encoding="utf-8")
        try:
            record = json.loads(raw_record)
        except json.JSONDecodeError:
            record = {"summary": raw_record.strip()}
    discovery_status = record.get("status", status.gobuster_status if status else "legacy")
    error = record.get("summary") if discovery_status in {"failed", "timed_out", "cancelled", "legacy"} else None
    # Legacy .status files contain only summary/detail and remain readable.
    if record and "status" not in record:
        error = record.get("summary")
    return {"scan_id": scan_id, "results": parse_gobuster_output(output),
            "error": error, "error_detail": record.get("detail"), "discovery_status": discovery_status,
            "enabled": record.get("enabled", status.path_discovery if status else None),
            "partial": discovery_status in {"failed", "timed_out", "cancelled"}}


@app.get("/webscan/{scan_id}/assessment")
def get_web_security_assessment(scan_id: str):
    assessment_path = SCANS_DIR / f"web_audit_{scan_id}.json"
    if not assessment_path.exists():
        raise HTTPException(status_code=404, detail="Web assessment not available yet")
    try:
        return json.loads(assessment_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read web assessment: {exc}")


@app.get("/webscan/{scan_id}/findings")
def get_web_findings(scan_id: str):
    return {"scan_id": scan_id, "findings": [item for item in load_snapshot(scan_id)["findings"] if item.get("domain") == "web"]}


@app.get("/scan/{scan_id}/alive-hosts")
def get_alive_hosts(scan_id: str):
    alive_path = SCANS_DIR / f"alive_{scan_id}.json"
    if alive_path.exists():
        try:
            data = json.loads(alive_path.read_text(encoding="utf-8"))
            hosts = data.get("alive", [])
            return {"scan_id": scan_id, "hosts": [{"ip": host} for host in hosts]}
        except (OSError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail=f"Failed to read alive hosts: {exc}")

    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    parsed = parse_nmap_xml(xml_path)
    hosts = []
    for host in parsed.get("hosts", []):
        ip = host.get("ip")
        if ip:
            hosts.append({
                "ip": ip,
                "hostnames": list(dict.fromkeys(
                    host.get("hostnames", [])
                    + ([host.get("reverse_dns")] if host.get("reverse_dns") else [])
                )),
                "reverse_dns": host.get("reverse_dns"),
                "mac": host.get("mac"),
                "mac_vendor": host.get("mac_vendor"),
                "os": host.get("os", []),
                "services": len(host.get("services", [])),
                "ports": [
                    service.get("port")
                    for service in host.get("services", [])
                    if service.get("port") is not None
                ],
            })
    return {"scan_id": scan_id, "hosts": hosts}

@app.get("/scan/{scan_id}/report.pdf")
def download_report(scan_id: str, baseline: Optional[str] = None):
    snapshot = load_snapshot(scan_id)
    differences = get_comparison(scan_id, baseline) if baseline else None
    pdf_bytes = build_pdf_report(scan_id=scan_id,
        exposure=snapshot["metadata"].get("exposure_effective") or "unknown",
        parsed=snapshot["components"]["network"].get("parsed", {"hosts": []}),
        findings=snapshot["findings"], snapshot=snapshot, differences=differences)
    return StreamingResponse(BytesIO(pdf_bytes), media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="risklens_{scan_id}.pdf"'})


def checked_scan_id(scan_id: str) -> str:
    try:
        canonical = str(UUID(scan_id))
        if canonical != scan_id.lower():
            raise ValueError()
        return canonical
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="Scan ID must be a canonical UUID")


def normalize_saved_scan(scan_id: str) -> dict:
    status = scan_status_store.get(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Saved scan metadata not found")
    xml = SCANS_DIR / f"{scan_id}.xml"
    partial = SCANS_DIR / f"{scan_id}.xml.partial"
    parsed = {"hosts": [], "observations": []}
    if xml.exists():
        parsed = parse_nmap_xml(xml)
    elif partial.exists():
        try:
            parsed = parse_nmap_xml(partial)
        except (ValueError, ExpatError):
            pass
    annotate_saved_services(parsed, status.exposure_effective or "unknown")
    audit = read_json(SCANS_DIR / f"web_audit_{scan_id}.json")
    path_status_file = SCANS_DIR / f"gobuster_{scan_id}.status"
    try:
        path_record = read_json(path_status_file)
    except json.JSONDecodeError:
        path_record = {"summary": path_status_file.read_text(encoding="utf-8")}
    path_output = SCANS_DIR / f"gobuster_{scan_id}.txt"
    words_file = SCANS_DIR / f"gobuster_{scan_id}.words.txt"
    words = words_file.read_text(encoding="utf-8").splitlines() if words_file.exists() else None
    names = [f"{scan_id}.xml", f"{scan_id}.xml.partial", f"nmap_{scan_id}.json", f"web_audit_{scan_id}.json",
             f"gobuster_{scan_id}.txt", f"gobuster_{scan_id}.status", f"gobuster_{scan_id}.words.txt"]
    snapshot = normalize_scan(status.model_dump(), parsed, audit,
        parse_gobuster_output(path_output) if path_output.exists() else None,
        path_record, read_json(SCANS_DIR / f"nmap_{scan_id}.json"),
        artifact_manifest(SCANS_DIR, names), words)
    snapshot["findings"] = build_findings(parsed, audit)
    return snapshot


def persist_snapshot(scan_id: str):
    snapshot = normalize_saved_scan(scan_id)
    atomic_json(SCANS_DIR / f"snapshot_{scan_id}.json", snapshot)
    return snapshot


def load_snapshot(scan_id: str) -> dict:
    scan_id = checked_scan_id(scan_id)
    try:
        snapshot = read_json(SCANS_DIR / f"snapshot_{scan_id}.json")
        if snapshot is None:
            return normalize_saved_scan(scan_id)  # legacy conversion in memory; GET never writes
        return validate_snapshot(snapshot, scan_id)
    except (OSError, ValueError, TypeError, ExpatError) as exc:
        raise HTTPException(status_code=422, detail=f"Cannot read saved evidence: {exc}")


@app.post("/webscan", response_model=ScanStatus)
def start_independent_web_scan(request: WebScanRequest, background_tasks: BackgroundTasks):
    return start_scan(ScanRequest(target=request.url, description=request.description, profile="web",
        authorized=request.authorized, path_discovery=request.path_discovery, network_scan=False), background_tasks)


@app.get("/scans/{scan_id}/snapshot")
def get_snapshot(scan_id: str):
    return load_snapshot(scan_id)


@app.get("/scans/{new_id}/compare/{old_id}")
def get_comparison(new_id: str, old_id: str):
    new, old = load_snapshot(new_id), load_snapshot(old_id)
    if new["metadata"].get("status") in {"pending", "running", "nmap_done"} or old["metadata"].get("status") in {"pending", "running", "nmap_done"}:
        raise HTTPException(status_code=409, detail="Wait for both scan jobs to finish; no negative inference from active scans")
    try:
        return compare_snapshots(old, new)
    except IncompatibleScans as exc:
        raise HTTPException(status_code=409, detail=str(exc))

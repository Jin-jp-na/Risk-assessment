import csv
import logging
from contextlib import asynccontextmanager
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import Optional, List
from uuid import uuid4
import subprocess
import xmltodict
import ipaddress
import json
import socket
import ssl
import requests
from urllib.parse import urlparse
from pathlib import Path
from backend.scanner.nvd_mapping import enrich_service_with_nvd
from pydantic import BaseModel
from backend.scanner.pcvp_scoring import pcvp_score_for_service
from backend.scanner.attack_graph import build_attack_graph
from backend.scanner.weak_creds import annotate_services_with_weak_creds
from backend.llm_remediation import generate_remediation_openai
from starlette.responses import StreamingResponse, Response
from backend.report_generator import build_pdf_report
from io import BytesIO
import io
import re
from typing import Tuple
import time 
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

NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"
IPSCAN_PATH = r"C:\Tools\AngryIP\ipscan.exe"  # ✅ add here

BASE_DIR = Path(__file__).resolve().parent
SCANS_DIR = BASE_DIR / "scans"
SCANS_DIR.mkdir(exist_ok=True)
SCAN_STATUS_FILE = SCANS_DIR / "scan_status.json"

def parse_target_and_port(raw: str) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns (host, port, scheme)
    Accepts:
      - "1.2.3.4"
      - "1.2.3.4:3000"
      - "example.com:8080"
      - "http://example.com:8080"
      - "https://example.com:8443"
    Note: IPv6 like [::1]:3000 not handled here (can be added).
    """
    raw = (raw or "").strip()
    scheme = None
    hostport = raw

    m = re.match(r"^(https?)://([^/]+)", raw, flags=re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        hostport = m.group(2)

    if ":" in hostport and hostport.count(":") == 1:
        host, port = hostport.split(":", 1)
        host = host.strip()
        port = port.strip()
        if port.isdigit():
            return host, port, scheme

    return hostport.strip(), None, scheme

GOBUSTER_EXE = BASE_DIR.parent / "gobuster_Windows_x86_64" / "gobuster.exe"
GOBUSTER_WORDLIST = BASE_DIR.parent / "wordlists" / "common.txt"
NMAP_SCRIPT_SET = "vuln"

BOOT_ID = str(uuid4())

templates = Jinja2Templates(directory=str(BASE_DIR.parent / "frontend" / "templates"))


class ScanRequest(BaseModel):
    target: str
    description: Optional[str] = None
    exposure: Optional[str] = "auto"
    ports: Optional[str] = None
    profile: str = "standard"

class ScanStatus(BaseModel):
    scan_id: str
    target: str
    status: str
    message: Optional[str] = None
    exposure: Optional[str] = "auto"
    exposure_effective: Optional[str] = None
    gobuster_status: Optional[str] = "pending"  # ✅ track gobuster separately
    profile: str = "standard"
    description: Optional[str] = None
    created_at: str = ""
    completed_at: Optional[str] = None


class WebScanRequest(BaseModel):
    url: str
    description: Optional[str] = None


class WebScanStatus(BaseModel):
    scan_id: str
    status: str
    message: str

class RemediationRequest(BaseModel):
    scan_id: str
    ip: str
    port: int
    protocol: str = "tcp"


scan_status_store: dict[str, ScanStatus] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_scan_status_store() -> None:
    if not SCAN_STATUS_FILE.exists():
        return
    try:
        data = json.loads(SCAN_STATUS_FILE.read_text(encoding="utf-8"))
        for scan_id, raw_status in data.items():
            status = ScanStatus.model_validate(raw_status)
            if not status.created_at:
                status.created_at = _utc_now()
            scan_status_store[scan_id] = status
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[SCAN STORE] Failed to load scan status store: {exc}")

def _save_scan_status_store() -> None:
    try:
        data = {k: v.model_dump() for k, v in scan_status_store.items()}
        tmp = SCAN_STATUS_FILE.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp.replace(SCAN_STATUS_FILE)
    except Exception as e:
        print(f"[SCAN STORE] Failed to save scan status store: {e}")

def is_cidr_target(s: str) -> bool:
    try:
        ipaddress.ip_network(s, strict=False)
        return "/" in s
    except Exception:
        return False


def run_angry_ip_discovery(scan_id: str, subnet: str) -> list[str]:
    out_csv = SCANS_DIR / f"angryip_{scan_id}.csv"

    # Convert CIDR -> start/end range for Angry IP feeder
    net = ipaddress.ip_network(subnet, strict=False)
    start_ip = str(net.network_address)
    end_ip = str(net.broadcast_address)

    cmd = [
        IPSCAN_PATH,
        "-s",                  # start scanning automatically
        "-q",                  # quit after exporting the results
        "-f:range", start_ip, end_ip,
        "-o", str(out_csv),    # exporter inferred from ".csv"
    ]

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
        creationflags=subprocess.CREATE_NO_WINDOW,  # ✅ hide Angry IP window
        startupinfo=startupinfo,
    )

    if result.returncode != 0:
        err = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
        raise Exception(f"Angry IP Scanner failed: {err or 'unknown error'}")

    if not out_csv.exists():
        return []

    alive: list[str] = []
    with out_csv.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            candidate = (row[0] or "").strip()
            try:
                ipaddress.ip_address(candidate)
                alive.append(candidate)
            except Exception:
                continue

    return sorted(set(alive), key=lambda x: tuple(int(p) for p in x.split(".")))


def run_nmap_scan_multi(scan_id: str, targets: List[str], ports: Optional[str] = None) -> None:
    """
    Runs ONE Nmap scan for multiple targets and writes:
      scans/<scan_id>.xml

    Uses a temporary file first to avoid partial XML reads.
    """
    status = scan_status_store.get(scan_id)
    if not status:
        return

    status.status = "running"
    status.message = "Nmap scan in progress (multi-host)..."
    status.gobuster_status = "skipped"
    scan_status_store[scan_id] = status
    _save_scan_status_store()

    output_file = SCANS_DIR / f"{scan_id}.xml"
    tmp_file = SCANS_DIR / f"{scan_id}.xml.tmp"

    try:
        # Remove any stale tmp
        try:
            if tmp_file.exists():
                tmp_file.unlink()
        except Exception:
            pass

        cmd = [NMAP_PATH, "-sV", "-O", "--osscan-guess", "-T4", "-Pn", "--script", NMAP_SCRIPT_SET]

        if ports:
            cmd += ["-p", ports]

        # ✅ Write to tmp first
        cmd += ["-oX", str(tmp_file)]
        cmd += list(targets)

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            # OS detection may require an elevated Nmap installation. Preserve
            # the service/vulnerability scan if Windows blocks raw probes.
            fallback = [arg for arg in cmd if arg not in ("-O", "--osscan-guess")]
            subprocess.run(fallback, check=True, capture_output=True)

        # ✅ Atomic replace: endpoints will only see a complete XML
        if not tmp_file.exists() or tmp_file.stat().st_size < 100:
            raise RuntimeError("Nmap did not produce a valid XML output file.")

        tmp_file.replace(output_file)

        status.status = "completed"
        status.message = f"CIDR scan completed. Alive hosts scanned: {len(targets)}"

    except subprocess.CalledProcessError as e:
        err_msg = ""
        try:
            err_msg = e.stderr.decode(errors="ignore") if e.stderr else ""
        except Exception:
            err_msg = str(e)

        status.status = "failed"
        status.message = f"Scan failed: {err_msg or str(e)}"

    except Exception as e:
        status.status = "failed"
        status.message = f"Unexpected error: {e}"

    finally:
        scan_status_store[scan_id] = status
        _save_scan_status_store()
        # cleanup tmp if left behind
        try:
            if tmp_file.exists():
                tmp_file.unlink()
        except Exception:
            pass


def run_cidr_scan(
    scan_id: str,
    subnet: str,
    ports: Optional[str],
) -> None:
    """
    1) Angry IP discovery -> alive hosts
    2) Run ONE combined Nmap scan against alive hosts
       and write scans/<scan_id>.xml (so your existing UI endpoints work)

    Also saves alive list:
      scans/alive_<scan_id>.json
    """
    st = scan_status_store.get(scan_id)
    if not st:
        return

    try:
        st.status = "running"
        st.message = "Discovering alive hosts (Angry IP Scanner)..."
        st.gobuster_status = "skipped"
        scan_status_store[scan_id] = st
        _save_scan_status_store()

        alive_hosts = run_angry_ip_discovery(scan_id, subnet)

        if not alive_hosts:
            st.status = "failed"
            st.message = "No alive hosts found in subnet."
            scan_status_store[scan_id] = st
            _save_scan_status_store()
            return

        # save alive list
        alive_path = SCANS_DIR / f"alive_{scan_id}.json"
        with alive_path.open("w", encoding="utf-8") as f:
            json.dump({"subnet": subnet, "alive": alive_hosts}, f, indent=2)

        st.message = f"Discovered {len(alive_hosts)} alive hosts. Running Nmap (combined)..."
        scan_status_store[scan_id] = st
        _save_scan_status_store()

        # ✅ IMPORTANT: run one Nmap scan for all alive hosts -> scans/<scan_id>.xml
        run_nmap_scan_multi(scan_id, alive_hosts, ports=ports)

        # run_nmap_scan_multi updates scan status to completed/failed and saves it
        return

    except Exception as e:
        st.status = "failed"
        st.message = f"CIDR scan failed: {e}"
        st.gobuster_status = "skipped"
        scan_status_store[scan_id] = st
        _save_scan_status_store()

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
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname:
        return {"url": url, "error": "Unsupported web URL."}

    result = {
        "url": url,
        "http": {},
        "tls": {},
        "technologies": [],
        "checks": [],
    }

    response = None
    request_error = None
    try:
        response = requests.get(url, timeout=15, allow_redirects=True, verify=True)
    except requests.exceptions.SSLError as exc:
        request_error = str(exc)
        try:
            response = requests.get(url, timeout=15, allow_redirects=True, verify=False)
        except requests.RequestException as fallback_exc:
            request_error = str(fallback_exc)
    except requests.RequestException as exc:
        request_error = str(exc)

    if response is not None:
        headers = {key.lower(): value for key, value in response.headers.items()}
        result["http"] = {
            "status": response.status_code,
            "final_url": response.url,
            "headers": dict(response.headers),
        }
        body_sample = response.text[:200000].lower()
        technology_signatures = {
            "Server": headers.get("server"),
            "Powered-By": headers.get("x-powered-by"),
            "WordPress": "wp-content" if "wp-content" in body_sample else None,
            "React": "react" if "react" in body_sample else None,
            "jQuery": "jquery" if "jquery" in body_sample else None,
        }
        result["technologies"] = [
            {"name": name, "evidence": evidence}
            for name, evidence in technology_signatures.items()
            if evidence
        ]
        security_headers = {
            "strict-transport-security": "HSTS",
            "content-security-policy": "Content-Security-Policy",
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
        }
        for header_name, label in security_headers.items():
            present = header_name in headers
            result["checks"].append({
                "name": label,
                "status": "pass" if present else "missing",
                "detail": "Header present" if present else "Security header is missing",
            })
        if "server" in headers:
            result["checks"].append({
                "name": "Server disclosure",
                "status": "review",
                "detail": f"Server header is exposed: {headers['server']}",
            })
        if request_error:
            result["checks"].append({
                "name": "TLS validation",
                "status": "review",
                "detail": request_error,
            })
    else:
        result["error"] = request_error or "HTTP request failed."

    if parsed_url.scheme == "https" and parsed_url.hostname:
        try:
            port = parsed_url.port or 443
            context = ssl._create_unverified_context()
            with socket.create_connection((parsed_url.hostname, port), timeout=10) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=parsed_url.hostname) as tls_socket:
                    certificate = tls_socket.getpeercert() or {}
                    cipher = tls_socket.cipher()
                    result["tls"] = {
                        "protocol": tls_socket.version(),
                        "cipher": cipher[0] if cipher else None,
                        "subject": str(certificate.get("subject", "")),
                        "issuer": str(certificate.get("issuer", "")),
                        "expires": certificate.get("notAfter"),
                    }
        except (OSError, ssl.SSLError) as exc:
            result["tls"] = {"error": str(exc)}

    return result


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
        if SCAN_STATUS_FILE.exists():
            SCAN_STATUS_FILE.unlink()
        scan_status_store.clear()
        _save_scan_status_store()
        return {"status": "ok", "message": "Persisted scan metadata cleared (raw files preserved)"}
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
    status = scan_status_store.get(scan_id)
    if not status:
        return

    status.status = "running"
    scan_status_store[scan_id] = status

    output_file = SCANS_DIR / f"{scan_id}.xml"

    try:
        profile = status.profile
        cmd = [
            NMAP_PATH,
            "-sV",
            "-T4",
            "-Pn",
        ]
        if profile in {"vulnerability", "full"}:
            cmd += ["-O", "--osscan-guess", "--script", NMAP_SCRIPT_SET]
        elif profile == "quick":
            cmd = [NMAP_PATH, "-T4", "-Pn"]

        if ports:
            cmd += ["-p", ports]  # ✅ only scan specified ports

        cmd += ["-oX", str(output_file), target]

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            fallback = [arg for arg in cmd if arg not in ("-O", "--osscan-guess")]
            subprocess.run(fallback, check=True, capture_output=True)

        status.status = "nmap_done"
        status.message = "Nmap completed. Waiting for Gobuster..."

    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode(errors="ignore") if e.stderr else str(e)
        status.status = "failed"
        status.message = f"Scan failed: {err_msg}"
    except Exception as e:
        status.status = "failed"
        status.message = f"Unexpected error: {e}"
    finally:
        scan_status_store[scan_id] = status
        _save_scan_status_store()

@app.post("/scan", response_model=ScanStatus)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.target:
        raise HTTPException(status_code=400, detail="Target is required")
    try:
        ip_tmp = ipaddress.ip_address(request.target.strip())
        if ip_tmp.version == 4 and request.target.strip().endswith(".0"):
            request.target = f"{request.target.strip()}/24"
    except Exception:
        pass

    # ✅ ADD THIS (CIDR subnet scan)
    if is_cidr_target(request.target):
        scan_id = str(uuid4())
        ports = (request.ports or "").strip() or None

        profile = request.profile if request.profile in {"quick", "standard", "vulnerability", "web", "full"} else "standard"
        status = ScanStatus(
            scan_id=scan_id,
            target=request.target,  # keep CIDR as target label
            status="pending",
            message="CIDR scan scheduled (Angry IP discovery + combined Nmap)",
            exposure=request.exposure or "auto",
            exposure_effective="internal",
            gobuster_status="skipped",
            profile=profile,
            description=request.description,
            created_at=_utc_now(),
        )
        scan_status_store[scan_id] = status
        _save_scan_status_store()

        background_tasks.add_task(run_cidr_scan, scan_id, request.target, ports)
        return status
    # ✅ END CIDR BLOCK

    host, implied_port, scheme = parse_target_and_port(request.target)

    # user-provided ports (optional)
    ports = (request.ports or "").strip() or None

    # if user typed host:port and didn't provide ports separately, use that
    if implied_port and not ports:
        ports = implied_port

    exposure_choice = request.exposure or "auto"
    if exposure_choice == "auto":
        exposure_effective = infer_exposure_from_target(host)
    else:
        exposure_effective = exposure_choice

    scan_id = str(uuid4())
    profile = request.profile if request.profile in {"quick", "standard", "vulnerability", "web", "full"} else "standard"
    status = ScanStatus(
        scan_id=scan_id,
        target=host,  # ✅ store clean host (not host:port)
        status="pending",
        message="Nmap + Gobuster scan scheduled",
        exposure=exposure_choice,
        exposure_effective=exposure_effective,
        profile=profile,
        description=request.description,
        created_at=_utc_now(),
    )
    scan_status_store[scan_id] = status
    _save_scan_status_store()

    # ✅ Nmap: scan host, optionally specific ports
    background_tasks.add_task(run_nmap_scan, scan_id=scan_id, target=host, ports=ports)

    # ✅ Gobuster: build URL including scheme and port (if single port)
    netloc = host
    if ports and ports.isdigit():
        netloc = f"{host}:{ports}"

    if not scheme:
        scheme = "http"

    target_url = f"{scheme}://{netloc}"
    if profile in {"web", "full", "standard", "vulnerability"}:
        background_tasks.add_task(run_gobuster_scan, scan_id, target_url)
    else:
        status.gobuster_status = "skipped"
        scan_status_store[scan_id] = status
        _save_scan_status_store()

    return status
@app.get("/scan/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: str):
    status = scan_status_store.get(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")

    xml_path = SCANS_DIR / f"{scan_id}.xml"
    done_path = SCANS_DIR / f"gobuster_{scan_id}.done"

    nmap_done = xml_path.exists() and xml_path.stat().st_size > 100
    gobuster_done = done_path.exists()

    # ✅ CIDR scans skip gobuster, so don't wait for gobuster_.done
    if status.gobuster_status == "skipped":
        gobuster_done = True

    if nmap_done and gobuster_done:
        status.status = "completed"
        if not status.completed_at:
            status.completed_at = _utc_now()
        # if gobuster was skipped, keep it skipped; otherwise mark completed
        if status.gobuster_status != "skipped":
            status.gobuster_status = "completed"
        status.message = "Scan fully completed."
        scan_status_store[scan_id] = status
        _save_scan_status_store()

    elif nmap_done and not gobuster_done:
        status.status = "nmap_done"
        status.gobuster_status = "running"
        if status.status not in ("failed",):
            status.message = "Nmap completed. Waiting for Gobuster..."
        scan_status_store[scan_id] = status

    elif not nmap_done:
        if status.status not in ("failed",):
            status.status = "running"
            status.message = "Nmap scan in progress..."
        scan_status_store[scan_id] = status

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

    # ✅ Wait a bit if Nmap is still writing the file (prevents truncated XML parse)
    xml_content = ""
    for _ in range(20):  # 20 * 0.5s = 10 seconds max wait
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
            xml_content = f.read()

        if xml_content.strip() and "</nmaprun>" in xml_content:
            break

        time.sleep(0.5)

    if not xml_content.strip():
        raise ValueError("Nmap XML is empty (scan not finished yet)")

    if "</nmaprun>" not in xml_content:
        raise ValueError("Nmap XML is incomplete (scan still running). Try again in a few seconds.")

    data = xmltodict.parse(xml_content)

    nmaprun = data.get("nmaprun", {})
    raw_hosts = nmaprun.get("host", [])

    if isinstance(raw_hosts, dict):
        hosts = [raw_hosts]
    else:
        hosts = raw_hosts

    parsed = {"hosts": []}

    for host in hosts:
        addresses = host.get("address", [])
        if isinstance(addresses, dict):
            addresses = [addresses]

        ip = None
        mac_address = None
        mac_vendor = None
        for addr in addresses:
            if addr.get("@addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("@addr")
            elif addr.get("@addrtype") == "mac":
                mac_address = addr.get("@addr")
                mac_vendor = addr.get("@vendor")

        reverse_dns = None
        if ip:
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                reverse_dns = None

        hostnames_block = (host.get("hostnames") or {}).get("hostname", [])
        if isinstance(hostnames_block, dict):
            hostnames_block = [hostnames_block]
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
                    "port": port_id,
                    "protocol": proto,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "nse_findings": nse_findings,
                }
            )

        parsed["hosts"].append({
            "ip": ip,
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
    scan_status = scan_status_store.get(scan_id)
    if not scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")
    if getattr(scan_status, "status", "") not in ("completed", "nmap_done"):
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

    annotate_services_with_weak_creds(parsed)

    host_count = 0
    for host in parsed.get("hosts", []):
        host_count += 1
        svc_count = 0
        for svc in host.get("services", []):
            svc_count += 1
            product = svc.get("product")
            version = svc.get("version")

            try:
                svc["nvd"] = enrich_service_with_nvd(product, version)
            except Exception as nvd_err:
                svc["nvd"] = {"keyword": None, "cves": [], "error": str(nvd_err)}

            try:
                pcvp = pcvp_score_for_service(svc, exposure_effective)
                svc["pcvp_score"] = pcvp["pcvp_score"]
                svc["pcvp_level"] = pcvp["pcvp_level"]
                svc["pcvp_reasons"] = pcvp["pcvp_reasons"]
            except Exception:
                svc["pcvp_score"] = 0
                svc["pcvp_level"] = "informational"
                svc["pcvp_reasons"] = []

    return {"scan_id": scan_id, "exposure": scan_status.exposure, "profile": scan_status.profile, "data": parsed}


def build_findings(parsed: dict, web_assessment: Optional[dict] = None) -> list[dict]:
    findings: list[dict] = []
    for host in parsed.get("hosts", []):
        ip = host.get("ip") or "unknown"
        for service in host.get("services", []):
            location = f"{ip}:{service.get('port')}/{service.get('protocol', 'tcp')}"
            for script in service.get("nse_findings", []):
                findings.append({
                    "id": f"NSE-{script.get('id', 'finding')}-{ip}-{service.get('port')}",
                    "title": f"Nmap vulnerability check: {script.get('id')}",
                    "severity": "high",
                    "confidence": "high",
                    "asset": location,
                    "evidence": script.get("output", ""),
                    "remediation": "Review the NSE evidence and apply the vendor-recommended fix.",
                    "source": "Nmap NSE",
                })
            weak = service.get("weak_creds") or {}
            if weak.get("found"):
                findings.append({
                    "id": f"WEAK-CREDS-{ip}-{service.get('port')}",
                    "title": "Weak credentials detected",
                    "severity": "critical",
                    "confidence": "high",
                    "asset": location,
                    "evidence": f"{weak.get('protocol', 'service')} accepted supplied credentials",
                    "remediation": "Disable default credentials and rotate the affected account.",
                    "source": "Credential check",
                })
            for cve in (service.get("nvd") or {}).get("cves", [])[:5]:
                score = cve.get("score") or 0
                severity = str(cve.get("severity") or "medium").lower()
                findings.append({
                    "id": cve.get("id") or "CVE-unknown",
                    "title": f"Known vulnerability in {service.get('product') or service.get('service') or 'service'}",
                    "severity": severity,
                    "confidence": "medium",
                    "asset": location,
                    "evidence": cve.get("description", ""),
                    "cvss": score,
                    "remediation": "Upgrade or patch the affected product and verify the service version.",
                    "source": "NVD",
                })
    for check in (web_assessment or {}).get("checks", []):
        if check.get("status") == "missing":
            findings.append({
                "id": f"WEB-{check.get('name', 'header').replace(' ', '-').upper()}",
                "title": f"Missing web security control: {check.get('name')}",
                "severity": "medium",
                "confidence": "high",
                "asset": (web_assessment or {}).get("url", "web target"),
                "evidence": check.get("detail", ""),
                "remediation": f"Configure the {check.get('name')} response header.",
                "source": "HTTP assessment",
            })
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return sorted(findings, key=lambda item: (rank.get(item["severity"], 0), float(item.get("cvss") or 0)), reverse=True)


def enrich_scan_data(scan_id: str) -> tuple[dict, Optional[dict]]:
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    parsed = parse_nmap_xml(xml_path)
    status = scan_status_store.get(scan_id)
    exposure = status.exposure_effective if status and status.exposure_effective else "external"
    annotate_services_with_weak_creds(parsed)
    for host in parsed.get("hosts", []):
        for service in host.get("services", []):
            service["ip"] = host.get("ip")
            service["nvd"] = enrich_service_with_nvd(service.get("product"), service.get("version"))
            score = pcvp_score_for_service(service, exposure)
            service.update(score)
    audit_path = SCANS_DIR / f"web_audit_{scan_id}.json"
    web_audit = json.loads(audit_path.read_text(encoding="utf-8")) if audit_path.exists() else None
    return parsed, web_audit


@app.get("/scan/{scan_id}/findings")
def get_findings(scan_id: str):
    if not (SCANS_DIR / f"{scan_id}.xml").exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")
    parsed, web_audit = enrich_scan_data(scan_id)
    findings = build_findings(parsed, web_audit)
    counts = {level: sum(1 for f in findings if f["severity"] == level) for level in ("critical", "high", "medium", "low")}
    return {"scan_id": scan_id, "summary": counts, "findings": findings}


@app.get("/scan/{scan_id}/findings.csv")
def download_findings_csv(scan_id: str):
    data = get_findings(scan_id)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "title", "severity", "confidence", "asset", "source", "cvss", "evidence", "remediation"])
    writer.writeheader()
    writer.writerows(data["findings"])
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
    if getattr(scan_status, "status", "") not in ("completed", "nmap_done"):
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

    for host in parsed.get("hosts", []):
        for svc in host.get("services", []):
            product = svc.get("product")
            version = svc.get("version")
            svc["nvd"] = enrich_service_with_nvd(product, version)

            pcvp = pcvp_score_for_service(svc, exposure_effective)
            svc["pcvp_score"] = pcvp["pcvp_score"]
            svc["pcvp_level"] = pcvp["pcvp_level"]
            svc["pcvp_reasons"] = pcvp["pcvp_reasons"]

    graph = build_attack_graph(parsed)
    return {"scan_id": scan_id, "exposure": scan_status.exposure, "graph": graph}

def run_gobuster_scan(scan_id: str, url: str) -> None:
    output_path = SCANS_DIR / f"gobuster_{scan_id}.txt"
    status_path = SCANS_DIR / f"gobuster_{scan_id}.status"
    done_path = SCANS_DIR / f"gobuster_{scan_id}.done"
    SCANS_DIR.mkdir(parents=True, exist_ok=True)

    # ✅ Mark gobuster as running
    scan_st = scan_status_store.get(scan_id)
    if scan_st:
        scan_st.gobuster_status = "running"
        scan_status_store[scan_id] = scan_st
        _save_scan_status_store()

    gobuster_failed = False
    friendly_error: Optional[str] = None

    try:
        audit_path = SCANS_DIR / f"web_audit_{scan_id}.json"
        audit = run_web_security_assessment(url)
        audit_path.write_text(json.dumps(audit, indent=2), encoding="utf-8")

        urls = [url]
        if url.lower().startswith("http://"):
            urls.append("https://" + url[7:])

        last_error = ""
        for candidate_url in urls:
            cmd = [
                str(GOBUSTER_EXE),
                "dir",
                "-u", candidate_url,
                "-w", str(GOBUSTER_WORDLIST),
                "-o", str(output_path),
                "-t", "30",
                "--timeout", "10s",
                "--no-tls-validation",
                "--no-color",
                "-q",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0:
                last_error = ""
                break
            last_error = (result.stderr or result.stdout or "").strip()

        if last_error and not output_path.exists():
            gobuster_failed = True
            raw_err = last_error or "Gobuster exited with an error"
            friendly_error = _normalize_webscan_error(raw_err)
            with status_path.open("w", encoding="utf-8") as f:
                json.dump({
                    "summary": friendly_error,
                    "detail": raw_err[:2000],
                }, f, indent=2)
        elif last_error:
            with status_path.open("w", encoding="utf-8") as f:
                json.dump({
                    "summary": "Gobuster completed with warnings; partial results are available.",
                    "detail": last_error[:2000],
                }, f, indent=2)

    except subprocess.TimeoutExpired:
        gobuster_failed = True
        friendly_error = "Web scan timed out (overall gobuster timeout)."
        with status_path.open("w", encoding="utf-8") as f:
            json.dump({"summary": friendly_error}, f, indent=2)

    except Exception as e:
        gobuster_failed = True
        friendly_error = _normalize_webscan_error(str(e))
        with status_path.open("w", encoding="utf-8") as f:
            json.dump({"summary": friendly_error, "detail": str(e)[:2000]}, f, indent=2)

    finally:
        # ✅ Always write .done so UI can stop waiting
        try:
            with done_path.open("w", encoding="utf-8") as f:
                f.write("done")
        except Exception as e:
            print(f"[GOBUSTER] Failed to write .done file: {e}")

        # ✅ Mark gobuster status accurately
        scan_st = scan_status_store.get(scan_id)
        if scan_st:
            scan_st.gobuster_status = "failed" if gobuster_failed else "completed"
            scan_status_store[scan_id] = scan_st
            _save_scan_status_store()
# ✅ Now checks .done file instead of .txt file
@app.get("/webscan/{scan_id}", response_model=WebScanStatus)
def get_web_scan_status(scan_id: str):
    done_path = SCANS_DIR / f"gobuster_{scan_id}.done"
    status_path = SCANS_DIR / f"gobuster_{scan_id}.status"

    if done_path.exists():
        if status_path.exists():
            try:
                status_data = json.loads(status_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                status_data = {"summary": status_path.read_text(encoding="utf-8", errors="ignore").strip()}
            output_path = SCANS_DIR / f"gobuster_{scan_id}.txt"
            has_results = output_path.exists() and output_path.stat().st_size > 0
            return WebScanStatus(
                scan_id=scan_id,
                status="completed_with_warnings" if has_results else "failed",
                message=status_data.get("summary") or "Web scan completed with a warning.",
            )
        return WebScanStatus(scan_id=scan_id, status="completed", message="Gobuster scan completed.")
    else:
        return WebScanStatus(scan_id=scan_id, status="running", message="Gobuster scan is still running or not started.")

def parse_gobuster_output(path: Path) -> List[dict]:
    entries: List[dict] = []
    if not path.exists():
        return entries

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                part, rest = line.split(" (Status:", 1)
                web_path = part.strip()
                rest = rest.strip()
                status_part, size_part = rest.split(")", 1)
                status = int(status_part.strip())
                size = None
                if "[Size:" in size_part:
                    size_str = size_part.split("[Size:", 1)[1].split("]")[0].strip()
                    if size_str.isdigit():
                        size = int(size_str)
            except ValueError:
                continue

            entries.append({
                "path": web_path,
                "status": status,
                "size": size,
            })

    return entries

@app.get("/webscan/{scan_id}/results")
def get_web_scan_results(scan_id: str):
    output_path = SCANS_DIR / f"gobuster_{scan_id}.txt"
    status_path = SCANS_DIR / f"gobuster_{scan_id}.status"

    error_message = None
    error_detail = None
    if status_path.exists():
        try:
            status_data = json.loads(status_path.read_text(encoding="utf-8"))
            error_message = status_data.get("summary")
            error_detail = status_data.get("detail")
        except json.JSONDecodeError:
            error_message = status_path.read_text(encoding="utf-8", errors="ignore").strip()

    if not output_path.exists():
        if error_message:
            return {
                "scan_id": scan_id,
                "results": [],
                "error": error_message,
                "error_detail": error_detail,
            }
        raise HTTPException(status_code=404, detail="Gobuster output not found yet")

    entries = parse_gobuster_output(output_path)
    return {
        "scan_id": scan_id,
        "results": entries,
        "error": error_message,
        "error_detail": error_detail,
    }


@app.get("/webscan/{scan_id}/assessment")
def get_web_security_assessment(scan_id: str):
    assessment_path = SCANS_DIR / f"web_audit_{scan_id}.json"
    if not assessment_path.exists():
        raise HTTPException(status_code=404, detail="Web assessment not available yet")
    try:
        return json.loads(assessment_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read web assessment: {exc}")


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

@app.post("/scan/{scan_id}/remediation")
def get_llm_remediation(scan_id: str, req: RemediationRequest):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    parsed = parse_nmap_xml(xml_path)

    scan_status = scan_status_store.get(scan_id)

    exposure_effective = (
        scan_status.exposure_effective
        if scan_status and scan_status.exposure_effective
        else infer_exposure_from_target(scan_status.target) if scan_status else "external"
    )

    annotate_services_with_weak_creds(parsed)

    target_svc = None
    for host in parsed.get("hosts", []):
        if host.get("ip") != req.ip:
            continue
        for svc in host.get("services", []):
            if svc.get("port") == req.port and (svc.get("protocol") or "tcp") == req.protocol:
                svc["ip"] = host.get("ip")

                svc["nvd"] = enrich_service_with_nvd(svc.get("product"), svc.get("version"))
                pcvp = pcvp_score_for_service(svc, exposure_effective)
                svc["pcvp_score"] = pcvp["pcvp_score"]
                svc["pcvp_level"] = pcvp["pcvp_level"]
                svc["pcvp_reasons"] = pcvp["pcvp_reasons"]

                target_svc = svc
                break

    if not target_svc:
        raise HTTPException(status_code=404, detail="Service not found for remediation generation")

    remediation = generate_remediation_openai(target_svc, exposure_effective)
    return {
        "scan_id": scan_id,
        "exposure": scan_status.exposure if scan_status else "auto",
        "service": target_svc,
        "remediation": remediation,
    }

@app.get("/scan/{scan_id}/report.pdf")
def download_report(scan_id: str):
    xml_path = SCANS_DIR / f"{scan_id}.xml"
    if not xml_path.exists():
        raise HTTPException(status_code=404, detail="Scan output not found yet")

    parsed = parse_nmap_xml(xml_path)

    scan_status = scan_status_store.get(scan_id)

    exposure_effective = (
        scan_status.exposure_effective
        if scan_status and scan_status.exposure_effective
        else infer_exposure_from_target(scan_status.target) if scan_status else "external"
    )

    annotate_services_with_weak_creds(parsed)

    for host in parsed.get("hosts", []):
        for svc in host.get("services", []):
            svc["ip"] = host.get("ip")
            svc["nvd"] = enrich_service_with_nvd(svc.get("product"), svc.get("version"))
            pcvp = pcvp_score_for_service(svc, exposure_effective)
            svc["pcvp_score"] = pcvp["pcvp_score"]
            svc["pcvp_level"] = pcvp["pcvp_level"]
            svc["pcvp_reasons"] = pcvp["pcvp_reasons"]

    attack_graph = build_attack_graph(parsed)
    findings = build_findings(parsed)

    pdf_bytes = build_pdf_report(
        scan_id=scan_id,
        exposure=exposure_effective,
        parsed=parsed,
        attack_graph=attack_graph,
        findings=findings,
    )

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="pcvp_report_{scan_id}.pdf"'},
    )
# RiskLens

RiskLens is a Windows web application that runs bounded Nmap TCP scans,
calculates a contextual risk score from saved observations, builds an attack graph, and optionally
performs web directory discovery with Gobuster.

Opening results, history, CSV, or PDF reads saved evidence without credential
attempts, live NVD lookups, or reverse-DNS requests. Service details contain
small deterministic review messages. Credential testing is disabled; "not tested"
does not mean credentials are safe. NVD "not queried" does not mean no CVEs exist.

Only scan systems that you own or have explicit permission to assess.

## Requirements

- Windows 10 or Windows 11
- Python 3.11 or newer (Python 3.13 is supported by the included dependency set)
- Nmap for Windows
- A modern browser
- Internet access for the existing CDN-loaded frontend libraries

The repository contains a Windows Gobuster executable at
`gobuster_Windows_x86_64\gobuster.exe` and its wordlist at
`wordlists\common.txt`.

## First-time setup

Open PowerShell and run these commands from the project directory:

```powershell
Set-Location 'D:\security project'

# Create a fresh environment. Do not use the checked-in venv; it belongs to
# the computer on which the project was originally developed.
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, either allow scripts for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

or use the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Install external scanners

Install Nmap and add it to PATH, or configure its absolute executable path.
No executable path is hard-coded in the application. An explicit invalid path
fails instead of silently falling back. CIDR scans use Nmap directly; Angry IP
Scanner is no longer required.

```powershell
# Configure only targets you own or have explicit permission to assess.
$env:RISKLENS_ALLOWED_TARGETS = '127.0.0.1/32'

# If Nmap is already on PATH:
$env:RISKLENS_NMAP_PATH = (Get-Command nmap -ErrorAction Stop).Source

# Alternatively, resolve your installed executable, for example:
# $env:RISKLENS_NMAP_PATH = (Resolve-Path 'C:\Program Files (x86)\Nmap\nmap.exe').Path

# Optional: needed only when explicitly selecting the Web profile.
$env:RISKLENS_GOBUSTER_PATH = (Resolve-Path '.\gobuster_Windows_x86_64\gobuster.exe').Path
```

Scope is a comma-separated list of canonical IPs/CIDRs. It is empty by default:
no scope means no scan. Hostnames, implicit subnet expansion, targets outside
scope, multicast/unspecified/link-local/reserved addresses, and requests without
`authorized: true` are rejected. Loopback is supported. A scan permits at most
32 total CIDR addresses, 100 Quick ports or 1,000 Standard ports, and one active
job per application process. Run a single Uvicorn worker.

## Local result viewing

No API key is required. Result and report handlers do not call external enrichment
services. The legacy credential-checking implementation is retained as unused
source, is not imported by the application, and its optional Paramiko dependency
is no longer installed by the application requirements.

## Start the application

From the project root, with the virtual environment active:

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8787 --reload
```

Keep this PowerShell window open. Open the UI at:

<http://127.0.0.1:8787>

Alternatively, use the included launcher:

```powershell
.\run.ps1
```

To choose another port:

```powershell
.\run.ps1 -Port 9000
```

Verify the backend before scanning:

```powershell
Invoke-RestMethod http://127.0.0.1:8787/health
```

The response should include `"status": "ok"`.

## Run a scan

1. Configure the server's approved scope before launch, then enter an approved
   literal IP, IP:port, HTTP(S) IP origin, or canonical CIDR in **Target**.
2. Choose exposure context and Quick, Standard, or explicit Web assessment.
3. Check the authorization acknowledgement and click **Start scan**.
4. Polling reports the worker's actual completion or error; a saved file cannot
   erase a failure. No automatic credential testing or online enrichment occurs.
5. Review network ports and their recorded state. The Web tab is separate.
6. Open Details for local guidance, or download CSV/PDF from saved evidence.

A `.0` address remains a single address. CIDR is limited to 32 total addresses
(e.g. `/27` or smaller IPv4 networks); network/broadcast addresses are excluded
where `ipaddress.hosts()` does so. Approved private targets are not inferred from
a private address: they must still match server scope. Scope is checked again
before the worker executes. Multiple IP families cannot be mixed in one scan.

### Scan profiles

| Profile | Default TCP coverage | Version probes | HTTP/Gobuster | Process limit |
|---|---|---|---|---|
| Quick | Top 100 ports | No | No | 120 seconds |
| Standard | Top 1,000 ports | `-sV --version-light` | No | 300 seconds |
| Web | One explicit HTTP(S) port | Light | Explicit opt-in | Nmap 300 seconds; Gobuster 120 seconds |

Validated explicit ports replace top-port defaults and remain subject to the
profile's port-count cap. Both network profiles use `-sT -n -Pn -T3`, one retry,
and 30-second Quick / 60-second Standard per-host timeout. No OS guessing,
`--script vuln`, `-sC`, `-A`, or automatic retry with different flags is used.
Vulnerability/full profile strings return HTTP 400 and are disabled in the UI.
Standard performs active service/version probes; Quick performs TCP connects.
Windows Nmap/Npcap permissions must still be configured appropriately.

The Web profile accepts a single approved origin and one port, does not follow
redirects, does not retry HTTPS or disable certificate verification after an
HTTP failure, and uses two Gobuster threads. Existing saved NSE/OS evidence is
still readable; new network scans do not request OS or vulnerability scripts.

Interactive API documentation: <http://127.0.0.1:8787/docs>.

The **Findings** tab converts raw scanner output into prioritized findings with
severity, confidence, affected asset, evidence, source, and remediation. Use
**Download CSV** for spreadsheet analysis; the PDF report includes the same
evidence-based findings section.

The **Scan History** tab keeps completed and in-progress scan metadata across
server restarts. Select **View results** to reload a previous scan's services,
findings, asset inventory, web results, and attack graph. The **Clear saved
scans** button removes the saved history metadata.

## Stop and restart

Press `Ctrl+C` in the Uvicorn PowerShell window to stop the server. Start it
again with the same command. Scan output is written under
`backend\scans\` and are retained so the Scan History tab can reload previous
results.

## Troubleshooting

### `ModuleNotFoundError`

Make sure the fresh environment is active and reinstall dependencies:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Scanner configuration errors

A missing or invalid executable returns HTTP 503 before any job is created.
Set `RISKLENS_NMAP_PATH` or use PATH; Web additionally needs Gobuster. Scope or
authorization denial returns 403, malformed input/disabled profile returns 400,
and an already active scanner returns 409. No automatic retry is performed.

### PowerShell says the old `venv` is invalid

The checked-in `venv` records an absolute Python path from another computer.
Ignore or remove that environment and use the fresh `.venv` created above.

### Empty CVE results

The compatibility `/scan/{scan_id}/nvd` endpoint is retained for the existing UI,
but returns `status: not_queried` with no live NVD request. Existing raw XML does
not contain previous NVD keyword-enrichment results. No result-viewing operation
attempts credentials or contacts saved targets.

## Regression tests

```powershell
Set-Location 'D:\security project'
& '.\.venv\Scripts\python.exe' -m pip install -r requirements-dev.txt
& '.\.venv\Scripts\python.exe' -B -m unittest discover -s tests -v
```

The suite uses synthetic XML, mocked scanner processes, and in-process HTTP requests. It blocks
outbound requests, DNS, socket connections, subprocesses, and credential annotation
while reading every GET route, including CSV/PDF. Scanner submission is tested
with mocked workers, not a real target scan.


### Nmap artifacts and failures

Completed scans retain `backend/scans/<id>.xml`. Nmap writes `.xml.tmp` first;
only XML with successful run statistics, the requested hosts, and matching TCP
port coverage is published. Rejected/partial XML is retained as `.xml.partial`.
`nmap_<id>.json` records exact arguments, approved scope, timeout, exit code,
stderr tail, and outcome. Status/history remain in `scan_status.json` with
additive fields for approved targets, requested ports, Nmap state, and exit code.
Old JSON records still load. Interrupted jobs become failed on restart and are
never automatically resumed. See [Day 3 implementation and tests](docs/DAY-03.md).

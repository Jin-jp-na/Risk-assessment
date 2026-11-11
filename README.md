# RiskLens

RiskLens is a Windows web application that runs Nmap service discovery and
vulnerability NSE scripts,
enriches services with NVD vulnerability data, calculates a contextual risk
score, checks selected weak credentials, builds an attack graph, and optionally
performs web directory discovery with Gobuster.

Only scan systems that you own or have explicit permission to assess.

## Requirements

- Windows 10 or Windows 11
- Python 3.11 or newer (Python 3.13 is supported by the included dependency set)
- Nmap for Windows
- Angry IP Scanner, required only for CIDR/subnet scans
- A modern browser
- Internet access for NVD lookups, the CDN-loaded frontend libraries, and
  optional Gemini remediation

The repository contains a Windows Gobuster executable at
`gobuster_Windows_x86_64\gobuster.exe` and its wordlist at
`wordlists\common.txt`.

## First-time setup

Open PowerShell and run these commands from the project directory:

```powershell
cd F:\kale\PCVP

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

Install Nmap so this file exists:

```text
C:\Program Files (x86)\Nmap\nmap.exe
```

Install Angry IP Scanner so this file exists:

```text
C:\Tools\AngryIP\ipscan.exe
```

The paths are currently configured in `backend\main.py`. If you install either
tool elsewhere, update `NMAP_PATH` or `IPSCAN_PATH` before running the server.
Gobuster is already included and normally requires no separate installation.

Check the required files:

```powershell
Test-Path 'C:\Program Files (x86)\Nmap\nmap.exe'
Test-Path 'C:\Tools\AngryIP\ipscan.exe'
Test-Path '.\gobuster_Windows_x86_64\gobuster.exe'
Test-Path '.\wordlists\common.txt'
```

The first two commands should return `True`.

## Optional API keys

The application works without these keys, but some features are reduced:

- `NVD_API_KEY` increases the NVD API request allowance.
- `GEMINI_API_KEY` enables LLM-generated remediation in the service details
  dialog. Without it, the UI displays an explanatory fallback.

Set keys only in the current PowerShell session:

```powershell
$env:NVD_API_KEY = 'your-nvd-key'
$env:GEMINI_API_KEY = 'your-gemini-key'
```

Do not commit keys to the repository. To make them persistent, configure them
through Windows environment-variable settings instead of placing them in
source code.

## Start the application

From `F:\kale\PCVP`, with the virtual environment active:

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

1. Enter a permitted hostname or IP address in **Target**, for example
   `scanme.nmap.org` or `192.168.1.10`.
2. Choose **Auto**, **External**, or **Internal** exposure context.
3. Click **Start scan**.
4. Wait for Nmap, its `vuln` NSE checks, and (for web targets) Gobuster to
   complete. NSE checks can take longer than a basic port scan.
5. Review **Overview**, **Services**, **Attack Graph**, and **Web Scan**.
6. Open **Details** for remediation and use **Download PDF** when the scan is
   complete.

For a specific port, enter it as part of the target, such as
`192.168.1.10:8080`. CIDR targets such as `192.168.1.0/24` use Angry IP
Scanner to find live hosts first, so they take longer and skip Gobuster.

The server also exposes interactive API documentation at:

<http://127.0.0.1:8787/docs>

Nmap vulnerability-script evidence appears in the **NSE Findings** column and
in each service's **Details** dialog. The scan uses `--script vuln`, `-Pn`, and
OS detection with a safe fallback when elevated Nmap probes are unavailable.
Only scan systems for which you have explicit authorization because some NSE
checks can be intrusive and may generate more traffic than service discovery.

The Overview tab also provides an asset inventory with IP addresses, hostnames,
reverse-DNS names, MAC/vendor data when available, OS matches, services, and
ports. The Web Scan tab adds HTTP status/header checks, security-header
coverage, technology hints, TLS protocol/cipher information, and certificate
metadata when the target uses HTTPS.

### Scan profiles

Choose a profile before starting a scan:

- **Quick discovery**: fast host and port discovery without the heavier checks.
- **Standard**: service/version detection with the normal RiskLens workflow.
- **Vulnerability assessment**: service detection, OS detection, and Nmap
  `vuln` NSE checks.
- **Web assessment**: standard discovery plus HTTP/TLS and Gobuster checks.
- **Full lab assessment**: all available network and web checks.

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

### Nmap or Angry IP errors

Confirm the executable paths with the `Test-Path` commands above. If they are
different, update the two constants in `backend\main.py` and restart Uvicorn.

### PowerShell says the old `venv` is invalid

The checked-in `venv` records an absolute Python path from another computer.
Ignore or remove that environment and use the fresh `.venv` created above.

### No CVE results

NVD lookups require internet access and work best when Nmap identifies a
product and version. Set `NVD_API_KEY` if the public NVD rate limit is reached.

### Remediation says `GEMINI_API_KEY not set`

Set `GEMINI_API_KEY` in the same PowerShell window before starting Uvicorn,
then restart the server.

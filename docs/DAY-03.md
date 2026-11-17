# Day 3 — bounded Nmap profiles and explicit authorized scope

## What the inspected code did

The starting point was the existing Day 2 working tree; its uncommitted changes
were preserved. The original single-target commands assembled in the main module
were:

```text
Quick:    nmap -T4 -Pn [-p PORTS] -oX backend/scans/ID.xml IP
Standard: nmap -sV -T4 -Pn [-p PORTS] -oX backend/scans/ID.xml IP
```

Neither supplied a smaller default port set for Quick. Without `-p`, Nmap's
normal TCP coverage is the most common 1,000 ports. Standard also automatically
scheduled HTTP/TLS assessment and Gobuster. The CIDR branch first ran Angry IP
Scanner, then ignored the selected profile and ran:

```text
nmap -sV -O --osscan-guess -T4 -Pn --script vuln [-p PORTS] -oX ID.xml.tmp IP...
```

Single-target processes had no application timeout. A failed command was retried
with OS-detection arguments removed, even when the failure was unrelated. Status
polling could overwrite failure based on XML size and a Gobuster `.done` marker.
The target parser allowed hostnames and silently converted `.0` addresses to /24.
XML reads waited up to ten seconds for the scanner to finish writing.

## Implemented profiles and real commands

[scan_policy.py](../backend/scanner/scan_policy.py) contains one command builder
for single targets and CIDRs. With default ports, the new commands are:

```text
Quick:
nmap -sT -n -Pn -T3 --max-retries 1 --host-timeout 30s --top-ports 100 -oX ID.xml.tmp IP...

Standard:
nmap -sT -n -Pn -T3 --max-retries 1 --host-timeout 60s -sV --version-light --top-ports 1000 -oX ID.xml.tmp IP...
```

The worker uses an argument list, `shell=False`, captured text output, a bounded
stderr tail, and a subprocess timeout of 120 seconds for Quick or 300 seconds
for Standard. IPv6 adds `-6`. Explicit validated ports replace `--top-ports` with
`-p` and a canonical numeric list. No silent fallback/retry changes the flags.

Quick has no version detection or NSE selection. Standard performs active light
service/version probing, not a vulnerability assessment. No supported profile
requests `--script vuln`, `-sC`, `-A`, OS guessing, UDP scans, or credential tests.
Quick/Standard do not schedule HTTP/Gobuster. The old vulnerability/full profile
values return HTTP 400 and are disabled visibly in the UI rather than silently
mapped to a different profile. Existing historical results remain readable.

Nmap's documentation describes [TCP connect scans](https://nmap.org/book/man-port-scanning-techniques.html),
[top-port coverage](https://nmap.org/book/man-port-specification.html),
[timeouts/retries](https://nmap.org/book/man-performance.html), and
[light service detection](https://nmap.org/book/man-version-detection.html).
`--version-light` means intensity 2, not passive banner viewing or a guarantee
that no application probes occur. Nmap may use its built-in version-detection
mechanisms; no generic/vulnerability NSE category is requested.

## Authorization and configuration

- `RISKLENS_ALLOWED_TARGETS` is an operator-configured, comma-separated list of
  canonical IPs/CIDRs. Empty scope denies every new scan. Private IPs receive no
  implicit authorization. The request must additionally contain `authorized: true`.
- Inputs must be literal IPv4/IPv6 addresses, IP:port, HTTP(S) IP origins, or
  canonical CIDRs. Hostnames, shell/option-like strings, lists in one target,
  credentials, URL paths, queries, fragments, and zone IDs are rejected.
- CIDRs have at most 32 total addresses and must be fully contained in approved
  scope. `ipaddress.hosts()` determines the explicit finite address list. A `.0`
  address remains a single address. No Angry IP executable/discovery dependency.
- Mixed IP families, unspecified, multicast, link-local, and reserved targets are
  unsupported; loopback is permitted if explicitly approved. IPv6 support is
  limited to literal unicast targets, not zone-scoped discovery.
- Quick permits at most 100 distinct explicit ports; Standard at most 1,000.
  Only ascending numeric ports/ranges within 1–65535 are accepted. Conflicting
  target and body ports are rejected.
- The saved authorization flag, target list, approved scope, profile, and ports
  are checked again before the worker runs. One job at a time is admitted per
  process. A second job receives 409, rather than waiting in an unbounded queue.
- Nmap resolves from the validated absolute `RISKLENS_NMAP_PATH`, or
  `shutil.which('nmap')` when unset. Invalid explicit configuration does not fall
  back. Windows tools must resolve to existing `.exe` files; no batch wrapper or
  source-code installation path is assumed. Tool identity/provenance is trusted
  local configuration, not cryptographically verified.

The explicit Web profile remains available only for one approved IP origin and
one port. It resolves Gobuster through `RISKLENS_GOBUSTER_PATH` or PATH and retains
the existing project wordlist. Redirect following, insecure HTTP certificate
fallback, and automatic HTTP-to-HTTPS retry were removed to avoid escaping scope.
Requests ignores ambient proxies; Gobuster receives an environment without proxy
variables. Gobuster uses two threads and a 120-second process timeout. A nonzero
exit fails even with empty stderr or partial output. This is explicit enumeration,
not part of Quick/Standard.

## Status, JSON storage, and XML

The endpoints and original response fields remain. Request authorization and
status metadata are additive. The compatibility `/nvd`, report, graph, and other
read paths remain local and do not start scanning. Existing saved JSON loads
with defaults for new fields.

```text
POST /scan -> pending -> running -> completed | failed
Web only: Nmap success -> nmap_done -> completed | failed (with separate web state)
```

Status is set by the worker. `GET /scan/{id}` reports it without inferring success
from files. `completed_at` is set on success/failure. Interrupted pending/running
jobs are marked failed and persisted at startup; they are never resumed. Clearing
history during an active job returns 409. JSON status writes share a local lock
and atomic replace; use one Uvicorn process.

Artifacts stay under [backend/scans](../backend/scans):

- `<id>.xml.tmp`: scanner's working output.
- `<id>.xml`: final artifact, published by atomic replace only after validation.
- `<id>.xml.partial`: rejected/interrupted output when present.
- `nmap_<id>.json`: exact argument list, timeout, authorization/scope, targets,
  ports, timestamps, exit code, stderr tail, outcome, and artifact reference.
- `alive_<id>.json`: approved CIDR hosts reported up, for the existing API.
- `scan_status.json`: existing status/history store plus the additive metadata.

The worker requires exit code zero, parseable XML within 16 MiB, successful Nmap
run statistics, all requested host addresses, no unexpected addresses/explicit
TCP ports, and no reported host timeout. Missing hosts are incomplete coverage,
not closed ports. Invalid output is never published as a new successful artifact.
Reads reject incomplete XML immediately instead of sleeping. Entity expansion is
disabled. Recorded open/closed states remain in parsed JSON and are now visible
in the Services table. Non-open ports are not scored as open exposures or turned
into findings. An open port alone still does not prove a vulnerability.

HTTP errors before scheduling: 400 invalid input/disabled profile; 403 missing
authorization/scope or out-of-scope target; 503 bad executable/server scope
configuration; 409 scanner busy; 500 storage/scheduling failure. After acceptance,
process errors are reported in saved scan status with diagnostics, not as an HTTP
exception after the response has already been sent.

## Files changed this day

- [main.py](../backend/main.py): scan entry/worker/status/XML handling; remove Angry
  discovery and hard-coded tool paths; scope-safe explicit web dispatch.
- [scan_policy.py](../backend/scanner/scan_policy.py), new: configuration validation,
  finite targets/ports/scope, and shared Nmap command construction.
- [app.js](../frontend/static/app.js): send authorization acknowledgement, show API
  errors and recorded port state.
- [index.html](../frontend/templates/index.html): authorization checkbox, accurate
  profile descriptions, disabled intrusive profiles, script cache version 20.
- [test_read_only_endpoints.py](../tests/test_read_only_endpoints.py): adapt existing
  synthetic fixtures to explicit scope and the new profile behavior.
- [test_scan_execution.py](../tests/test_scan_execution.py), new: policy, profile,
  worker, failure, restart, XML, and explicit-web scope regressions.
- [README.md](../README.md): configuration, profile semantics, artifacts, and errors.
- [DAY-03.md](./DAY-03.md): this handoff.
- [day3-changes.patch](../artifacts/day3-changes.patch): this day's diff against the
  saved Day 2 state, including the new files. Earlier uncommitted Day 2 work is
  not included in that patch and was not reverted.

No new packages, database, queue service, framework, AI feature, or live target
scan was introduced. [run.ps1](../run.ps1) remains compatible with environment
configuration and localhost binding.

## Exact Windows PowerShell commands

Use the existing working environment. Install development dependencies only if
not already present:

```powershell
Set-Location 'D:\security project'
& '.\.venv-baseline\Scripts\python.exe' -m pip install -r '.\requirements-dev.txt'
& '.\.venv-baseline\Scripts\python.exe' -B -m unittest discover -s tests -v
node --check '.\frontend\static\app.js'
node '.\tests\test_service_details.js'
git diff --check
```

Verified here on Python 3.14.3: **29 Python tests pass**, plus the frontend syntax
and Details-handler checks. The suite exercises real API handlers, XML parsing,
CSV and PDF exports with synthetic files; every Nmap/Gobuster process is mocked.
It proves profile flags, scope rejection, resource limits, successful XML/port
results, timeout, exit/stderr preservation, corrupt/missing/incomplete XML,
scope revocation, job concurrency, and restart reconciliation. Read-only tests
still block network requests, DNS, socket connections, and credential calls.
Editor diagnostics and whitespace checks pass. A pre-existing TemplateResponse
deprecation warning remains.

To launch after stopping any previously running app, in terminal 1:

```powershell
Set-Location 'D:\security project'
$env:RISKLENS_ALLOWED_TARGETS = '127.0.0.1/32'
# Use this machine's existing installation as explicit configuration:
$env:RISKLENS_NMAP_PATH = (Resolve-Path 'C:\Program Files (x86)\Nmap\nmap.exe').Path
# Or, if Nmap is on PATH: Remove-Item Env:RISKLENS_NMAP_PATH
& '.\.venv-baseline\Scripts\python.exe' -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

This does not authorize any LAN or public target. Change the scope only to
systems for which you have explicit authorization. Another approved IP/CIDR may
be appended with a comma. Do not start multiple Uvicorn workers. The original
launcher can instead be used with its expected `.venv` environment.

Optional manual loopback assessment in terminal 2, only when you choose to run a
real scan of this local app (these requests were not executed during development):

```powershell
Invoke-RestMethod 'http://127.0.0.1:8787/health'
$body = @{ target='127.0.0.1'; profile='quick'; ports='8787'; authorized=$true } | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post 'http://127.0.0.1:8787/scan' -ContentType 'application/json' -Body $body
$scan.scan_id
$deadline = (Get-Date).AddSeconds(135)
do {
    Start-Sleep -Seconds 1
    $status = Invoke-RestMethod "http://127.0.0.1:8787/scan/$($scan.scan_id)"
} while ($status.status -notin @('completed','failed') -and (Get-Date) -lt $deadline)
$status | Format-List
if ($status.status -eq 'completed') {
    $parsed = Invoke-RestMethod "http://127.0.0.1:8787/scan/$($scan.scan_id)/parsed"
    $parsed.data.hosts.services | Format-Table port,protocol,state,service
}
```

Expected when Nmap can reach the running local app: pending/running then
`completed`, `gobuster_status: skipped`, `nmap_exit_code: 0`, and recorded TCP
port 8787 `open`. Windows/Npcap, firewall, permissions, and actual listening
services can change observed results. On error, expect `failed`, a terminal
timestamp and diagnostic message; inspect `nmap_<id>.json` and any partial XML.
The client loop itself has a deadline, so it does not poll forever.

## Limits and stop

No actual Nmap/Gobuster process or target scan was executed. Windows binary
compatibility/Npcap permissions remain an operator verification step; mocked
success is not proof of real network reachability. Service/version detection is
active and can be misidentified; a host timeout or missing XML is an incomplete
assessment. IPv6 zone-scoped targets and hostname resolution are intentionally
unsupported. TCP-only coverage, 32-address cap, and one-process/one-job operation
are deliberate MVP limits. Explicit web HTTP/socket operations retain their
per-operation timeouts; only Nmap and Gobuster have hard process deadlines.

Reports, historical JSON/XML, deterministic remediation, and the no-hidden-read
activity protections remain. Broader findings rules and the Exposure Change
Detector are outside this day. Stop here.

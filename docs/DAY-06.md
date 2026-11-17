# Day 6 — optional path observations and independent web rules

## What the real code did before this change

Inspected `run_gobuster_scan()`, its callers and result readers, the bundled
wordlist, the frontend request/render code, and existing regression tests.
The bundled Gobuster executable reports version 3.8.2 in its local
`dir --help`; that help confirms the flags used below, verified TLS by default,
and redirect following disabled by default. Only help was executed, not a scan.

Previously every authorized Web profile ran HTTP/TLS assessment followed by
Gobuster. Submission required Gobuster even when only HTTP evidence was wanted.
The command used safe subprocess arguments with two workers, 10-second HTTP
timeout and 120-second process timeout, but no request delay or operator stop.
`wordlists/common.txt` contains 4,751 lines, including `.env`, `.git/config`,
and shell history paths. Its size exceeds a small local assessment's needs.
The path parser produced `{path, status, size}`. The frontend inserted these
values into HTML without escaping and described completion as Nmap + Gobuster.
Web header findings shared one generic rule ID and lacked re-test instructions;
certificate errors did not generate a separate actionable rule.

Implemented plan: preserve the worker and old JSON fields, make discovery a
separate opt-in within the Web job, bound the wordlist/process/rate, retain saved
path evidence, and expose deterministic web rules independently of path results.
Normal Nmap scans, stored artifacts and HTTP/TLS assessment remain usable.

## Files modified and new files

- [backend/main.py](../backend/main.py): default-false `path_discovery` request
  and persisted flag, saved exact `web_url`, independent `web_status`, worker
  validation and optional execution, stop endpoint, path status/observations,
  saved-data web findings endpoint, CSV re-test column, web findings in PDF input.
- [backend/scanner/path_discovery.py](../backend/scanner/path_discovery.py)
  **new**: bounded wordlist snapshot, safe Gobuster process lifecycle and parser.
- [backend/scanner/web_rules.py](../backend/scanner/web_rules.py) **new**:
  deterministic rules using saved checks/certificate errors only.
- [wordlists/web-safe.txt](../wordlists/web-safe.txt) **new**: 15 common paths.
  The original [common.txt](../wordlists/common.txt) is preserved and unused by
  the optional job. No automatic full-list fallback occurs.
- [frontend/templates/index.html](../frontend/templates/index.html): unchecked
  optional checkbox, independent web findings panel, path-job state and stop.
- [frontend/static/app.js](../frontend/static/app.js): explicit request flag,
  truthful job messages, saved web rule rendering with remediation/re-test,
  escaped path values, incomplete coverage and skipped states. Invalidate the
  old cached path HTML once. Restoring history does not opt into a future job.
- [tests/test_path_discovery.py](../tests/test_path_discovery.py) **new**: 18
  process, policy, job, saved-data and rule regressions.
- [tests/test_path_discovery.js](../tests/test_path_discovery.js) **new**:
  actual frontend path renderer, HTML escaping, opt-in markup and job states.
- [tests/test_web_assessment.js](../tests/test_web_assessment.js): assert the
  additional saved-rule request, rule evidence, remediation and re-test display.
- [tests/test_read_only_endpoints.py](../tests/test_read_only_endpoints.py) and
  [tests/test_scan_execution.py](../tests/test_scan_execution.py): explicitly
  opt into existing path-job tests and mock the new process boundary.
- This document and [the exact Day 6 patch](../artifacts/day6-changes.patch).

No dependencies, AI features, credential checks, external analytics, or intrusive
NSE scripts were added. The Day 5 transport/header checker was reused unchanged.

## Execution, scope, output and stopping

`POST /scan` still requires `authorized: true` plus operator-configured IP scope.
The Web profile performs its existing Nmap and verified HTTP/TLS assessment.
`path_discovery` defaults to **false**, including old persisted scans without
this field. Only Web requests can opt in. Missing Gobuster never prevents a
default HTTP/TLS-only job. For opted-in jobs, binary or discovery failure is
recorded separately after HTTP/TLS evidence is saved.

Optional command, expressed as arguments rather than a shell command string:

```text
<resolved gobuster.exe> dir -u <saved exact origin>
  -w <saved 15-path snapshot> -o <saved output>
  -t 1 --delay 1s --timeout 5s --no-color --no-progress -q
```

One worker waits one second between wordlist requests. Gobuster also performs
its own startup/wildcard prechecks; the delay is not a global transport-level
rate limiter for those probes. Only one application scan job can run at a time.
Wordlist validation allows at most 32 short relative entries and an 8 KiB file;
schemes, query strings, empty segments and traversal are rejected. The shipped
15-path list avoids sensitive-file enumeration. No extensions, recursion,
credentials, retries, force, redirect following, or TLS bypass flags are used.
Environment proxy settings are removed from the child process.

Before assessment and child launch, validate current and saved scope, saved
authorization, completed network step, exact IP, requested port and saved
scheme/IP/port origin. DNS names are still unsupported, avoiding DNS rebinding.
Revalidate scope about every 200 ms while the child runs. This polling is a
bounded detection delay, not packet-level enforcement against simultaneous
configuration edits; the command itself always contains the approved numeric
origin and never follows redirects.

The child has a 120-second job deadline, polled every 200 ms, and a five-second
HTTP request timeout. Stop, deadline, scope revocation or an early exit kills
the actual child if still running and waits up to five seconds to reap it.
No shell process, background detached scanner, insecure retry or auto-resume.
The Stop button calls `POST /webscan/{scan_id}/stop`; it can also cancel a
pending optional job before launch. It stops discovery only, not Nmap or the
initial HTTP/TLS assessment. The HTTP response acknowledges `stop_requested`;
the worker records `cancelled` after stopping. No active job returns 409;
unknown scan returns 404.

Saved files keep their existing names: `web_audit_<id>.json`,
`gobuster_<id>.txt`, `.status`, and `.done`. Added `.words.txt`, `.stdout.log`,
and `.stderr.log` preserve the exact bounded input and process diagnostics.
The status JSON includes enabled flag, exact URL, rate settings, timestamps,
word count when available, command on successful completion, error details and
terminal state. Status publication is atomic. Failed/stopped jobs retain any
partial path output and clearly mark incomplete coverage.

`GET /webscan/{id}/results` preserves `scan_id`, `results`, `error`,
`error_detail`, and adds `enabled`, `discovery_status`, `partial`. States include
`pending`, `running`, `skipped`, `completed`, `failed`, `timed_out`, `cancelled`.
Each path preserves `path`, numeric `status`, optional `size`, adding original
line `evidence`, `category: path_observation`, and a conservative interpretation.
Redirect destinations in output are text evidence, never followed or linked.
Empty completed output means no observed paths under this limited coverage;
missing/failed/cancelled output is not presented as successful negative coverage.
404 is excluded by Gobuster's default status filter. Paths never generate
vulnerability findings, regardless of status code or name.

`GET /webscan/{id}/assessment` retains the Day 5 artifact contract.
New `GET /webscan/{id}/findings` returns `{scan_id, findings}` from that saved
artifact alone, even without Nmap XML or successful Gobuster. The Web panel
always displays those rules independently. Existing combined findings/CSV/PDF
also receive web findings when a saved assessment is available. Overall scan
completion reflects network/HTTP assessment; optional discovery failure appears
in `gobuster_status` and the completion message rather than hiding web findings.
All GET endpoints remain read-only and never start a scanner, TLS connection,
DNS lookup, password attempt, or automatic re-test.

## Rules

Every emitted rule carries `id`, `rule_id`, title, evidence, original evidence,
severity, confidence scope, domain, verification status, remediation, and
explicit `retest` instructions. No claim of exploitation is made.

| ID | Saved evidence trigger | Severity | Action and explicit re-test |
|---|---|---|---|
| WEB-HDR-001 | HTTPS HSTS missing, empty, invalid max-age or max-age=0 | info | Review positive max-age and subdomain readiness; repeat authorized Web assessment and inspect HSTS. HTTP is not applicable. |
| WEB-HDR-002 | CSP missing or empty | info | Design/test an application-appropriate CSP, initially report-only; repeat assessment and review the header. |
| WEB-HDR-003 | XCTO absent or not nosniff | info | Set nosniff and correct Content-Type; repeat and inspect the exact value. |
| WEB-HDR-004 | XFO absent or not DENY/SAMEORIGIN | info | Review framing needs/CSP frame-ancestors and legacy XFO; repeat and inspect headers. CSP may already provide adequate framing policy. |
| WEB-HDR-005 | Referrer-Policy absent or no recognized value | info | Select a supported application-appropriate policy; repeat and review the value. |
| WEB-HDR-006 | Permissions-Policy absent or empty | info | Restrict unneeded browser features after reviewing application needs; repeat and inspect policy. |
| WEB-TLS-001 | certificate_verification_failed from verified transport | low | Review dates, trust chain/issuer and matching IP SAN; repeat with verification enabled and expect verified TLS/HTTP evidence. |

Nonempty CSP/Permissions-Policy need review rather than automatic approval.
No HTTP response produces no missing-header rules. A TLS verification failure
does not establish interception; a private CA may simply be untrusted locally.
Opening saved results never performs the re-test.

## PowerShell run and tests

Use the existing environment. If reconstructing a clean checkout, create it and
install development requirements first:

```powershell
Set-Location 'D:\security project'
# Only if the environment does not already exist:
py -m venv .venv-baseline
& '.\.venv-baseline\Scripts\python.exe' -m pip install -r .\requirements-dev.txt
```

Mocked tests need neither an installed Gobuster nor a reachable target:

```powershell
Set-Location 'D:\security project'
& '.\.venv-baseline\Scripts\python.exe' -B -m unittest discover -s tests -v
node .\tests\test_service_details.js
node .\tests\test_web_assessment.js
node .\tests\test_path_discovery.js
git diff --check
```

Expected: 75 Python tests, `OK`, and three frontend `PASS` lines. Tests cover
successful/empty discovery, missing executable, timeout kill/reap, operator stop,
scope revocation and changed origin, unsafe wordlist, exact rate/arguments,
partial failures, conservative rules, no automatic discovery on default Web,
independent findings, escaped path output, and all earlier regression cases.
The pre-existing Starlette template deprecation warning may appear.

Launch locally; the example approves only loopback:

```powershell
Set-Location 'D:\security project'
$env:RISKLENS_ALLOWED_TARGETS = '127.0.0.1/32,::1/128'
$env:RISKLENS_ALLOWED_WEB_PORTS = '80,443,8080,8443'
# For live jobs, Nmap must be on PATH or set RISKLENS_NMAP_PATH to its installed executable.
# Optional discovery can use the bundled executable, or Gobuster on PATH:
$env:RISKLENS_GOBUSTER_PATH = (Resolve-Path '.\gobuster_Windows_x86_64\gobuster.exe').Path
& '.\.venv-baseline\Scripts\python.exe' -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

In another terminal, check health and optionally run an owned local fixture:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8787/health'
# Separate terminal; keep it running only for the optional local exercise:
Set-Location 'D:\security project'
& '.\.venv-baseline\Scripts\python.exe' -m http.server 8080 --bind 127.0.0.1 --directory .\frontend\static
```

Submit and inspect HTTP/TLS only (no Gobuster needed). This manual exercise
still runs the existing Nmap step and requires installed/configured Nmap:

```powershell
$body = @{target='http://127.0.0.1:8080'; profile='web'; ports='8080'; authorized=$true; path_discovery=$false} | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post 'http://127.0.0.1:8787/scan' -ContentType 'application/json' -Body $body
$deadline = (Get-Date).AddSeconds(450)
do {
    Start-Sleep -Seconds 1
    $state = Invoke-RestMethod "http://127.0.0.1:8787/scan/$($scan.scan_id)"
} while ($state.status -notin @('completed','failed') -and (Get-Date) -lt $deadline)
$state | Format-List
Invoke-RestMethod "http://127.0.0.1:8787/webscan/$($scan.scan_id)/assessment" | ConvertTo-Json -Depth 12
Invoke-RestMethod "http://127.0.0.1:8787/webscan/$($scan.scan_id)/findings" | ConvertTo-Json -Depth 12
Invoke-RestMethod "http://127.0.0.1:8787/webscan/$($scan.scan_id)/results" | ConvertTo-Json -Depth 6
```

Expected if Nmap/fixture succeed: overall `completed`, `web_status: completed`,
`gobuster_status: skipped`, saved HTTP status 200, configuration observations,
and empty path results. Health returns `status: ok`. A failed network step skips
web entirely; do not interpret absent assessment as empty findings.

To explicitly opt into a new local path job, change only the boolean and submit
again. This intentionally makes requests to the owned fixture:

```powershell
$body = @{target='http://127.0.0.1:8080'; profile='web'; ports='8080'; authorized=$true; path_discovery=$true} | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post 'http://127.0.0.1:8787/scan' -ContentType 'application/json' -Body $body
# Optional while that path job is pending or running:
Invoke-RestMethod -Method Post "http://127.0.0.1:8787/webscan/$($scan.scan_id)/stop"
# Poll /scan/{id} as above, then inspect the saved path state:
Invoke-RestMethod "http://127.0.0.1:8787/webscan/$($scan.scan_id)/results" | ConvertTo-Json -Depth 6
```

Expected stop acknowledgement: `stop_requested`, then terminal discovery
`cancelled` if it had not already finished. Without stopping, this particular
static fixture may produce no listed paths; that is a successful empty
observation set, not proof of security. Missing Gobuster gives discovery
`failed` and an explicit error while completed HTTP findings stay available.
Timeout gives `timed_out` with incomplete coverage. Outside-scope submission
returns 403 before any job/probe; changed worker origin fails before HTTP or
child launch. Test those failure modes with the mocked suite rather than an
unauthorized live target.

## Limits and stop

Verification used mocked HTTP/process responses and the executable's local
help; no live Nmap/Gobuster assessment or target HTTP request was performed.
Gobuster's startup prechecks are additional requests. A one-second per-worker
delay is not a precise aggregate RPS budget. The 15-path list is deliberately
incomplete, wildcard responses can prevent discovery, and different Gobuster
versions may reject flags or use an unsupported output format (failures are
reported; no unsafe fallback). Scope changes are observed by polling; they do
not retract requests already in flight. Stop affects only optional discovery.
TLS/header results retain Day 5's transport limits and require application
context. Historic outputs remain readable but cannot gain missing evidence
without an explicit new scan. No Exposure Change Detector was added. Stop here.

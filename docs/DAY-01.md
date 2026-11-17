# RiskLens 2.0 — Day 1: inspect before changing behavior

Inspected 2026-11-16. Day 1 is the source/ZIP inventory, evidence review, and a
14-day implementation plan. Application behavior is unchanged. Days 2–14 below
are proposed scopes, not completed work. No targets were scanned.

Follow-up: [working baseline guide](./DAY-01-BASELINE.md) records the successful
localhost launch and HTTP health/root/static checks, source tree, architecture,
setup instructions, checklist, five priority issues, and Git commands.

## 1. What is actually here

The backend source archive is [backend ZIP](../backend-20261016T162918Z-1-001.zip)
(40 entries); the [frontend ZIP](../frontend-20261016T162919Z-1-001.zip) has four
entries. All four frontend source files are byte-identical to the working copy.
Six of eight backend Python files are byte-identical. The credential module
differs only in comments. The main module also changes a response import from
FastAPI to Starlette. The inspection record includes the actual unified diff,
SHA-256 hashes, syntax results, routes, and frontend call sites.

Other archives: a 244-entry Git archive, two byte-identical three-entry Gobuster
archives, and a one-entry wordlist archive. These were inventoried without
extraction. The Git archive was not restored, and packaged executables were not
run. ZIP hashes establish identity, not executable authenticity.

The working tree was already dirty: application/comment edits, tracked bytecode,
history metadata, and additional raw scans. Those were preserved. ZIP comparison
is separate from comparison against Git HEAD.

### Actual entry points

| File / symbol | Actual behavior |
|---|---|
| [run.ps1](../run.ps1) | Runs the existing virtual environment with `uvicorn backend.main:app`, binds `127.0.0.1`, port 8787 by default, enables reload. |
| [app](../backend/main.py#L480) | FastAPI ASGI application. Startup loads saved scan metadata. Mounts the frontend static directory. No direct script entry point. |
| [index](../backend/main.py#L513) | Renders the standalone main template. |
| [index.html](../frontend/templates/index.html) | Actual page, with inline styles, Tailwind CDN, vis-network CDN, and the application JavaScript. Does not extend the base template. |
| [app.js](../frontend/static/app.js) | Form submission, polling, services, findings, history, web results, graph, details, and export actions. |
| [base.html](../frontend/templates/base.html), [style.css](../frontend/static/css/style.css) | Present, but the rendered main page does not use this base template or link this stylesheet. Editing only these will not restyle the actual page. |
| [tasks.json](../.vscode/tasks.json) | Existing baseline run task uses the baseline environment, loopback binding, port 8787, and `-B`. |

There is no implemented baseline comparison or Exposure Change Detector in the
inspected source. No need to replace FastAPI, templates, JavaScript, Nmap, or
Gobuster. No reason to introduce another frontend framework or database for this
deadline.

### All 18 explicitly declared routes

All handlers below are in [main.py](../backend/main.py). FastAPI additionally
provides its generated OpenAPI/docs endpoints; `/static` is a mount, not one of
these 18 decorated routes.

| Method and path | Handler | Important behavior |
|---|---|---|
| `GET /` | `index` | Render main page. |
| `GET /health` | `health_check` | Status, service name, per-process boot ID. |
| `POST /scan` | `start_scan` | Queue network scan and, for most profiles, web checks. No authorization/scope gate. |
| `GET /scan/{scan_id}` | `get_scan_status` | Infers completion from files; can update metadata. |
| `GET /scan/{scan_id}/raw` | `get_raw_scan` | Read XML. |
| `GET /scan/{scan_id}/parsed` | `get_parsed_scan` | Parse XML; also performs live reverse DNS. |
| `GET /scan/{scan_id}/nvd` | `get_scan_with_nvd` | Parse, attempt credentials, query NVD, score services. |
| `GET /scan/{scan_id}/findings` | `get_findings` | Calls `enrich_scan_data`: credential attempts and NVD requests before building findings. |
| `GET /scan/{scan_id}/findings.csv` | `download_findings_csv` | Calls findings route logic; inherits its network activity. |
| `GET /scan/{scan_id}/attack-graph` | `get_attack_graph` | Live NVD enrichment, score, graph; no credential annotation in this handler. |
| `GET /scan/{scan_id}/alive-hosts` | `get_alive_hosts` | Read saved discovery list, otherwise parse XML with reverse DNS. |
| `POST /scan/{scan_id}/remediation` | `get_llm_remediation` | Credential annotation, live NVD, then optional Gemini call. |
| `GET /scan/{scan_id}/report.pdf` | `download_report` | Credential annotation, live NVD, score, graph, PDF. Builds findings without the saved web assessment. |
| `GET /webscan/{scan_id}` | `get_web_scan_status` | Read marker/error files; unknown/skipped scans can appear to run indefinitely. |
| `GET /webscan/{scan_id}/results` | `get_web_scan_results` | Read Gobuster output and warnings. |
| `GET /webscan/{scan_id}/assessment` | `get_web_security_assessment` | Read saved web-audit JSON. |
| `GET /scans/history` | `get_scan_history` | Return in-memory metadata loaded from disk. |
| `POST /scans/clear` | `clear_persisted_scans` | Clear metadata, preserve raw evidence files. |

`WebScanRequest` exists but has no corresponding web-only POST route. Do not
build a frontend around a nonexistent `/webscan` POST endpoint.

### Actual scan profiles

Single-target commands are assembled in [run_nmap_scan](../backend/main.py#L517).
All use `-T4 -Pn`; without explicit ports, Nmap chooses its normal default set.
Quick does not use `-F` or a separate live-host discovery step.

| Profile | Single-target Nmap | HTTP/TLS + Gobuster automatically queued? |
|---|---|---|
| `quick` | No `-sV`, OS detection, or explicit NSE set | No |
| `standard` (default) | `-sV` | Yes |
| `web` | `-sV` | Yes |
| `vulnerability` | `-sV -O --osscan-guess --script vuln` | Yes |
| `full` | Same Nmap flags as vulnerability | Yes |

Unknown profile strings silently become `standard`. The UI sends target,
exposure, and profile; the API also accepts description and ports.

CIDR is different: [run_cidr_scan](../backend/main.py#L299) invokes Angry IP
Scanner and then [run_nmap_scan_multi](../backend/main.py#L220). That command
always includes service/OS detection and `--script vuln`, regardless of profile.
An IPv4 target ending in `.0` is silently expanded to `/24`. Discovered addresses
are not checked against a separate authorized scope. Angry IP Scanner was absent
at its configured location during inspection; Nmap was present.

[run_gobuster_scan](../backend/main.py#L1044) first performs HTTP/TLS assessment,
then invokes directory discovery with 30 threads, 10-second per-request timeout,
300-second process timeout, and TLS validation disabled. If HTTP Gobuster fails,
it can try HTTPS without explicit user selection. The Requests assessment follows
redirects and retries invalid TLS with certificate verification disabled. No
scope validation occurs at redirected destinations. Gobuster is not explicitly
passed its redirect-following option; its packaged runtime behavior was not tested.

### Storage and replay

Storage is local files in [backend/scans](../backend/scans), not SQLAlchemy or
SQLite despite the installed database packages:

- Network evidence: `<scan_id>.xml`; combined CIDR scans write `.xml.tmp` first.
- CIDR discovery: `angryip_<scan_id>.csv`, `alive_<scan_id>.json` when generated.
- Web evidence: `gobuster_<scan_id>.txt`, `.status`, `.done`, and
  `web_audit_<scan_id>.json`.
- [scan_status.json](../backend/scans/scan_status.json): scan ID, cleaned target,
  status, exposure, profile, description, timestamps, Gobuster status. It does
  not preserve a full immutable request, resolved scope, tool arguments/version,
  authorization acknowledgement, normalized snapshot, or rule version.
- [llm_cache.json](../llm_cache.json): remediation cache relative to process CWD.
- Browser localStorage: `pcvp:*` last scan, services, rendered HTML, statistics,
  graph, web results, and remediation. A new backend boot ID clears some cached
  selection state; saved server history remains.

The inspection counted seven XML files, six Gobuster text outputs, six status
files, six done markers, and seven JSON files in the scan directory. Their
contents were not treated as authorization to contact those saved targets.

History is not immutable replay: result reads can query DNS/NVD and attempt
logins again. Network and web evidence already have separate files/endpoints,
but `build_findings` merges them without an explicit domain discriminator. PDF
findings omit the web audit used by JSON/CSV findings.

### Frontend call map

The exact source lines are also recorded by the offline inspection script.

| User action / loader in [app.js](../frontend/static/app.js) | Backend calls |
|---|---|
| Initial load | `/health`, saved scan status if selected, `/scans/history`; may restore result loaders. |
| Submit form | `POST /scan` with `{target, exposure, profile}`, then history and status polling. |
| Completed scan / historical scan | Services `/nvd`, `/findings`, `/alive-hosts`, web `/results`, web `/assessment`, `/attack-graph`. |
| Service details | `POST /scan/{id}/remediation`, unless browser cache satisfies it. |
| CSV / PDF buttons | Navigate to `/findings.csv` or `/report.pdf`. |
| Clear saved scans | `POST /scans/clear`, clear selected browser caches. |

The frontend does not currently call `/raw`, `/parsed`, or web status polling.
Opening the page can restore a saved scan and reach active enrichment paths.

## 2. Evidence gaps and minimum corrections

These are source-backed application behaviors, not vulnerabilities asserted about
any scanned asset.

| Evidence | Consequence and smallest useful correction |
|---|---|
| [weak_creds.py](../backend/scanner/weak_creds.py) actively tests SSH, FTP, HTTP Basic; annotation is called by result/export handlers. | Remove automatic credential calls and imports from request paths. Old saved data remains historical evidence, not permission to retry. |
| [llm_remediation.py](../backend/llm_remediation.py) imports Google GenAI; its misleadingly named `generate_remediation_openai` uses Gemini and includes service/credential details in its prompt. | Replace the remediation implementation with local rule text while retaining the response shape. Remove GenAI dependency and AI setup/UI instructions. No LLM calls during this work. |
| [nvd_client.py](../backend/scanner/nvd_client.py) performs keyword searches; [nvd_mapping.py](../backend/scanner/nvd_mapping.py) truncates version strings. | Make reads offline; preserve any saved references as unverified candidates. No live enrichment by default, no cloud analytics. |
| [build_findings](../backend/main.py#L908) marks every script output high/high and every approximate NVD hit a known vulnerability. | Distinguish observation, hardening recommendation, candidate, and supported finding. Require rule-specific positive evidence and retain raw source references. |
| [pcvp_scoring.py](../backend/scanner/pcvp_scoring.py) scores service type and assumed exposure/privilege; [attack_graph.py](../backend/scanner/attack_graph.py) connects high-scoring services as possible chains. | Label scores as exposure prioritization; remove unsupported compromise/pivot claims and use observed asset/service relationships. |
| [start_scan](../backend/main.py#L566) accepts target text and raw ports without a scope gate. | Require explicit authorization and validated finite targets/ports before scheduling anything. Reject options, unsupported syntax, ambiguous ranges, and implicit subnet expansion. Validate DNS answers and pin connections to authorized addresses. |
| Web redirects, TLS fallback, HTTP-to-HTTPS fallback bypass explicit destination choices. | Record redirect Location as evidence without following it; retain TLS errors without retrying insecurely; require explicit web origin/ports. Ignore ambient HTTP proxies for assessment traffic. |
| [run.ps1](../run.ps1) binds loopback, but the app lacks request host/origin enforcement. | Keep loopback startup; add local host/origin and scan-request protections with negative tests. A FastAPI app cannot prevent an operator from overriding Uvicorn's bind address. |
| Completion is inferred from XML size and `.done`; a Gobuster failure still produces `.done`. | Track component outcomes separately. Never convert a failed component to completed merely because its file exists. Bound scanner duration and concurrency. |
| Status snapshots share a temporary filename and background workers have no persistent queue. | Keep one local process; serialize metadata writes and bound jobs. Reconcile interrupted scans on restart. No distributed queue for the MVP. |

Offline reproduction ran the existing findings builder in isolation with invented
data. It returned:

```text
Nmap vulnerability check: synthetic-script | severity=high | confidence=high
evidence=NOT VULNERABLE
Known vulnerability in synthetic-product | severity=high | confidence=medium
evidence=Unverified keyword candidate
```

No target was contacted. An open port is an exposure observation; a discovered
path is a path observation; neither proves a vulnerability. Header absence needs
HTTP/HTTPS and application context. Even a positive scanner claim needs its
script ID, raw output, affected endpoint, and qualification before presentation.

## 3. Fourteen-day plan, with a stopping point each day

Keep the existing stack and saved evidence. Each day ends after its stated
acceptance check, with changed files, code/diff, PowerShell commands, expected
output, and limitations. Do not implement later days in advance.

| Day | Small deliverable | Acceptance check / stop |
|---|---|---|
| 1 | This source/ZIP map, offline reproduction, and plan. | Source parses, archive differences recorded, no application behavior changes. |
| 2 | Remove automatic credential attempts and all reachable LLM/GenAI use. Make result/export/remediation reads local and deterministic. Disable scan submission until the scope and safe-profile gates are ready. | Reads cannot call credential code, Requests, DNS, scanners, or GenAI; submission fails closed. Existing history remains available. |
| 3 | Explicit authorization + finite target/port validation and persisted scope. Remove `.0` expansion. Validate all DNS answers; constrain process arguments and scan identifiers. Keep submissions closed until Day 4. | Unauthorized/out-of-scope/option-like targets and unsafe ports are rejected before jobs or files are created. No implicit broadening. |
| 4 | One consistent conservative network profile for single targets and supported CIDR, timeouts and bounded jobs. Disable intrusive NSE sets, OS guessing, and automatic Gobuster. | Mocked command tests prove no `vuln`, brute-force, exploit, or web enumeration defaults. Enable only the validated path. |
| 5 | Explicit web origin assessment with redirect blocking, verified TLS, pinned approved destinations, response limits. | Local fixture proves no external redirect/proxy traffic and no insecure fallback. Preserve HTTP and TLS evidence separately. |
| 6 | Optional, explicit Gobuster discovery with small bounded wordlist/concurrency and the same scope rules. | Enumeration off by default; a path/status is never promoted to a vulnerability. Disable hostname enumeration if pinning cannot be guaranteed. |
| 7 | Versioned deterministic findings/remediation rules and consistent JSON/CSV/PDF evidence. | Negative NSE output, open ports, and approximate CVEs cannot become confirmed vulnerabilities. Header checks retain context and evidence. |
| 8 | Immutable normalized network/web snapshots alongside existing raw files. | Replay makes no network calls; legacy scans marked with missing metadata; raw evidence unchanged. |
| 9 | Exposure Change Detector for two comparable saved network snapshots. | Detect added/removed hosts and observed open ports, service/version changes; incompatible/partial scans are rejected or explicitly inconclusive. |
| 10 | Web snapshot comparison by explicit origin/path; header/status/TLS changes. | No cross-origin or network/web conflation; missing collection never means resolved exposure. |
| 11 | Baseline selection + separate Network, Web, and Changes views in the current UI. | New observations and changed evidence visible with before/after references; no new frontend framework. |
| 12 | Offline UI assets, safe DOM rendering, consistent evidence exports and observed relationships graph. | Page and saved results work with internet blocked; no speculative attack-chain assertions. |
| 13 | End-to-end regression using mocks and an explicitly authorized loopback fixture. | Scope, redirects, disabled credentials/LLMs, failure states, restart, and comparable change detection pass. |
| 14 | Demo fixture, clean setup/run guide, known limitations, final verification. | Repeatable Windows demo shows a real before/after exposure change from saved evidence. Freeze scope. |

Expected edits start with existing [main.py](../backend/main.py),
[app.js](../frontend/static/app.js), [index.html](../frontend/templates/index.html),
[requirements.txt](../requirements.txt), and [README.md](../README.md).
Existing parsing/report/scoring helpers should be reused where their semantics
remain valid. Any new scope, snapshot, comparison, or test module will be named
before creation on its day; those modules do not exist yet.

For the Change Detector, a proposed network identity is authorized asset IP +
protocol + port; web identity is explicit scheme + host + port + path. Compare
only compatible authorization/scope, resolved asset identity, port coverage,
profile, tool/rule/schema versions, and successful component coverage. A port
absent from a partial or narrower scan is unknown, not closed. A new open port is
an exposure change, not a newly proven vulnerability. Store both scan IDs and
source evidence references for every change. Normalize ordering; ignore scan
timestamps in semantic comparisons. Do not match unrelated assets across DNS/IP
changes. Keep network and web change lists distinct.

## 4. Day 1 files and working code

Only these deliverables were added:

- [DAY-01.md](./DAY-01.md): this report and plan.
- [inspect_day1.py](../tools/inspect_day1.py): executable offline inspection code.
  New functions `digest` and `inspect` exist only in this tool. It parses eight
  backend Python files, inventories archives in memory, extracts decorated routes
  and frontend call lines, and reproduces the existing pure findings builder on
  synthetic inputs. It never imports the application or calls its I/O helpers.
- [day1-inspection.json](../artifacts/day1-inspection.json): generated inspection
  evidence, including source hashes and the ZIP-to-working-source diff.

No application/dependency/configuration files or saved scans were modified by
Day 1. The full working code is supplied in the inspection tool; there is no
application patch in this day's scope.

## 5. Windows PowerShell run and verification commands

The existing baseline interpreter was configured and reports Python 3.14.3.
The inspection tool uses only the standard library. Run from the project root:

```powershell
Set-Location 'D:\security project'
& '.\.venv-baseline\Scripts\python.exe' -B '.\tools\inspect_day1.py' |
    Set-Content -Encoding utf8 '.\artifacts\day1-inspection.json'
if ($LASTEXITCODE -ne 0) { throw 'Offline inspection failed' }

$audit = Get-Content '.\artifacts\day1-inspection.json' -Raw | ConvertFrom-Json
$audit.python_files_parsed
$audit.routes.Count
$audit.archives | ForEach-Object { $_.source_comparisons } |
    Format-Table file, bytes_equal, ast_equal -AutoSize
$audit.synthetic_findings_reproduction |
    Format-List title, severity, confidence, evidence

# Review this day's additions and preserve pre-existing edits.
git status --short
Get-Content '.\tools\inspect_day1.py'
```

Expected output: `8` parsed Python files; `18` decorated application routes;
four byte-equal frontend files; eight backend comparisons with seven equal ASTs
and one unequal AST (response-class import). The two synthetic findings above
reproduce the existing evidence problem. These are baseline observations, not
passing safety checks. Editor diagnostics reported no errors in the added tool.

For a fresh machine without either existing environment, create a tooling-only
environment with `py -3 -m venv .venv-inspection` and use its Python for the same
script. No packages need installing to reproduce Day 1.

The existing backend can be launched for a health-only check in one PowerShell
window:

```powershell
Set-Location 'D:\security project'
& '.\.venv-baseline\Scripts\python.exe' -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

Then in a second PowerShell window:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8787/health' | Format-List
```

Expected if dependencies/startup succeed: Uvicorn listens on loopback; health
returns `status: ok`, `service: risklens-backend`, and a changing `boot_id`.
Stop with Ctrl+C. These launch/HTTP commands were not executed in the initial
inventory; the follow-up baseline guide records the subsequent successful launch.
Avoid opening the legacy UI or its result/export routes
before the automatic credential/enrichment paths are removed: their actual
side effects are documented above. Do not run a target scan for Day 1.

## 6. Limits and stop

This is a static inventory plus a focused isolated runtime reproduction, not a
completed safety conversion. No Nmap, Gobuster, credential tests, Gemini, live
NVD, browser CDN loads, or saved-target requests were executed. Executable
provenance, full installed dependencies, Windows scanner permissions, and real
scan output were not revalidated. The old baseline report describes earlier
checks; those were not counted as tests performed today.

The app's scope enforcement, safe defaults, evidence classification, and Change
Detector remain to be implemented. Day 1 ends here.

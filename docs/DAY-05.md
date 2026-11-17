# Day 5 — truthful, scoped HTTP/TLS evidence

## Actual execution path and original contract

Inspected the working source before editing, rather than assuming the ZIP's
original implementation still applied after Days 2–4:

`POST /scan` → authorized Web profile → Nmap completes →
`run_gobuster_scan()` → `run_web_security_assessment(url)` →
`backend/scans/web_audit_<scan_id>.json` → Gobuster.
`GET /webscan/{scan_id}/assessment` only reads that saved JSON.
The frontend `loadWebAssessment()` fetches that endpoint when showing results.

The original successful response structure, taken from the function's code, was:

```text
{
  url: string,
  http: {status: integer, final_url: string, headers: object},
  tls: {protocol, cipher, subject, issuer, expires} or {error} or {},
  technologies: [{name, evidence}],
  checks: [{name, status, detail}],
  error?: string
}
```

HTTP failure left `http` empty. Unsupported URLs returned only `{url, error}`.
The HTTP request used Requests with verification enabled, redirects disabled,
environment proxies disabled, and a 15-second timeout. A separate TLS connection
then used `ssl._create_unverified_context()`, so its metadata did not establish
that the HTTP connection was verified. HTTP headers were stored with original
casing, redirect decisions were absent, and header presence alone produced a
`pass`. The frontend could label an HTTPS failure “Not HTTPS”. The worker could
continue into Gobuster after an assessment error.

Plan implemented: keep the wrapper, endpoint, artifact name, and original JSON
fields; isolate transport and evidence logic in one new module; replace both
connections with one verified, pinned connection; add deterministic checks and
mocked regressions. No new dependency or schema version is required.

## Files changed today

- [backend/main.py](../backend/main.py): assessment wrapper, submission-time web
  URL/port policy, worker authorization check, atomic audit publication and stop
  on assessment error, informational web configuration findings.
- [backend/scanner/web_assessment.py](../backend/scanner/web_assessment.py) **new**:
  URL validation, direct IP transport, TLS/HTTP evidence and header observations.
- [frontend/static/app.js](../frontend/static/app.js): truthful HTTPS failure
  labels, categorized errors, saved headers/certificate/redirect evidence.
- [tests/test_scan_execution.py](../tests/test_scan_execution.py): replace the old
  Requests-specific expectation with a test of the retained public wrapper.
- [tests/test_web_assessment.py](../tests/test_web_assessment.py) **new**: 19
  mocked transport, policy, failure, worker, and read-only endpoint tests.
- [tests/test_web_assessment.js](../tests/test_web_assessment.js) **new**: execute
  the actual frontend reader with synthetic saved data, including escaped errors.
- This document and [the exact Day 5 diff](../artifacts/day5-changes.patch) **new**.

The existing network findings module, report generator, templates, requirements,
and scan execution policy were not edited today. Earlier uncommitted changes
remain in place. Do not reapply the patch to this already updated working tree.

## Behavior and evidence now

- HTTP/HTTPS only; literal IPv4/IPv6 addresses only, preserving the existing
  no-DNS policy. Reject userinfo, fragments, zone IDs, backslashes, control
  characters, malformed/zero ports, and unsupported addresses. Current operator
  scope is checked during validation and immediately before connecting.
- `RISKLENS_ALLOWED_TARGETS` remains mandatory. Default allowed web ports are
  `80,443,8080,8443`; `RISKLENS_ALLOWED_WEB_PORTS` can replace that list with
  explicit comma-separated numeric ports. The worker also checks the saved
  authorized IP list, saved scope, and exact requested port before assessment.
- A direct numeric-address socket prevents hostname rebinding. Verify its peer
  matches the approved IP. Environment HTTP proxies are not used. TLS uses
  `ssl.create_default_context()` with certificate and IP SAN verification on.
  No insecure retry, secondary TLS probe, credential attempt, or exploit occurs.
- Record HTTP status, requested URL as `final_url` (nothing is followed),
  lowercase `http.headers`, and `http.raw_headers` preserving duplicate fields.
  HTTP 4xx/5xx are recorded responses; transport completion does not mean the
  application is healthy or secure.
- Record `redirects` with raw Location, resolved destination, HTTP status,
  `followed: false`, and a decision. Even approved redirects are not followed.
  A scheme, IP, or port change is blocked, including HTTPS downgrade or another
  approved IP. DNS names, credentials, malformed destinations, and disallowed
  ports are blocked. `final_url` never pretends the redirect was visited.
- TLS metadata comes from the same verified connection: negotiated protocol and
  cipher, subject, issuer, validity dates, serial number, SANs, certificate DER
  SHA-256, verification state, and provenance. Certificate failure has no claimed
  negotiated protocol/certificate metadata and no invented HTTP observations.
- Connect/handshake inactivity timeout: 5 seconds. Read inactivity timeout: 10
  seconds. Body sampling: at most 200,000 bytes, with a 20-second assessment
  budget checked between body reads. The remaining budget shortens body read
  timeouts. `body_bytes_sampled` and `body_limit_reached` describe sampling.
- Existing `url`, `http`, `tls`, `technologies`, `checks`, and optional string
  `error` remain. Additive `status` is `completed`, `partial`, or `failed`;
  `error_category` distinguishes certificate verification, TLS, connect timeout,
  read timeout, refusal, connection/protocol errors, invalid URL, scope rejection,
  configuration error, and blocked redirect. HTTP evidence survives body errors.
  Empty/failed HTTP responses do not generate missing-header observations.
- Header statuses are `missing`, `misconfigured`, `review`, or `not_applicable`.
  Check empty values, XCTO `nosniff`, XFO `DENY`/`SAMEORIGIN`, HSTS positive
  `max-age`, and recognized Referrer-Policy values. HSTS over HTTP is not
  applicable. Nonempty CSP/Permissions-Policy need contextual review; their
  presence is not a claim of adequate protection. Header observations have
  informational severity; finding confidence concerns the observed header only.
  Technology strings are hints tied to saved header/body evidence.
- Atomic JSON publication prevents readers seeing partial files. A failed audit
  is saved and stops Gobuster. Normal successful Web scans still run existing
  Gobuster with its verified TLS/no-follow settings. GET returns saved successful
  or failed JSON with 200; missing artifact is 404; unreadable/malformed is 500.
  Opening results never repeats HTTP, TLS, DNS or credential operations.

Example certificate failure (message and verification code depend on OpenSSL):

```json
{
  "url": "https://127.0.0.1/",
  "http": {},
  "tls": {"verification": "failed", "error": "certificate verify failed", "verify_code": null},
  "technologies": [],
  "checks": [],
  "status": "failed",
  "redirects": [],
  "error_category": "certificate_verification_failed",
  "error": "certificate verify failed"
}
```

## Windows PowerShell verification

Use the existing configured environment (Python 3.14.3 here). If restoring a
clean checkout, create that environment and install the dev requirements first:

```powershell
Set-Location 'D:\security project'
# Only when the environment does not already exist:
py -m venv .venv-baseline
& '.\.venv-baseline\Scripts\python.exe' -m pip install -r .\requirements-dev.txt
```

Run tests; no Nmap, Gobuster, remote server, certificate installation or API keys
are needed. Node is only needed for these standalone frontend tests:

```powershell
Set-Location 'D:\security project'
& '.\.venv-baseline\Scripts\python.exe' -B -m unittest discover -s tests -v
node .\tests\test_service_details.js
node .\tests\test_web_assessment.js
git diff --check
```

Actual result: `Ran 57 tests ... OK`; both Node checks print `PASS`. Coverage
includes invalid certificate without retry, outside-scope/same-origin redirects,
HTTPS downgrade, connect/read/body timeout, connection refusal, changed peer,
revoked scope, denied ports, malformed configuration, bounded sampling, verified
TLS evidence, failed artifact reads without probes, and no Gobuster after a
failed assessment. Prior Nmap, no-credential, PDF/CSV and network finding tests
also pass. The existing Starlette template deprecation warning is unrelated.

Launch the app locally, setting only scope you own or are explicitly allowed to
assess. The scope below authorizes loopback only:

```powershell
Set-Location 'D:\security project'
$env:RISKLENS_ALLOWED_TARGETS = '127.0.0.1/32,::1/128'
$env:RISKLENS_ALLOWED_WEB_PORTS = '80,443,8080,8443'
& '.\.venv-baseline\Scripts\python.exe' -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

In another terminal:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8787/health'
```

Expected: `status: ok`, `service: risklens-backend`, and a boot ID.

Optional local HTTP-only manual exercise, not performed during this change:
start a deliberately owned fixture in a third terminal:

```powershell
Set-Location 'D:\security project'
& '.\.venv-baseline\Scripts\python.exe' -m http.server 8080 --bind 127.0.0.1 --directory .\frontend\static
```

With app and fixture running, submit an explicitly authorized Web profile. This
does run the existing Nmap and Gobuster binaries; they must be installed and
configured as described on Day 3. No extra third-party target is involved:

```powershell
$body = @{target='http://127.0.0.1:8080'; ports='8080'; profile='web'; authorized=$true} | ConvertTo-Json
$scan = Invoke-RestMethod -Method Post 'http://127.0.0.1:8787/scan' -ContentType 'application/json' -Body $body
$deadline = (Get-Date).AddSeconds(450)
do {
    Start-Sleep -Seconds 1
    $status = Invoke-RestMethod "http://127.0.0.1:8787/scan/$($scan.scan_id)"
} while ($status.status -notin @('completed','failed') -and (Get-Date) -lt $deadline)
$status | Format-List
if ($status.gobuster_status -in @('completed','failed')) {
    $assessment = Invoke-RestMethod "http://127.0.0.1:8787/webscan/$($scan.scan_id)/assessment"
    $assessment | ConvertTo-Json -Depth 12
}
```

Expected when the network step succeeds: saved HTTP status 200, lowercase
headers, `tls.verification: not_applicable`, configuration observations, and
`redirects: []`. Gobuster can fail independently (for example, wildcard-response
behavior); inspect saved assessment and worker error separately. Nmap failure
skips web entirely and creates no assessment artifact.

## Limits and stop

No real scan or live HTTP/TLS target request was executed for verification;
transport and certificate behavior were tested with mocks. Hostnames remain
unsupported; private HTTPS servers need a trusted certificate containing the
literal IP in its SAN. Invalid certificates are reported, never bypassed.
All redirects stop at the first response, even same-origin paths. One response
and a bounded body sample do not establish whole-site policy or technology
identity. TLS metadata covers the negotiated connection, not an exhaustive
protocol/cipher audit. Inactivity timeouts and the between-read body budget are
not a hard wall-clock deadline for slow header delivery. Old artifacts remain
readable but cannot acquire missing evidence without an explicit new scan.
Gobuster's independent requests retain their existing behavior and process
deadline. No Exposure Change Detector or other day's scope was added. Stop here.

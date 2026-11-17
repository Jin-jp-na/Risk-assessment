# Day 4 — explainable network observations and unverified CVE candidates

## Actual output inspected before editing

The current parser, annotation and findings builder were executed against invented
saved XML containing one open SSH port. No target or NVD service was contacted.
The original `/parsed` envelope was:

```json
{
  "scan_id": "synthetic",
  "data": {
    "hosts": [{
      "ip": "192.0.2.10", "hostnames": [], "reverse_dns": null,
      "mac": null, "mac_vendor": null, "os": [],
      "services": [{
        "port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
        "product": "OpenSSH", "version": null, "extrainfo": null,
        "nse_findings": []
      }]
    }]
  }
}
```

`/nvd` preserved this host/service structure and added `ip`, `weak_creds`, `nvd`,
`remediation`, `pcvp_score`, `pcvp_level`, and `pcvp_reasons` to each service.
The observed SSH-only case scored **90 / critical**, using assumed privilege,
credential risk and attack-path points despite no such evidence. Injecting an
invented keyword candidate made the old findings builder emit “Known
vulnerability in OpenSSH” with critical severity. Every NSE output was also
automatically high/high, including `NOT VULNERABLE` output. This was reproduced
before changing those rules.

## Output now

Existing routes and host/service fields remain. The parser adds a flat
`data.observations` array with these exact keys:

```text
host, protocol, port, state, service, product, version, evidence
```

Example observation, shortened only for documentation:

```json
{
  "host": "192.0.2.10",
  "protocol": "tcp",
  "port": 22,
  "state": "open",
  "service": "ssh",
  "product": "OpenSSH",
  "version": null,
  "evidence": {
    "source": "Nmap XML",
    "artifact": "day4-example.xml",
    "sha256": "<SHA-256 of the actual XML bytes>",
    "host_addresses": [{"@addr": "192.0.2.10", "@addrtype": "ipv4"}],
    "locator": "host[192.0.2.10]/ports/port[@protocol='tcp'][@portid='22']",
    "original": {
      "@protocol": "tcp", "@portid": "22",
      "state": {"@state": "open", "@reason": "syn-ack"},
      "service": {"@name": "ssh", "@product": "OpenSSH"}
    }
  }
}
```

The exact generated JSON and real hash are in
[day4-network-example.json](../artifacts/day4-network-example.json), backed by
[day4-example.xml](../artifacts/day4-example.xml). Both are clearly synthetic,
not assertions about a real target. `original` is the parsed original port
record, not a byte-for-byte XML fragment; the file/hash retains the byte-level
source. The locator is a human-readable record selector, not executable XPath.
The hash is computed once per parse. Host IPs are canonicalized; unknown versions
remain null and invalid numeric ports are not invented into observations.

`/nvd` still does not query NVD. It adds bounded exposure-review fields and
`data.candidate_vulnerabilities`. Ordinary XML-only results have an empty candidate
array and NVD status `not_queried`. If local candidate data is supplied to the
existing annotation/findings helpers, it is normalized conservatively:

```json
{
  "category": "candidate_vulnerability",
  "domain": "network",
  "title": "Unverified CVE candidate: SYNTHETIC-CVE",
  "rule_id": "NET-CVE-KEYWORD-001",
  "severity": "info",
  "confidence": "low",
  "confidence_scope": "CVE_applicability",
  "verification_status": "unverified",
  "cvss": null,
  "reported_severity": "CRITICAL",
  "reported_cvss": 9.8,
  "reason": "Keyword matching does not establish product/version applicability. The observed version is unknown."
}
```

The full object also includes the observed endpoint, normalized observation,
original Nmap evidence, original candidate metadata, and local review guidance.
The candidate's advisory severity/CVSS is reference metadata, never an asset
rating. Even an upstream `verified`/`confirmed` flag cannot promote a keyword
match. Merely having a product name and banner version does not confirm that a
CVE applies. No applicability verifier or automatic confirmation is implemented.

`GET /scan/{id}/findings` preserves `scan_id`, `summary`, and `findings`, and adds
separate `network_observations` and `candidate_vulnerabilities` arrays. The
compatibility findings list contains explicitly typed observations, script output,
candidates, and web recommendations. Every network entry has a rule ID, reason,
severity, scoped confidence, verification status, affected endpoint, and source
evidence. Web records have `domain: web` and a hardening-recommendation category;
their existing header rules were not broadened this day.

## Deterministic rules

| Rule | Trigger | Severity / confidence | Meaning |
|---|---|---|---|
| `NET-OPEN-001` | Nmap reports `state=open` | Info; high confidence only in the recorded port state when original XML/hash exists, otherwise low | Open service observation; not a vulnerability. |
| `NET-NSE-REVIEW-001` | Saved nonempty NSE output | Info / low vulnerability-interpretation confidence | Retain output for review; arbitrary positive or negative words do not establish a flaw. |
| `NET-CVE-KEYWORD-001` | Supplied keyword candidate with an ID | Info / low applicability confidence; unverified | Product/version/advisory conditions still need verification. |
| Non-open port | Closed/filtered/unknown state | No open-service finding; review score 0 | Preserve the normalized state, do not claim exposure. |

Product/version identity confidence is low when either is missing, medium when
both are scanner-reported. This concerns scanner identity only and never proves
installed-package identity or CVE applicability. State confidence and applicability
confidence are deliberately different claims.

The old `pcvp_*` response fields are kept for compatibility, but mean exposure
review priority now:

```text
Observed open port:                         +10
Administrative/data service or listed port: +10
External exposure context:                   +5
Maximum:                                    25
Non-open state:                               0
Keyword candidate / assumed compromise:      +0
```

Any nonzero review priority has label `low`; zero is `informational`.
`score_kind` explicitly says `exposure_review_priority`; network severity is
separately `info`. Thus external open SSH is **25 / low review priority / info
severity**, not a confirmed critical flaw. Exposure context is not proof of
internet reachability. Removed privilege, weak-password, exploitability and
attack-path assumptions do not contribute points.

## Relevant changes only

- [main.py](../backend/main.py): normalized observations with original evidence;
  conservative local annotation; separate API arrays; CSV rule/reason/type/source
  columns and JSON-serialized original evidence. Scan scheduling, profiles,
  authorization policy, subprocesses, and JSON persistence were not changed.
- [network_findings.py](../backend/scanner/network_findings.py), new: pure network
  observation/candidate rules and normalization, no I/O or new packages.
- [pcvp_scoring.py](../backend/scanner/pcvp_scoring.py): bounded review priority,
  independent informational severity, explicit reasons.
- [nvd_mapping.py](../backend/scanner/nvd_mapping.py): the optional legacy keyword
  helper marks results unverified at its producer too. It is still not invoked
  by result reads; tests mock its HTTP-query boundary.
- [attack_graph.py](../backend/scanner/attack_graph.py): CVE relation says
  `candidate_cve`, with unverified node status. No applicability claim.
- [report_generator.py](../backend/report_generator.py): relevant headings/labels
  distinguish service review priority and candidate CVEs; report generation is
  otherwise unchanged.
- [app.js](../frontend/static/app.js) and [index.html](../frontend/templates/index.html):
  show review priority, advisory-versus-asset severity, confidence scope, rule,
  reason, and expandable original evidence. Escape evidence and service strings.
  Existing graph association labels are explicitly unverified. Old rendered
  score/graph caches are invalidated once and the script URL advances to v21.
- [test_network_findings.py](../tests/test_network_findings.py), new: nine tests.
- [test_service_details.js](../tests/test_service_details.js): additional assertions
  for original evidence and unverified advisory labels, still forbidding fetch.
- [DAY-04.md](./DAY-04.md), synthetic example files, and
  [day4-changes.patch](../artifacts/day4-changes.patch): this day's handoff and
  exact diff against saved Day 3 state, preserving earlier uncommitted work.

The attached [weak_creds.py](../backend/scanner/weak_creds.py) was not modified or
enabled. The application still does not import or call it.

## PowerShell tests, run commands, and expected output

```powershell
Set-Location 'D:\security project'
# Only if development requirements are not already installed:
& '.\.venv-baseline\Scripts\python.exe' -m pip install -r '.\requirements-dev.txt'

& '.\.venv-baseline\Scripts\python.exe' -B -m unittest discover -s tests -p test_network_findings.py -v
& '.\.venv-baseline\Scripts\python.exe' -B -m unittest discover -s tests -v
node --check '.\frontend\static\app.js'
node '.\tests\test_service_details.js'
git diff --check
```

Verified using the existing Python 3.14.3 environment:

```text
Focused network suite: 9 tests, OK
Full Python suite:    38 tests, OK
PASS: service details render local guidance without fetch
```

The required open-service-only, unknown-version, and candidate-CVE tests are
included, plus raw evidence/hash, unknown applicability despite a known version,
NSE strings, API separation, producer labeling, and graph candidate labels.
Earlier scope/profile/failure/read-only/PDF/CSV tests still pass. No scans, NVD
requests, credentials, or AI calls were performed. An existing TemplateResponse
deprecation warning remains.

Restart the existing server to load code changes; do not start a second server
on an occupied port. Existing Day 3 scope configuration still applies:

```powershell
$env:RISKLENS_ALLOWED_TARGETS = '127.0.0.1/32'
& '.\.venv-baseline\Scripts\python.exe' -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

For an existing saved scan ID, read results without initiating a new scan:

```powershell
$scanId = 'replace-with-an-existing-scan-id'
$parsed = Invoke-RestMethod "http://127.0.0.1:8787/scan/$scanId/parsed"
$parsed.data.observations | ConvertTo-Json -Depth 12
$findings = Invoke-RestMethod "http://127.0.0.1:8787/scan/$scanId/findings"
$findings.findings | Select-Object domain,category,severity,confidence,rule_id,reason | Format-List
```

Expected: original observations with evidence references; open services are info
observations; any supplied keyword candidate is unverified/info/low confidence.
Hard-refresh the page for the new script. No real server launch or browser layout
test was performed this day; API handlers were tested in-process.

## Limitations and stop

This is a conservative evidence presentation layer, not a CVE applicability
engine. No candidate-import UI, offline CVE database, affected-version range/CPE
validator, script-specific vulnerability verifier, or manual confirmation workflow
was added. Current XML-only `/nvd` reads remain `not_queried`; the example candidate
is explicitly injected offline for demonstration. There are no automatically
confirmed network vulnerabilities from these rules. Web assessment semantics and
the Exposure Change Detector remain outside today's scope. Stop here.

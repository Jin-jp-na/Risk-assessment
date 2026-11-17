# Day 2 — remove AI and make result reads local

## Actual call paths and the change

Before this change, [main.py](../backend/main.py) imported the credential
annotation helper and a Gemini generator at module load. The `/nvd` route called
credential annotation directly; findings/CSV called it through `enrich_scan_data`;
PDF and the remediation POST route also called it. XML parsing did reverse DNS.
NVD enrichment made fresh HTTP requests in service, findings, graph, and report
reads. Opening a service detail modal in [app.js](../frontend/static/app.js)
automatically posted to the remediation route and cached the response HTML.

The implemented change removes those paths rather than masking their results:

- Deleted the AI backend module and its import, request model, and POST route.
  `/scan/{scan_id}/remediation` now returns 404 and is absent from OpenAPI.
- Removed the frontend generated-remediation function, request, cache code, and
  generated-content element. The existing Details button remains useful for
  saved service/NSE evidence. It displays deterministic review guidance already
  present in the service response; clicking it makes no additional request.
- Removed credential annotation and live NVD calls from all result/export routes.
  Removed fresh reverse DNS from XML parsing; a reverse hostname is shown only
  when a PTR hostname is present in saved XML.
- Kept `/scan/{scan_id}/nvd` for compatibility with the existing UI. Its name is
  historical: no NVD API is called. Raw XML does not contain prior NVD enrichment
  or credential-check results, so these fields explicitly report unperformed
  checks instead of claiming a clean assessment.
- Removed `google-genai` and `paramiko` from application requirements. The
  application imports neither. The legacy credential module remains untouched
  and unused; running it independently would require its own dependencies.
- Updated current README setup/instructions and result labels. Historical Day 1
  records, original ZIPs, stored scan evidence, and the unused old AI cache remain
  preserved. They are not runtime feature implementations.

New local helpers in the existing main module are `service_remediation` and
`annotate_saved_services`. The shared annotation logic is:

```python
def annotate_saved_services(parsed: dict, exposure: str) -> None:
    for host in parsed.get("hosts", []):
        for service in host.get("services", []):
            service["ip"] = host.get("ip")
            service["weak_creds"] = {"found": False, "status": "not_tested"}
            service["nvd"] = {"keyword": None, "cves": [], "status": "not_queried"}
            service["remediation"] = service_remediation(service)
            service.update(pcvp_score_for_service(service, exposure))
```

Example SSH guidance: “Restrict SSH to authorized clients, prefer key-based
authentication, and review vendor updates.” This is general review guidance,
not evidence that SSH or an open port is vulnerable. FTP, web, and generic
services have similarly small fixed messages.

The frontend displays `svc.remediation` using its existing HTML-escaping helper.
PDF labels now say “Not tested” and “Not queried” rather than “None.” Normal
scan scheduling and Nmap/Gobuster command construction were preserved.

## Files supplied

Modified:

- [main.py](../backend/main.py): remove active result enrichment and AI route;
  introduce the two pure local helpers; parse saved PTR data.
- [report_generator.py](../backend/report_generator.py): accurate unperformed-check labels.
- [app.js](../frontend/static/app.js): remove AI request/UI/cache paths; render local guidance.
- [index.html](../frontend/templates/index.html): current result labels; increment script URL to `v=19`.
- [requirements.txt](../requirements.txt): remove two unused runtime dependencies.
- [README.md](../README.md): current behavior, setup, and regression commands.

Deleted: the former AI remediation Python module under the backend directory.

Added:

- [requirements-dev.txt](../requirements-dev.txt): existing runtime requirements
  plus pinned HTTPX 0.28.1 for FastAPI's in-process TestClient.
- [test_read_only_endpoints.py](../tests/test_read_only_endpoints.py): eight
  regression tests using invented XML/web files and temporary project-local storage.
- [test_service_details.js](../tests/test_service_details.js): runs the actual
  frontend Details handler with a small DOM stub and a throwing `fetch` function.
- [day2-changes.patch](../artifacts/day2-changes.patch): exact unified diff of the
  six modified tracked source/docs files, deleted AI module, new tests,
  development requirements, and this handoff.
- [DAY-02.md](./DAY-02.md): this handoff.

## Windows PowerShell commands

Use an existing working environment; the commands verified here used
`.venv-baseline` and Python 3.14.3. On another machine, substitute the path to
your working project's Python interpreter.

```powershell
Set-Location 'D:\security project'

# For a new environment, install both runtime and test requirements.
& '.\.venv-baseline\Scripts\python.exe' -m pip install -r '.\requirements-dev.txt'

# Does not contact targets or launch scanners.
& '.\.venv-baseline\Scripts\python.exe' -B -m unittest discover -s tests -v

# Node is used only for these frontend checks; no npm install is needed.
node --check '.\frontend\static\app.js'
node '.\tests\test_service_details.js'

git diff --check
git diff -- backend/main.py backend/report_generator.py frontend/static/app.js frontend/templates/index.html requirements.txt README.md
Get-Content '.\requirements-dev.txt'
```

Expected test output:

```text
Ran 8 tests in ...s
OK
PASS: service details render local guidance without fetch
```

HTTPX 0.28.1 was already installed in the verified environment; no dependency
download or uninstall was performed. Installing the revised requirements does
not uninstall old packages in an existing environment. Their presence does not
enable any removed feature; startup is separately tested with their imports
blocked. A clean environment will not install them via these requirements.

Launch in one terminal, or restart an existing server so it loads the changes:

```powershell
& '.\.venv-baseline\Scripts\python.exe' -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

In a second terminal:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8787/health'
$schema = Invoke-RestMethod 'http://127.0.0.1:8787/openapi.json'
$schema.paths.PSObject.Properties.Name -contains '/scan/{scan_id}/remediation'
```

Expected: health `status: ok`, service `risklens-backend`; schema membership
`False`. Hard-refresh the browser to load the new script. Do not start a new
target scan merely to run the regression suite.

## Verification and limitations

All eight Python tests pass. The GET test enumerates every declared GET route
and generated API/docs routes and checks HTTP 200 for a complete synthetic saved
scan. During requests, it blocks Requests HTTP, DNS lookups, socket connections,
process creation, and the legacy credential annotation helper. Mocks are asserted
unused, so swallowing an I/O error cannot make the test pass. PDF checks real
ReportLab output starting with `%PDF-`; CSV contains saved evidence.

Other tests verify deterministic repeated service responses, explicit unperformed
statuses, removal of the route/frontend request, startup without removed imports,
scan scheduling, and actual scanner worker command/output flow using mocked
external tools. The JavaScript test and Node syntax check pass. Editor diagnostics
reported no errors in the changed Python/JavaScript files; `git diff --check` passes.

The suite starts TestClient before blocking connections because Windows asyncio
creates an internal socket pair during loop initialization. The tests run no
real scanners, credential attempts, NVD queries, or AI calls. Temporary files are
created in the project and cleaned up, avoiding the exhausted Windows temporary
drive encountered during testing. An existing Starlette TemplateResponse
deprecation warning remains; it does not fail the suite.

The updated app was also launched on `127.0.0.1:8787`; startup completed, health
and the root page returned HTTP 200, and OpenAPI omitted the removed route. Full
browser styling/layout and real Nmap/Gobuster execution were not tested. CDN
assets, scan-scope enforcement, scan defaults, speculative graph/scoring logic,
and the broader findings-classification problems are outside this change. Status
polling may still update local completion metadata; "read-only" here means no
new target probes, credential attempts, DNS, or external enrichment. Old cached
CVEs are not recreated from missing raw evidence.

This day's scope ends with removal of AI and hidden result-read activity. No
Exposure Change Detector or later-day refactor was implemented.

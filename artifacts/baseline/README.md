# RiskLens baseline

Baseline captured on 2026-11-10 (America/Halifax), before application changes.

- Branch: `chore/local-baseline`, based on commit `6042070`.
- Fresh environment: `.venv-baseline`, Python 3.14.3. The existing `.venv` was preserved.
- Installed all pinned application requirements plus Playwright for screenshots.
- `pip check`: no broken requirements found.
- App running at <http://127.0.0.1:8787>, bound to loopback only.
- `GET /health`: HTTP 200, `status: ok`, `service: risklens-backend`.
- `GET /`: HTTP 200. No JavaScript page errors during screenshot capture.
- No scans were started. The screenshot browser blocks non-read requests. Existing saved scan metadata was preserved.
- Nmap is installed at the configured path. Angry IP Scanner is absent at its configured path; subnet discovery was not tested.
- The app uses CDN assets. Screenshot capture required network access; no application assets were changed.
- The mobile baseline shows horizontal overflow in the header actions; this existing layout issue was recorded without changing the UI.

## Screenshots

Desktop viewport: 1440 × 1000. Mobile viewport: 390 × 844. Screenshots capture the full page.

1. [Overview](./01-overview-desktop.png)
2. [Services](./02-services-desktop.png)
3. [Findings](./03-findings-desktop.png)
4. [Attack Graph](./04-attack-graph-desktop.png)
5. [Web Scan](./05-web-scan-desktop.png)
6. [Scan History](./06-history-desktop.png)
7. [Mobile overview](./07-overview-mobile.png)

## Verification records

- [Health response](./health.json)
- [Browser check results](./browser-check.json)
- [Installed package snapshot](./installed-requirements.txt)
- [Repeatable screenshot capture](./capture_baseline.py)

From the project root, start the existing VS Code task **RiskLens: run baseline**, or run:

```powershell
& '.\.venv-baseline\Scripts\python.exe' -B -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

With the server running, regenerate screenshots in another terminal:

```powershell
& '.\.venv-baseline\Scripts\python.exe' artifacts/baseline/capture_baseline.py
```

The capture script uses the installed Microsoft Edge browser in headless mode. Baseline setup and artifacts have not been committed or pushed.

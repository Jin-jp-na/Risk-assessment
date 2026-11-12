"""Capture the local app's initial screens without starting any scans."""

import json
from pathlib import Path

from playwright.sync_api import sync_playwright


OUTPUT = Path(__file__).resolve().parent
BASE_URL = "http://127.0.0.1:8787"


def main():
    errors = []
    blocked_requests = []
    views = [
        ("Overview", "01-overview-desktop.png", "tab-overview"),
        ("Services", "02-services-desktop.png", "tab-services"),
        ("Findings", "03-findings-desktop.png", "tab-findings"),
        ("Attack Graph", "04-attack-graph-desktop.png", "tab-attack"),
        ("Web Scan", "05-web-scan-desktop.png", "tab-web"),
        ("Scan History", "06-history-desktop.png", "tab-history"),
    ]

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 1000})

        def allow_read_only(route):
            if route.request.method not in {"GET", "HEAD", "OPTIONS"}:
                blocked_requests.append(route.request.url)
                route.abort()
            else:
                route.continue_()

        context.route("**/*", allow_read_only)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        health = context.request.get(BASE_URL + "/health")
        assert health.status == 200, health.status
        assert health.json()["status"] == "ok", health.text()
        (OUTPUT / "health.json").write_text(
            json.dumps(health.json(), indent=2) + "\n", encoding="utf-8"
        )
        response = page.goto(BASE_URL, wait_until="networkidle")
        assert response.status == 200, response.status
        page.get_by_text("No scan started yet.", exact=True).first.wait_for()
        for name, filename, panel in views:
            page.get_by_role("button", name=name, exact=True).click()
            page.locator("#" + panel).wait_for(state="visible")
            page.screenshot(path=str(OUTPUT / filename), full_page=True)

        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="networkidle")
        page.locator("#tab-overview").wait_for(state="visible")
        page.screenshot(path=str(OUTPUT / "07-overview-mobile.png"), full_page=True)
        report = {
            "url": BASE_URL,
            "health_status": health.status,
            "root_status": response.status,
            "desktop_viewport": {"width": 1440, "height": 1000},
            "mobile_viewport": {"width": 390, "height": 844},
            "screenshots": [view[1] for view in views] + ["07-overview-mobile.png"],
            "page_errors": errors,
            "blocked_non_read_requests": blocked_requests,
            "scans_started": 0,
        }
        (OUTPUT / "browser-check.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        browser.close()
        assert not errors, errors
        assert not blocked_requests, blocked_requests
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

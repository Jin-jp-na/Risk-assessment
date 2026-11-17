"""Explicit offline migration; stop the app first. Never scans or resolves targets."""
from backend import main
from backend.snapshots import read_json


def main_cli():
    saved = read_json(main.SCAN_STATUS_FILE) or {}
    if any(value.get("status") in {"pending", "running", "nmap_done"} for value in saved.values()):
        raise SystemExit("Active/interrupted jobs exist. Start then stop the backend to reconcile them before migration.")
    for scan_id, value in saved.items():
        main.checked_scan_id(scan_id)
        main.scan_status_store[scan_id] = main.ScanStatus.model_validate(value)
    for scan_id in main.scan_status_store:
        if (main.SCANS_DIR / f"snapshot_{scan_id}.json").exists():
            print(f"{scan_id}: existing snapshot preserved")
            continue
        try:
            snapshot = main.persist_snapshot(scan_id)
            print(f"{scan_id}: {snapshot['status']}")
        except (OSError, ValueError) as exc:
            print(f"{scan_id}: cannot normalize: {exc}")


if __name__ == "__main__":
    main_cli()

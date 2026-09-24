"""Reference automation pattern for the Automation Standards repository.

This example intentionally uses only the Python standard library. Replace
run_work() with the real automation logic and keep the completion contract.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path("automation_results")
AUTOMATION_NAME = "Example Infrastructure Automation"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_work() -> dict:
    # Replace this with the actual automation.
    time.sleep(1)
    return {
        "ItemsProcessed": 25,
        "Violations": 2,
        "OutputFile": "example-report.json",
    }


def main() -> int:
    run_id = str(uuid.uuid4())
    started = utc_now()
    start_monotonic = time.monotonic()
    status = "Success"
    result = {}
    error = None

    try:
        result = run_work()
    except Exception as exc:  # noqa: BLE001 - reference pattern intentionally captures terminal failure
        status = "Failed"
        error = {"Type": type(exc).__name__, "Message": str(exc)}

    completed = utc_now()
    duration = round(time.monotonic() - start_monotonic, 3)

    completion = {
        "SchemaVersion": "1.0",
        "Name": AUTOMATION_NAME,
        "Status": status,
        "RunId": run_id,
        "Started": started,
        "Completed": completed,
        "Lastrun": completed,
        "DurationSeconds": duration,
        "Summary": "Reference automation completion record.",
        **result,
    }

    if error:
        completion["Error"] = error

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / f"{AUTOMATION_NAME.lower().replace(' ', '_')}.json"
    output.write_text(json.dumps(completion, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote completion JSON: {output}")
    return 0 if status == "Success" else 1


if __name__ == "__main__":
    raise SystemExit(main())

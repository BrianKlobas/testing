# Automation Standards

## Purpose

This repository defines the standard contract for infrastructure/security automation that will be surfaced through the Infrastructure Intelligence platform.

The core standard is simple:

> **Automations are Python programs, and every completed run produces a completion JSON document.**

For the current local platform, completion JSON files are stored locally. The target platform architecture moves those files into an S3-backed results store so that status, timing, history, reporting, and future re-trigger/re-run actions can be driven from a common contract.

This repository is a **standards/design repository**. It documents the contract and includes a reference example; it is not itself the production orchestration engine.

---

## Core principles

1. **Python is the standard automation language.**
2. **Every automation produces one completion JSON document per run.**
3. **The completion document is machine-readable first, human-readable second.**
4. **Minimum fields are stable and predictable.**
5. **Additional key/value data is allowed and should be surfaced by the platform.**
6. **Run status and timestamps are explicit.**
7. **A run has a unique identifier so history can be retained.**
8. **The result format must work from local files today and S3 tomorrow.**
9. **The platform should eventually be able to re-trigger an automation from its recorded metadata.**
10. **Automations should not need to know how the platform UI stores or displays their results.**

---

## Repository structure

```text
Automation-Standards/
├── README.md
├── schemas/
│   └── completion.schema.json       # Proposed machine-readable contract
├── examples/
│   ├── automation_example.py       # Reference Python automation
│   └── output/
│       └── completion-example.json  # Example completed run
└── docs/
    └── diagrams/
        ├── automation-lifecycle.md
        └── platform-architecture.md
```

---

# 1. Python standard

All new automation intended for the platform should be written in Python unless there is a documented technical reason to use another implementation.

Typical automation responsibilities may include:

- AWS inventory collection
- AWS Organizations collection
- Palo Alto/Firewall collection
- Wiz collection
- compliance checks
- security policy checks
- remediation preparation
- reporting
- data synchronization
- infrastructure discovery

Python gives the automation layer a consistent operational model and makes the output contract independent of the implementation details.

The platform does **not** need to understand the internal Python code. It needs the automation to honor the completion contract.

---

# 2. Completion JSON standard

## Minimum required fields

Every completed automation must write at least:

| Field | Required | Meaning |
|---|---:|---|
| `Name` | Yes | Human-readable automation name |
| `Status` | Yes | Final run status, such as `Success`, `Failed`, or `Partial` |
| `Lastrun` | Yes | Timestamp representing the completion time of the run |

These are the minimum fields required by the current local Automation Results page.

## Recommended standard fields

The proposed platform standard adds structured run metadata:

| Field | Recommended | Meaning |
|---|---:|---|
| `SchemaVersion` | Yes | Completion contract version |
| `Name` | Yes | Automation name |
| `Status` | Yes | Final status |
| `RunId` | Yes | Unique identifier for this execution |
| `Started` | Yes | Start timestamp |
| `Completed` | Yes | Completion timestamp |
| `Lastrun` | Yes | Compatibility/display timestamp; normally equal to `Completed` |
| `DurationSeconds` | Yes | Total execution duration |
| `Summary` | No | Human-readable summary |
| `Error` | No | Failure/error information when applicable |
| `Metrics` | No | Structured counters and measurements |
| `HistoryKey` | Future | Logical history identifier/group |
| `Rerun` | Future | Metadata describing how the platform can re-trigger the automation |

Additional top-level keys are allowed.

---

# 3. Example completion JSON

```json
{
  "SchemaVersion": "1.0",
  "Name": "AWS Security Group Compliance Check",
  "Status": "Success",
  "RunId": "8d0d2f0e-2a7d-4d83-a6f3-3fdb9e7e2d8a",
  "Started": "2026-09-24T16:00:12Z",
  "Completed": "2026-09-24T16:04:41Z",
  "Lastrun": "2026-09-24T16:04:41Z",
  "DurationSeconds": 269,
  "Summary": "Checked AWS Security Groups across the organization.",
  "Metrics": {
    "AccountsChecked": 412,
    "SecurityGroupsChecked": 18473,
    "Violations": 37,
    "Errors": 0
  },
  "Violations": 37,
  "AccountsProcessed": 412,
  "OutputFile": "sg_compliance_2026-09-24.json"
}
```

The important point is that the automation can add useful data without requiring a new UI template for every field.

---

# 4. How additional key/value fields are displayed

The current local Infrastructure Intelligence Automation Results page requires `Name`, `Status`, and `Lastrun`, then displays additional keys from the completion JSON as extra information.

For the example above, the platform can display the standard fields first:

```text
AWS Security Group Compliance Check
-----------------------------------
Status: Success
Last Run: 2026-09-24T16:04:41Z

Additional Results
------------------
Violations: 37
AccountsProcessed: 412
OutputFile: sg_compliance_2026-09-24.json

Metrics
-------
AccountsChecked: 412
SecurityGroupsChecked: 18473
Violations: 37
Errors: 0
```

This means an automation can return domain-specific values without requiring the automation platform to understand every possible automation type.

### Standard fields vs. extension fields

```text
Completion JSON
      |
      +--> Standard fields
      |      Name
      |      Status
      |      Lastrun
      |      RunId
      |      Started
      |      Completed
      |      DurationSeconds
      |
      +--> Extension fields
             Metrics
             Violations
             AccountsProcessed
             OutputFile
             Any future automation-specific values
```

The UI should treat unknown fields as data, not as an error.

---

# 5. Status standard

Use a small, predictable set of final statuses.

Recommended values:

- `Success` — automation completed as intended.
- `Partial` — automation completed but one or more portions did not complete successfully.
- `Failed` — automation did not complete successfully.

If the platform later needs lifecycle states such as `Running`, those should be represented separately from the **completion** document or through a run-state store. The completion JSON is produced when the automation reaches its terminal state.

Avoid inventing dozens of status strings that make platform-wide filtering difficult.

---

# 6. Time and run history

Every run should have a unique `RunId` and timestamps.

At minimum:

```text
Started
   |
   v
Python automation executes
   |
   v
Completed
   |
   v
completion JSON written
```

The platform can use these values to calculate and display:

- last run
- execution duration
- run history
- failure history
- success/partial/failure trends
- stale automation detection

### History model

A logical automation may have many runs:

```text
Automation: AWS Security Group Compliance Check

Run 001 -> Success -> 2026-09-22
Run 002 -> Success -> 2026-09-23
Run 003 -> Failed  -> 2026-09-24 08:00
Run 004 -> Success -> 2026-09-24 12:00
```

The completion document represents **one run**. A platform-level history index can aggregate all runs for the same automation.

---

# 7. Current local storage

Today, the local Infrastructure Intelligence application can read completion files from:

```text
automation_results/
```

Example:

```text
automation_results/
├── aws_security_group_compliance.json
├── aws_org_collection.json
├── palo_policy_usage.json
└── wiz_policy_check.json
```

The current local UI reads the JSON and displays:

- `Name`
- `Status`
- `Lastrun`
- additional fields

This keeps the initial implementation extremely simple: a Python automation finishes, writes JSON, and the platform can immediately consume it.

---

# 8. Future S3 storage

The intended next architecture is to replace local filesystem storage with S3 without changing the automation's core output contract.

Conceptually:

```text
Python automation
       |
       v
completion JSON
       |
       v
S3 automation-results bucket
       |
       +--------------------+
       |                    |
       v                    v
Run history            Current status
       |                    |
       +---------+----------+
                 |
                 v
          Infrastructure
          Intelligence UI
```

A future object layout could look like:

```text
s3://<automation-results>/
  <automation-name>/
    history/
      2026/09/24/<run-id>.json
    latest.json
```

The exact bucket/key layout is intentionally left as a platform implementation decision. The important standard is that the JSON contract remains stable.

---

# 9. Future re-trigger / re-run capability

The long-term platform should be able to show a completed automation and offer a **Re-run** or **Re-trigger** action.

The important design principle is that the result file describes the completed run; it does not itself execute the automation.

Future flow:

```text
User opens automation result
          |
          v
Platform reads completion JSON
          |
          v
User selects "Re-run"
          |
          v
Platform identifies automation + parameters
          |
          v
Orchestrator starts a new Python run
          |
          v
New RunId assigned
          |
          v
New completion JSON written
          |
          v
History now contains both runs
```

A future `Rerun` section can carry metadata such as:

```json
"Rerun": {
  "Enabled": true,
  "AutomationId": "aws-security-group-compliance",
  "Parameters": {
    "Environment": "prod"
  }
}
```

This is a **future capability**, not a requirement for the current local filesystem implementation.

---

# 10. Parameters and reproducibility

If an automation depends on parameters, the run should record enough information to explain what was executed.

For example:

```json
"Parameters": {
  "Environment": "prod",
  "Regions": ["us-east-1", "us-east-2"],
  "SeverityThreshold": "high"
}
```

Do not place secrets, passwords, API tokens, or credentials into completion JSON.

If parameters contain sensitive values, record a safe identifier or redacted representation instead.

---

# 11. Error handling

A failed automation should still attempt to write its completion JSON.

Example:

```json
{
  "SchemaVersion": "1.0",
  "Name": "AWS Security Group Compliance Check",
  "Status": "Failed",
  "RunId": "f0f0b55d-9af0-4d98-a6d4-bb0fdb4b8d3a",
  "Started": "2026-09-24T17:00:00Z",
  "Completed": "2026-09-24T17:00:17Z",
  "Lastrun": "2026-09-24T17:00:17Z",
  "DurationSeconds": 17,
  "Error": {
    "Type": "AccessDenied",
    "Message": "Unable to read Security Group inventory."
  }
}
```

The platform should be able to show the failure without requiring access to the automation host's console output.

---

# 12. Reference Python pattern

See [`examples/automation_example.py`](examples/automation_example.py).

The pattern is:

```text
start timer
   |
   v
run automation work
   |
   +---- success/partial/failure
   |
   v
build completion dictionary
   |
   v
write completion JSON
```

The completion writer should be small and reusable. Business logic belongs in the automation itself; result-contract logic belongs at the end of the run.

---

# 13. What the platform should eventually track

At the platform level, the model should support:

### Automation identity

- automation name
- stable automation ID
- description
- owner/team
- enabled/disabled state

### Execution state

- current status
- last run
- last success
- last failure
- current/last run ID

### Timing

- start time
- completion time
- duration

### History

- every run ID
- every completion status
- timestamps
- error information
- selected metrics

### Actions

Future platform actions may include:

- Re-run
- Re-trigger
- view latest result
- view previous run
- compare runs
- view logs/output location

These are platform capabilities built around the completion contract; they do not need to be embedded into each Python automation.

---

# 14. Non-goals

The completion JSON is not intended to be:

- a replacement for detailed application logs
- a place to store credentials or secrets
- a full database dump
- an unbounded binary artifact
- a substitute for source-system data

Large reports/artifacts should be stored separately, with the completion JSON containing a reference such as an object key, file name, report ID, or URL as appropriate.

---

# 15. Standard adoption checklist

A new automation is ready for platform integration when:

- [ ] Written in Python.
- [ ] Has a stable automation name/identity.
- [ ] Produces one completion JSON per terminal run.
- [ ] Includes `Name`.
- [ ] Includes `Status`.
- [ ] Includes `Lastrun`.
- [ ] Includes `RunId`.
- [ ] Includes `Started` and `Completed` timestamps.
- [ ] Includes `DurationSeconds` where practical.
- [ ] Writes a completion record on failure when possible.
- [ ] Does not write secrets into the completion JSON.
- [ ] Places domain-specific values in additional keys rather than changing the required fields.
- [ ] Keeps large artifacts outside the completion JSON and references them from the result.

---

## Relationship to Infrastructure Intelligence

The local Infrastructure Intelligence application already has an **Automation Results** page that reads completion JSON files from the local filesystem. The future platform can replace that local directory with an S3-backed results/history service while keeping the automation contract consistent.

That separation is intentional:

```text
Automation implementation
        !=
Platform implementation
        !=
UI implementation
```

The completion JSON is the contract connecting them.

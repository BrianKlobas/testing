# Infrastructure Intelligence (Infra Intel) — v21

Local Flask/Jinja security and infrastructure intelligence dashboard for AWS, Palo Alto, Wiz, automation events, and audit/reporting events.

This release is based on the previous v20 package and updates the Automation Results event layout, event-directory model, status handling, Wiz filter initialization, and documentation.

## Design principles

- Python + Flask + Jinja + HTML/CSS.
- No browser-side JavaScript is required for the dashboard UI.
- Existing search, filters, prefilled choices, and server-rendered pages remain intact.
- Large datasets should not be automatically rendered when a page is opened.
- Collectors/ingestion and the web application remain separate concerns.
- JSON event files are metadata/status records; they are not executable command files.

## Directory layout

```text
infra_intel_local_v21/
├── app.py
├── database.py
├── ingest.py
├── aws_org_collect.py
├── aws_resource_collect.py
├── static/
│   └── app.css
├── templates/
│   ├── base.html
│   ├── search.html
│   ├── firewall_policy_lookup.html
│   ├── palo_object_search.html
│   ├── wiz_policy_check.html
│   ├── aws_org_topology.html
│   ├── automation_results.html
│   ├── audit_reporting.html
│   ├── information_links.html
│   └── about.html
├── automation_results/
│   ├── success/
│   └── fails/
├── audit_results/
│   ├── success/
│   └── fails/
└── README.md
```

The `success/` and `fails/` folders are intentionally separate from the application code. In the long-term AWS architecture, they can correspond to S3 event prefixes synchronized into the local application or consumed by an equivalent event adapter.

---

# 1. Running the application

Start the web application:

```powershell
python app.py
```

Default address:

```text
http://localhost:8080/
```

The application does not ingest source JSON while serving the web UI. Run `ingest.py` when AWS/Palo Alto/Wiz source data changes.

Example:

```powershell
python ingest.py
```

The application supports these path options:

```powershell
python app.py `
  --db infra_intel.db `
  --firewall-data parsed `
  --aws-data aws_parsed `
  --org-file org_topology.json `
  --automation-results automation_results `
  --audit-results audit_results `
  --port 8080
```

## Command-line options

| Option | Default | Purpose |
|---|---|---|
| `--db` | `./infra_intel.db` | SQLite database used by the dashboard and normalized Wiz data |
| `--firewall-data` | existing parsed firewall-data path | Parsed Palo Alto data source used by the application |
| `--aws-data` | existing parsed AWS-data path | Parsed AWS data source used by the application |
| `--org-file` | `./org_topology.json` | AWS Organization topology used for account/OU context |
| `--automation-results` | `./automation_results` | Automation event root containing flat JSON and/or `success/` and `fails/` |
| `--audit-results` | `./audit_results` | Audit event root containing `success/` and `fails/` |
| `--port` | `8080` | Flask listen port |
| `--host` | `0.0.0.0` | Flask listen address |
| `--debug` | off | Flask debug mode |

---

# 2. Automation Results

The **Automation Results** page is a server-rendered event dashboard. It shows the current automation event records and supports:

- **All**
- **Success**
- **Failed**
- expandable **View Event Details**
- optional **Run Again** button
- event filename
- description
- last-run timestamp
- arbitrary additional event fields

## Automation event directories

The preferred layout is now:

```text
automation_results/
├── success/
│   ├── aws_vpc_inventory.json
│   ├── aws_org_inventory.json
│   └── another_automation.json
└── fails/
    ├── aws_vpc_inventory.json
    └── another_automation.json
```

For backward compatibility, the application also continues to read JSON files directly under:

```text
automation_results/*.json
```

Therefore an existing deployment does not have to move all existing event files immediately.

### Recommended AWS/S3 model

The event bucket can use separate automation prefixes:

```text
<event-bucket>/
└── automation-results-events/
    ├── success/
    │   ├── aws_vpc_inventory.json
    │   └── ...
    └── fails/
        ├── aws_vpc_inventory.json
        └── ...
```

A sync/collector process can mirror those event objects into the local:

```text
automation_results/success/
automation_results/fails/
```

The Flask application itself does not need AWS credentials simply to display local event JSON.

## Required automation fields

Only one field is effectively required:

### `Name`

Identifies the automation in the UI.

If `Name` is omitted, the application uses the JSON filename without its extension as the display name.

## Recommended automation fields

```json
{
  "Name": "AWS VPC Inventory",
  "Status": "Successful",
  "Lastrun": "2026-10-05T09:00:00Z",
  "Description": "Collect VPC inventory across all AWS accounts",
  "Run_Again": {
    "key": "Automation",
    "value": "aws-vpc-inventory"
  },
  "Accounts": 431,
  "Regions": 5
}
```

### Accepted fields

| Field | Required | Accepted value | Purpose |
|---|---:|---|---|
| `Name` | No | string | Display name; filename is fallback |
| `Status` | No | string | Used for status filtering and status pill |
| `Lastrun` | No | string | Last execution time shown in the card |
| `Description` | No | string | Human-readable description |
| `Run_Again` | No | object `{key,value}` or 2-item array | Supplies safe Run Again identifier |
| `Run_Again_Key` | No | string | Alternative to `Run_Again.key` |
| `Run_Again_Value` | No | string | Alternative to `Run_Again.value` |
| any other fields | No | any JSON value | Displayed under Event Details |

Field-name matching is case-insensitive for the recognized fields.

For example, `status`, `Status`, and `STATUS` are recognized as the same field.

## Automation status filtering

Status matching is normalized and case-insensitive.

The following values are treated as **Success**:

```text
SUCCESS
Successful
Succeeded
Complete
Completed
OK
Passed
```

Formatting differences such as capitalization and surrounding whitespace are ignored.

The following values are treated as **Failed**:

```text
FAIL
Failed
Failure
Error
Errored
Unsuccessful
```

Statuses beginning with `fail` are also treated as failed.

Anything else is displayed as a neutral/unknown status and appears under **All**, but not under Success or Failed.

This means an event such as:

```json
{
  "Name": "Example",
  "Status": "Successful"
}
```

correctly appears when the **Success** filter is selected.

## Automation Run Again

Run Again is deliberately based on a **key/value identifier**, not a shell command or arbitrary executable string.

Preferred format:

```json
"Run_Again": {
  "key": "Automation",
  "value": "aws-vpc-inventory"
}
```

Equivalent format:

```json
{
  "Run_Again_Key": "Automation",
  "Run_Again_Value": "aws-vpc-inventory"
}
```

The UI sends the pair to:

```text
/automation/run?key=Automation&value=aws-vpc-inventory
```

The Flask route does **not** execute arbitrary commands supplied by the event. The key/value pair is an identifier that a future automation dispatcher can map to an approved workflow, Lambda, Step Function, or other runner.

This prevents an event JSON file from becoming an arbitrary command-execution mechanism.

---

# 3. Audit / Reporting

The **Audit / Reporting** page uses the same general event-card model but is designed for audits that generate a report artifact.

The local layout is:

```text
audit_results/
├── success/
│   ├── aws_vpc_audit.json
│   └── security_group_audit.json
└── fails/
    └── aws_vpc_audit.json
```

The preferred AWS event-bucket layout is:

```text
<event-bucket>/
└── audit-results-events/
    ├── success/
    └── fails/
```

The actual report files belong in a separate audit-results bucket:

```text
<audit-results-bucket>/
├── aws-vpc-audit/
│   └── 2026-10-05/
│       └── aws-vpc-audit-20261005-090000.xlsx
├── security-group-audit/
│   └── 2026-10-05/
│       └── security-group-audit-20261005-090000.xlsx
└── palo-policy-audit/
    └── ...
```

The event JSON acts as metadata and a pointer to the latest generated report.

## Required audit fields

No field is required for the page to parse a JSON event successfully.

`Name` is strongly recommended because it identifies the audit/report in the UI.

If `Name` is omitted, the JSON filename is used.

## Recommended audit event

```json
{
  "Name": "AWS VPC Audit",
  "Status": "Successful",
  "Lastrun": "2026-10-05T09:00:00Z",
  "File": "https://example.example/report.xlsx",
  "File_Name": "aws-vpc-audit-20261005-090000.xlsx",
  "Description": "AWS VPC configuration audit across all accounts",
  "Run_Again": "/audit/run?name=aws-vpc-audit",
  "Accounts": 431,
  "Regions": 5
}
```

### Accepted audit fields

| Field | Required | Purpose |
|---|---:|---|
| `Name` | No | Audit/report display name; filename fallback |
| `Status` | No | Status filter and status pill |
| `Lastrun` | No | Last execution time |
| `Description` | No | Human-readable description |
| `File` | No | HTTPS report URL or `s3://bucket/key` reference |
| `File_Name` | No | Report filename shown/retained as metadata |
| `Run_Again` | No | Safe local application path for rerun |
| any other fields | No | Shown under Event Details |

Recognized field names are matched case-insensitively.

## Audit report links

For private S3 reports, the preferred design is for the event-producing system to place a current HTTPS presigned URL in `File`.

Example:

```json
"File": "https://signed-url.example/report.xlsx"
```

The application also accepts:

```text
s3://my-audit-results/aws-vpc-audit/2026-10-05/report.xlsx
```

but displays an `s3://` value as a reference rather than pretending it is a browser-accessible link.

## Audit Run Again

Audit events may provide a local application path in `Run_Again`. The application intentionally does not execute shell commands from event JSON.

The current placeholder route accepts requests such as:

```text
/audit/run?name=aws-vpc-audit
```

A future runner can replace/register the route and map the audit name to an approved Step Function or other workflow.

## Latest event behavior

Audit/Reporting keeps the **latest event per report/audit name** for the dashboard. Historical event JSON can remain retained in S3 without producing an ever-growing set of duplicate cards in the UI.

---

# 4. Wiz Policy Check

The Wiz page searches Wiz Security Group findings and correlates them with AWS account/OU context.

## Page-load behavior

The page intentionally has two separate behaviors:

1. **Filter choices are populated when the page opens.**
2. **Finding cards are not displayed until the user submits a search.**

This means the AWS OU, AWS Account, and Wiz Policy dropdown/datalist choices are available immediately without rendering the entire Wiz findings dataset.

The Security Group field remains a free-text SG name/ID search field.

## Wiz data source

Wiz source data is expected to be normalized into the SQLite database by `ingest.py`.

Raw Developer Console JSON can be stored under:

```text
wiz_data/
```

for ingestion/testing.

Example:

```text
wiz_data/
├── issues_page_001.json
├── issues_page_002.json
└── issues_page_003.json
```

The web application reads the normalized SQLite `wiz_issues` table rather than repeatedly parsing the raw files.

## Wiz filter fields

| Filter | Behavior |
|---|---|
| AWS OU | Matches OU or OU path |
| AWS Account | Matches account name or account ID |
| Security Group | Matches SG name or SG ID |
| Wiz Policy | Matches policy name or policy ID |

Filters can be combined.

## Wiz issue fields used

The current parser uses information such as:

```text
id
status
severity
type
control.id
control.name
control.description
control.resolutionRecommendation
sourceRule.id
sourceRule.name
entitySnapshot.id
entitySnapshot.type
entitySnapshot.nativeType
entitySnapshot.name
entitySnapshot.cloudPlatform
entitySnapshot.providerId
entitySnapshot.externalId
entitySnapshot.region
entitySnapshot.cloudProviderURL
project.id
project.name
project.slug
```

Security Group findings are identified using:

```text
entitySnapshot.nativeType = securityGroup
```

The exact AWS Security Group ID is taken from:

```text
entitySnapshot.externalId
```

The AWS ARN is taken from:

```text
entitySnapshot.providerId
```

AWS account and OU context is resolved from `org_topology.json` when the account ID can be derived from the AWS ARN.

## Wiz Developer Console query

A suitable test query is:

```graphql
query {
  issuesV2(first: 100) {
    nodes {
      id
      createdAt
      updatedAt
      status
      severity
      type
      control {
        id
        name
        description
        resolutionRecommendation
      }
      sourceRule {
        id
        name
      }
      entitySnapshot {
        id
        type
        nativeType
        name
        cloudPlatform
        providerId
        externalId
        region
        cloudProviderURL
      }
      project {
        id
        name
        slug
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```

Save the complete response as `wiz_data/issues_page_001.json`. Repeat with `after: "<endCursor>"` until `hasNextPage` is false.

Then run:

```powershell
python ingest.py --wiz-data wiz_data --org-file org_topology.json --db infra_intel.db
```

---

# 5. Search & Investigate

Search & Investigate is the general infrastructure/security lookup page.

It can correlate identifiers such as:

- IP addresses
- CIDRs
- AWS instance IDs
- ENI IDs
- Security Group IDs
- DNS/R53 information
- Palo Alto objects/groups/rules

The search engine is backed by the SQLite data model and supports CIDR/network rollups and related AWS/Palo Alto relationships.

The UI uses expandable sections to avoid presenting every underlying object immediately.

---

# 6. Firewall Policy Lookup

Firewall Policy Lookup supports source/destination searches with optional port filtering.

The page can search:

- source-only
- destination-only
- source + destination
- optional port
- address objects
- address groups
- security policy rules

The results identify the source/destination object/group and whether matching rules are allowed or denied.

---

# 7. Palo Alto Object Search

Palo Alto Object Search supports separate searches for:

- addresses
- address groups
- services
- service groups
- applications
- custom URL categories

Matching is case-insensitive where appropriate.

For services, exact port matching is used so searching for `443` does not incorrectly return `1443`.

Custom URL category searches support both category names and member FQDNs.

---

# 8. AWS Organization Topology

AWS Org Topology reads the organization inventory and presents accounts/OUs in a collapsible hierarchy.

Account data can include:

- account ID
- account name
- Primary Owner
- Secondary Owner
- all account tags
- AWS role/switch-role context when configured

The page supports account-name filtering/partial matching.

---

# 9. Ingestion architecture

The web application is intentionally separated from data collection.

Typical flow:

```text
AWS / Palo Alto / Wiz source data
            |
            v
      Collector / ingest
            |
            v
       Parsed JSON / SQLite
            |
            v
       Flask / Jinja UI
```

For future AWS deployment, collectors can run independently through Step Functions/Lambda or equivalent infrastructure. The UI can remain a consumer of normalized data and event metadata.

For event-driven automation/audit reporting:

```text
Automation / Audit runner
          |
          +----> event JSON ----> event S3 bucket
          |                         success/
          |                         fails/
          |
          +----> report artifact -> audit/results S3 bucket
```

The local application can consume synchronized event JSON from the corresponding local directories.

---

# 10. JSON safety rules

Event JSON is treated as data.

The application does not:

- execute shell commands from JSON
- evaluate Python from JSON
- treat arbitrary JSON strings as executable programs
- allow an event file to choose an arbitrary local executable

Run Again uses identifiers that can later be mapped to an approved automation/audit dispatcher.

---

# 11. APIs

Automation results:

```text
GET /api/automation/results
GET /api/automation/results?status=success
GET /api/automation/results?status=failed
```

Audit results:

```text
GET /api/audit/results
GET /api/audit/results?status=success
GET /api/audit/results?status=failed
```

The API status filters use the same normalized status behavior as the corresponding UI.

Wiz export:

```text
GET /export/wiz-policy-check
```

Other application pages also provide server-side JSON export where supported.

---

# 12. Recommended event conventions

For consistency across automation and audit systems, use this common base structure:

```json
{
  "Name": "Human-readable job name",
  "Status": "Successful",
  "Lastrun": "2026-10-05T09:00:00Z",
  "Description": "What the job does"
}
```

Automation events should additionally use:

```json
"Run_Again": {
  "key": "Automation",
  "value": "approved-job-id"
}
```

Audit events should additionally use:

```json
"File": "https://.../latest-report.xlsx",
"File_Name": "latest-report.xlsx"
```

Additional job-specific fields are allowed and are displayed under Event Details.

Using ISO-8601 timestamps in UTC is recommended for `Lastrun` so events from multiple AWS regions/systems can be compared consistently.

---

# 13. No-JavaScript UI

The dashboard uses normal Flask GET requests and native HTML `<details>` elements for expandable sections.

There is intentionally no requirement for a browser-side JavaScript framework.

This keeps the application simple, portable, and easy to host internally.

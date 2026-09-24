# Infrastructure Intelligence — Local Repository

A local, server-rendered infrastructure/security intelligence application built with **Python, Flask, Jinja HTML, CSS, and SQLite**.

This repository is the documentation-oriented package for the current working local application. It intentionally preserves the existing application architecture and does **not** introduce JavaScript or additional application languages.

## What this application does

Infrastructure Intelligence provides one local UI for searching and correlating infrastructure/security data from multiple sources.

Current data domains include:

- **AWS infrastructure** — accounts, resources, networks, ENIs, EC2, VPC/subnet context, Security Groups, Route 53 data, and related indexed records.
- **Palo Alto / Panorama** — address objects, address groups, services, service groups, applications, custom URL categories, NAT/PBF/security rules, and relationships between objects and rules.
- **Wiz** — issues/findings, policies, and Security Groups, including correlation of a Wiz Security Group to the existing AWS Security Group inventory.
- **AWS Organizations** — account hierarchy, OU placement, tags, primary/secondary owners, and account information.
- **Automation Results** — completion JSON files produced by automation jobs. The UI renders the required fields (`Name`, `Status`, `Lastrun`) plus additional fields supplied by the automation.

The application is designed so that source collection/normalization happens before the web application reads the data. The web application primarily performs searches, relationships, rendering, and exports.

---

## Architecture at a glance

```text
                 DATA COLLECTION / SOURCE EXPORTS
                 --------------------------------
 AWS APIs ------> aws_resource_collect.py ----\
 AWS Organizations -> aws_org_collect.py -----+----> JSON source data
 Panorama exports / parsed objects -----------/
 Wiz GraphQL Developer Console/API ----------/
                                                   |
                                                   v
                                              ingest.py
                                                   |
                                                   v
                                           SQLite / indexes
                                                   |
                                                   v
                                               app.py
                                                   |
                                                   v
                                       Flask + Jinja + CSS UI
                                                   |
                 +-----------------+---------------+----------------+
                 |                 |               |                |
                 v                 v               v                v
            Search &         Firewall Policy   Palo Object      Wiz Policy
            Investigate         Lookup           Search            Check
                 |                 |               |                |
                 +-----------------+---------------+----------------+
                                                   |
                                                   v
                                             JSON exports

                           automation_results/*.json
                                      |
                                      v
                             Automation Results page
```

A more detailed Mermaid diagram is in [`docs/diagrams/architecture.md`](docs/diagrams/architecture.md).

---

## Repository structure

```text
Infrastructure-Intelligence-Local/
├── app.py                         # Flask application, routes, search logic, rendering/export logic
├── database.py                    # SQLite schema, indexing, database helpers and queries
├── ingest.py                      # Converts source JSON into the SQLite search/index model
├── aws_resource_collect.py        # AWS resource collector
├── aws_org_collect.py             # AWS Organizations/account/tag collector
├── requirements.txt
├── static/
│   └── app.css                    # Application CSS
├── templates/
│   ├── base.html
│   ├── search.html
│   ├── firewall_policy_lookup.html
│   ├── palo_object_search.html
│   ├── wiz_policy_check.html
│   ├── aws_org_topology.html
│   ├── automation_results.html
│   ├── information_links.html
│   └── about.html
├── README.md
└── docs/
    └── diagrams/
        ├── architecture.md
        └── data-flow.md
```

### Responsibilities

| File | Responsibility |
|---|---|
| `app.py` | Flask routes, server-side search/investigation logic, result shaping, page rendering, JSON export endpoints, AWS/Wiz/Palo correlation logic |
| `database.py` | SQLite database creation, indexes, normalized records, network indexes, and database search helpers |
| `ingest.py` | Reads collected/parsed JSON and rebuilds/updates the SQLite search model |
| `aws_resource_collect.py` | Collects AWS resource information into JSON for later ingestion |
| `aws_org_collect.py` | Collects AWS Organizations hierarchy and account tags/owner fields |
| `templates/` | Server-rendered Jinja pages; no browser-side JavaScript is required |
| `static/app.css` | Shared visual styling |
| `automation_results/` | Optional local directory of automation completion JSON files used by the Automation Results page |

---

## Technology choices

The current application intentionally uses:

- Python 3.11+ recommended
- Flask
- Jinja2 through Flask
- SQLite
- HTML/CSS
- boto3 for AWS collection

There is **no required JavaScript frontend**. Native HTML controls such as `<details>` are used for expandable sections.

---

## Requirements

Install Python and then:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

On Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

AWS collection additionally requires valid boto3 credentials with permissions appropriate to the collector being run. The web UI itself can be run against an existing SQLite database without AWS credentials.

---

## Expected source-data model

The application is deliberately split into **collection**, **ingestion**, and **presentation/search** stages.

```text
Source APIs / exports
        |
        v
JSON files
        |
        |  python ingest.py
        v
infra_intel.db
        |
        |  python app.py
        v
Flask UI
```

This separation is important: changing source JSON does not require the web application to directly query every source API on every user search.

### Typical source directories

The exact collector/export layout can vary, but the current package supports the existing concepts of:

```text
parsed/             # Palo/Panorama parsed data
aws_parsed/         # AWS resource collector output
wiz_data/            # Wiz GraphQL JSON responses
org_topology.json   # AWS Organizations topology/tags
infra_intel.db      # generated SQLite database
automation_results/ # automation completion JSON files
```

Do not commit credentials, secrets, private API responses, or production data to the repository.

---

## Running the application

Basic:

```powershell
python app.py
```

Example with explicit paths:

```powershell
python app.py --db infra_intel.db --firewall-data parsed --aws-data aws_parsed --org-file org_topology.json --port 8080
```

Then open the local Flask address shown by the application.

### Updating the database

When source JSON changes, run ingestion before testing the UI:

```powershell
python ingest.py
```

Or specify the source paths explicitly:

```powershell
python ingest.py --firewall-data parsed --aws-data aws_parsed --wiz-data wiz_data --org-file org_topology.json --db infra_intel.db
```

The web application does not replace the ingestion step.

---

## AWS collection

### AWS resource collection

`aws_resource_collect.py` is the standalone AWS resource collector. It uses boto3 and writes JSON for later ingestion.

### AWS Organizations collection

`aws_org_collect.py` collects the organization hierarchy and account tags. Account tags are retained and normalized into:

- `Tags`
- `PrimaryOwner`
- `SecondaryOwner`

The collector recognizes the existing owner-tag aliases and can be run with explicit tag names, for example:

```powershell
python aws_org_collect.py --output org_topology.json --primary-owner-tag PrimaryOwner --secondary-owner-tag SecondaryOwner
```

The AWS Org page supports partial/case-insensitive account-name search while retaining the matching accounts' parent OU hierarchy.

---

## Current UI pages

### Search & Investigate

Searches the indexed infrastructure/security dataset. Depending on the search, results can correlate:

- AWS resources
- ENIs
- EC2 instances
- Security Groups
- subnets/VPCs
- Route 53 records
- Palo Alto objects/groups/rules
- network containment/roll-up relationships
- Wiz-related indexed data where applicable

The investigation view uses collapsible sections to keep large result sets readable.

### Firewall Policy Lookup

Supports source/destination policy investigation, including optional port criteria. Source and destination objects/groups are presented separately, with matching rule types expandable below them.

### Palo Alto: Object Search

Provides dedicated searches for:

1. Addresses / Address Groups
2. Services / Service Groups
3. Applications
4. Custom URLs

Search behavior includes case-insensitive name matching and exact port semantics for service/application port searches. Custom URL searches inspect the actual FQDN/member values, not just object names.

### Wiz Policy Check

Reads normalized Wiz data from SQLite and correlates Wiz Security Groups to the existing AWS Security Group inventory using the exact AWS Security Group ID. The UI can show AWS-side details such as:

- Security Group name/ID
- VPC
- AWS account
- description
- tags
- inbound/outbound rules
- rule descriptions and referenced resources
- raw AWS Security Group JSON
- associated Wiz policies/issues/findings

### AWS Org Topology

Displays the AWS Organizations hierarchy and account metadata. Account search is server-side and partial/case-insensitive.

### Automation Results

Reads local completion JSON files. The required display fields are:

- `Name`
- `Status`
- `Lastrun`

Additional JSON keys are preserved and displayed as additional result information. This page is the first local representation of the broader automation-standard model documented in the separate **Automation Standards** repository.

---

## JSON export

The search-oriented pages provide server-side JSON export. Export data is generated from structured Python result objects rather than scraping the rendered HTML.

Current export-capable areas include:

- Search & Investigate
- Firewall Policy Lookup
- Palo Alto Object Search
- Wiz Policy Check

The export approach is intended to remain reusable as additional search pages are added.

---

## Design principles

1. **Python-first** — collection, processing, search, correlation, and orchestration stay in Python.
2. **Server-rendered UI** — Flask/Jinja/HTML/CSS; no required JavaScript frontend.
3. **Separate collection from search** — source systems are collected into files, then ingested into SQLite.
4. **Index for speed** — common searches should hit SQLite indexes rather than repeatedly parsing large JSON files.
5. **Preserve source context** — raw JSON remains available where useful for investigation.
6. **Containment over broad overlap** — IP/CIDR investigations use network containment semantics so a /32 does not explode into unrelated overlapping records.
7. **Avoid aggregate/noisy records in normal relationships** — broad safety-net JSON is available for exact inspection but should not create normal object/rule relationships.
8. **Reusable export model** — result exports are generated from server-side structures.
9. **Do not alter working authentication behavior casually** — authentication/login is treated as an existing integration boundary.

---

## Security and operational notes

- Keep AWS credentials outside the repository.
- Do not commit `infra_intel.db` if it contains production-sensitive information.
- Do not commit Panorama/Palo Alto configurations, Wiz responses, or AWS inventory unless explicitly sanitized.
- Treat raw source JSON as potentially sensitive infrastructure data.
- Run collectors with the minimum read permissions required.
- The local application is intended as an internal infrastructure/security intelligence tool, not a public internet-facing service.

---

## Future direction

The local package is intentionally a foundation rather than the final deployment architecture. Likely future directions include:

```text
Current local state
-------------------
Collectors -> JSON -> SQLite -> Flask

Future platform state
---------------------
Collectors/Automations
        |
        v
Completion JSON
        |
        v
S3 automation-results bucket
        |
        +--> history/status
        +--> platform UI
        +--> re-trigger/re-run controls
        |
        v
Cloud-hosted orchestration/search services
```

The separate **Automation Standards** repository defines the completion-file contract that makes this future model possible.

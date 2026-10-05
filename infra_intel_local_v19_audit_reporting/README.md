# Infrastructure Intelligence Local v19 — Server-Rendered UI

This package is based on the uploaded `infra_intel_local_v18_wiz_lazy_results_prefilled.zip` baseline and adds Audit / Reporting.

## What changed

- Replaced the single all-in-one `index.html` UI with separate Flask/Jinja pages.
- Removed browser-side JavaScript entirely.
- UI is now Python/Flask + Jinja HTML + CSS only.
- Search & Investigate uses a normal GET form and server-side rendering.
- Firewall Policy Lookup uses a normal GET form and server-side rendering.
- AWS Org Topology is loaded/rendered by Flask.
- AWS cross-account role links still work. Enter the role name and submit the form.
- Automation Results are loaded/rendered by Flask.
- Added a new **Wiz Policy Check** page as a server-rendered placeholder for the Wiz workflow.
- Removed the **PAN Panorama Topology** page from navigation.
- Removed the **Collection Analytics** page from navigation.
- Existing `/api/*` endpoints are retained for compatibility/future integrations; the UI does not depend on them.
- Existing investigation, policy lookup, AWS Org tag/owner, automation-result, and collector functionality was otherwise left intact.

## Layout

```text
infra_intel_local_v6/
├── app.py
├── aws_org_collect.py
├── aws_resource_collect.py
├── static/
│   └── app.css
├── audit_results/
│   ├── success/
│   └── fails/
├── templates/
│   ├── base.html
│   ├── search.html
│   ├── firewall_policy_lookup.html
│   ├── aws_org_topology.html
│   ├── wiz_policy_check.html
│   ├── automation_results.html
│   ├── audit_reporting.html
│   ├── information_links.html
│   └── about.html
└── README.md
```

## Running

Use the same command/options as the previous package, for example:

```powershell
python app.py
```

or with the existing options:

```powershell
python app.py --db infra_intel.db --firewall-data parsed --aws-data aws_parsed --org-file org_topology.json --port 8080
```

The app still does **not** ingest source JSON. Run `ingest.py` when source data changes, exactly as before.

## Notes

The new UI intentionally uses native HTML `<details>` elements for expandable sections, so no JavaScript is required.

## Wiz Developer Console test data

The Wiz Policy Check page can be tested before a Wiz service account exists. Create a `wiz_data` directory beside `app.py` and save raw GraphQL Developer Console responses containing `issuesV2.nodes` as JSON files, for example:

```text
wiz_data/
  issues_page_001.json
  issues_page_002.json
  issues_page_003.json
```

A single `wiz_data/issues.json` is also supported. The app accepts the raw GraphQL response wrapper (`{"data":{"issuesV2":{"nodes":[...]}}}`) directly and merges/deduplicates multiple pages by issue ID.

Use this query in the Wiz Developer Console:

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

Save the complete JSON response as `wiz_data/issues_page_001.json`. If `pageInfo.hasNextPage` is `true`, run the same query again with the returned cursor:

```graphql
query {
  issuesV2(
    first: 100
    after: "PASTE_THE_PREVIOUS_ENDCURSOR_HERE"
  ) {
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

Save each response with the next page number until `hasNextPage` is `false`.

For AWS Security Group findings, the parser uses `entitySnapshot.nativeType == "securityGroup"`, `externalId` as the exact SG ID, and `providerId` as the AWS ARN. AWS account/OU/owner context is resolved from `org_topology.json` when the account ID can be derived from the ARN.

## JSON exports

Search result pages provide an **Export Results as JSON** button. The export is generated server-side from the structured Python result data, not from rendered HTML. Current exports are available for Search & Investigate, Firewall Policy Lookup, Palo Alto Object Search, and Wiz Policy Check.


## Wiz Developer Console test data

Save raw `issuesV2` GraphQL responses under `wiz_data/`, for example `issues_page_001.json` through `issues_page_010.json`. Run the normal ingest command; Wiz issues, policies, and Security Group relationships are now stored in SQLite. `entitySnapshot.nativeType=securityGroup` is correlated using `entitySnapshot.externalId` as the exact SG ID and `providerId` as the AWS ARN. Account/OU context is resolved from `org_topology.json`.

Normal ingest:

```powershell
python ingest.py
```

Optional explicit paths:

```powershell
python ingest.py --firewall-data parsed --aws-data aws_parsed --wiz-data wiz_data --org-file org_topology.json --db infra_intel.db
```

The ingest output reports Wiz files/issues, unique policies, and unique Security Groups.


## Audit / Reporting

The **Audit / Reporting** page is a server-rendered dashboard for long-running audit/reporting jobs. It follows the same general pattern as Automation Results, but the JSON event is treated as metadata plus a pointer to the actual generated report.

The local application expects a small event/cache directory:

```text
audit_results/
├── success/
│   ├── aws_vpc_audit.json
│   └── security_group_audit.json
└── fails/
    └── aws_vpc_audit.json
```

In the long-term AWS design, these folders correspond to the success/failure event prefixes in the existing event S3 bucket. The actual generated audit files should be stored in a **separate audit-results S3 bucket**, organized by report/audit name:

```text
<event-bucket>/
└── audit-results-events/
    ├── success/
    └── fails/

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

The local app does not itself ingest or execute the audit. A separate S3 sync/collector process can place the event JSON into `audit_results/success` or `audit_results/fails`.

### Audit event JSON format

The important fields are:

```json
{
  "Name": "AWS VPC Audit",
  "Status": "SUCCESS",
  "Lastrun": "2026-10-05T09:00:00Z",
  "File": "https://<presigned-or-accessible-url>/aws-vpc-audit-20261005-090000.xlsx",
  "File_Name": "aws-vpc-audit-20261005-090000.xlsx",
  "Description": "AWS VPC configuration audit across all accounts",
  "Run_Again": "/audit/run?name=aws-vpc-audit",
  "Accounts": 431,
  "Regions": 5
}
```

`File` is the report link shown by the UI. For a private S3 object, the recommended value is a fresh HTTPS presigned URL generated by the event/report service rather than a permanent S3 URL. The UI also accepts an `s3://bucket/key` value and will display it as a reference without pretending it is directly browser-accessible.

`Run_Again` is optional. When present, it must be a local application path beginning with `/`; the UI displays a **Run Again** button. The application deliberately does not execute arbitrary shell commands from JSON. A real audit runner can expose a dedicated Flask route or be connected later to the Step Functions/automation API.

The page displays only the **latest event per report name**. This keeps the dashboard focused on the current audit/reporting state while allowing the underlying S3 event history to remain retained independently.

### Running with a custom audit event directory

By default the app reads:

```text
./audit_results/
```

A different local sync/cache location can be supplied with:

```powershell
python app.py --audit-results C:\path\to\audit_results
```

The existing options remain supported:

```powershell
python app.py --db infra_intel.db --firewall-data parsed --aws-data aws_parsed --org-file org_topology.json --audit-results audit_results --port 8080
```

The page also exposes `/api/audit/results` for future integrations. Use `?status=success` or `?status=failed` to filter the event set.

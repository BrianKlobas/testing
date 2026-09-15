# Infrastructure Intelligence Local v6 — Server-Rendered UI

This package is based directly on the working `infra_intel_local_v5` package.

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
├── templates/
│   ├── base.html
│   ├── search.html
│   ├── firewall_policy_lookup.html
│   ├── aws_org_topology.html
│   ├── wiz_policy_check.html
│   ├── automation_results.html
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

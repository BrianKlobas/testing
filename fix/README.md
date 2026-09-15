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

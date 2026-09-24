# Infrastructure Intelligence Architecture

## High-level architecture

```mermaid
flowchart LR
    A[AWS APIs] --> C[aws_resource_collect.py]
    B[AWS Organizations] --> D[aws_org_collect.py]
    P[Palo Alto / Panorama exports] --> J[Parsed JSON]
    W[Wiz GraphQL] --> K[wiz_data JSON]

    C --> F[JSON source data]
    D --> F
    J --> F
    K --> F

    F --> I[ingest.py]
    I --> DB[(SQLite infra_intel.db)]

    DB --> APP[Flask app.py]
    APP --> T[Jinja templates]
    T --> UI[Server-rendered HTML/CSS UI]

    AR[automation_results/*.json] --> APP

    UI --> S[Search & Investigate]
    UI --> FP[Firewall Policy Lookup]
    UI --> PO[Palo Alto Object Search]
    UI --> WZ[Wiz Policy Check]
    UI --> ORG[AWS Org Topology]
    UI --> AU[Automation Results]

    S --> E[JSON export]
    FP --> E
    PO --> E
    WZ --> E
```

## Layering

```text
+--------------------------------------------------------------+
| Presentation                                                 |
| Flask routes + Jinja templates + CSS                         |
+--------------------------------------------------------------+
| Search / correlation                                         |
| app.py                                                       |
+--------------------------------------------------------------+
| Data access / indexing                                       |
| database.py + SQLite                                         |
+--------------------------------------------------------------+
| Ingestion                                                    |
| ingest.py                                                    |
+--------------------------------------------------------------+
| Collection / source preparation                               |
| AWS collectors + Panorama/Palo parsing + Wiz exports         |
+--------------------------------------------------------------+
```

The important boundary is that `app.py` should not need to make a fresh AWS/Panorama/Wiz API call for every interactive search. Collection and ingestion prepare a searchable local model first.

# Future Automation Platform Architecture

```mermaid
flowchart LR
    subgraph Automations
      A1[Python Automation A]
      A2[Python Automation B]
      A3[Python Automation C]
    end

    A1 --> C[Completion JSON]
    A2 --> C
    A3 --> C

    C --> S3[(S3 automation-results)]
    S3 --> H[History / Status index]
    H --> UI[Infrastructure Intelligence Platform]
    UI --> V[View latest result]
    UI --> R[Re-trigger / Re-run]
    R --> O[Orchestrator]
    O --> A1
    O --> A2
    O --> A3

    A1 -. detailed artifacts .-> AR[(S3 artifacts)]
    A2 -. detailed artifacts .-> AR
    A3 -. detailed artifacts .-> AR
    UI -. artifact references .-> AR
```

## Separation of concerns

```text
+-----------------------+      +----------------------+      +--------------------+
| Python automation     | ---> | Completion contract  | ---> | Platform           |
|                       |      |                      |      |                    |
| AWS/Wiz/Palo/etc.     |      | JSON result          |      | status             |
| business logic        |      | standard fields      |      | history            |
| API calls             |      | extension fields    |      | UI                 |
| calculations          |      | run metadata         |      | re-run             |
+-----------------------+      +----------------------+      +--------------------+
```

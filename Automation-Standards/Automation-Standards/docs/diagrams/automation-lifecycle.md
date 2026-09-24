# Automation Lifecycle

```mermaid
flowchart TD
    A[Python automation starts] --> B[Create RunId]
    B --> C[Record Started timestamp]
    C --> D[Perform automation work]
    D --> E{Terminal result}
    E -->|Success| F[Status = Success]
    E -->|Partial| G[Status = Partial]
    E -->|Failure| H[Status = Failed]
    F --> I[Record Completed + Duration]
    G --> I
    H --> I
    I --> J[Write completion JSON]
    J --> K[Current local: automation_results/]
    J --> L[Future: S3 results bucket]
    L --> M[Platform history/status]
    M --> N{Future user action}
    N -->|View| O[Display result]
    N -->|Re-run| P[Platform starts a new Python run]
    P --> B
```

## Contract boundary

```text
                 Python automation
                        |
                        | implementation-specific
                        v
                 +--------------+
                 | automation   |
                 | business     |
                 | logic        |
                 +--------------+
                        |
                        | standardized
                        v
              +----------------------+
              | completion JSON      |
              | Name                 |
              | Status               |
              | Lastrun              |
              | RunId                |
              | Started / Completed  |
              | Duration             |
              | additional fields   |
              +----------------------+
                        |
          +-------------+-------------+
          |                           |
          v                           v
   Local filesystem                 S3
   today                            future
```

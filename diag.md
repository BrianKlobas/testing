# Security Inventory / Orchestration Platform Architecture

## Overview

This platform collects infrastructure, security, and operational metadata from multiple enterprise sources, normalizes the information, correlates relationships, and exposes a unified inventory through APIs and a GUI.

The design principle:

> Collect independently. Normalize centrally. Correlate everything. Serve quickly.

---

# High Level Architecture

```
                         Users
                           |
                           |
                    Web GUI / Dashboard
                           |
                           |
                      REST API Layer
                           |
                           |
                 Aurora PostgreSQL Database
                           |
                           |
             Correlation & Inventory Engine
                           |
                           |
                     S3 Data Lake
                           |
                           |
                  Collector Orchestration
                           |
                           |
                  Step Functions Workflow
                           |
                           |
        ------------------------------------------------
        |              |              |                |
        |              |              |                |
       AWS           Azure        Enterprise       Security
```

---

# Collection Triggers

The collection platform can be started from multiple sources.

```
+----------------+
| EventBridge    |
| Scheduled Run  |
+----------------+

        |

+----------------+
| Manual Run     |
| GUI Button     |
+----------------+

        |

+----------------+
| REST API       |
| Automation     |
+----------------+

        |

        v

+--------------------------------+
| Step Functions Orchestrator    |
+--------------------------------+
```

---

# Step Functions Orchestration

The workflow controls collection execution.

Capabilities:

- Scheduled execution
- Manual execution
- API triggered execution
- Approval gates
- Parallel collection
- Retry handling
- Failure isolation
- Result aggregation
- Notifications

Example workflow:

```
START

 |

 v

Approval Required?

       /          \

     YES           NO

      |             |

Manual Approval   Continue


        \         /

          v

     Parallel Map

          |

  ----------------------

  |        |        |

 AWS     Azure    Enterprise

  |        |        |

  ----------------------

          |

          v

    Aggregate Results

          |

          v

       COMPLETE
```

---

# Collector Lambda Architecture

Each integration is independent.

One Lambda = One responsibility.

```
Collector Lambda Examples:

AWS
---
aws-ec2-collector
aws-vpc-collector
aws-subnet-collector
aws-security-group-collector
aws-eni-collector
aws-route-table-collector
aws-iam-collector


Azure
-----
azure-vm-collector
azure-vnet-collector
azure-nsg-collector
azure-network-interface-collector


Enterprise
----------
servicenow-ci-collector
servicenow-service-collector
infoblox-dns-collector
infoblox-network-collector
palo-policy-collector
palo-address-object-collector


Security
--------
wiz-collector
algosec-collector
crowdstrike-collector
microsoft-defender-collector
```

---

# Raw Data Lake (S3)

Every collector stores the native API response.

Example structure:

```
s3://inventory-data/

raw/

    aws/

        ec2/

        vpc/

        subnet/


    azure/

        vm/

        vnet/


    servicenow/

        ci/


    palo/

        policies/


    wiz/

        findings/
```

---

# Native JSONB Examples

## AWS EC2 Raw Collection

Source:

AWS API Response

```json
{
  "InstanceId":"i-012345",

  "VpcId":"vpc-12345",

  "SubnetId":"subnet-456",

  "PrivateIpAddress":"10.0.1.25",

  "SecurityGroups":[
    {
      "GroupId":"sg-111"
    }
  ],

  "Tags":[
    {
      "Key":"Name",
      "Value":"WEB01"
    }
  ]
}
```

---

## ServiceNow Raw Collection

```json
{
 "sys_id":"8d2312",

 "name":"WEB01",

 "owned_by":"Payments",

 "assignment_group":"Cloud Ops",

 "business_service":"Checkout"
}
```

---

## Palo Alto Raw Collection

```json
{
 "rule":"Allow HTTPS",

 "source":"10.0.1.25",

 "destination":"Any",

 "service":"tcp-443",

 "action":"allow"
}
```

---

# Correlation & Inventory Engine

The correlation layer converts vendor-specific data into a common model.

Responsibilities:

```
Read Native JSON

        |

        v

Normalize Fields

        |

        v

Deduplicate Resources

        |

        v

Resolve Relationships

        |

        v

Create Generic Objects

        |

        v

Store in Database

        |

        v

Generate Reports
```

---

# Generic Asset Model

## Server Asset

```json
{
 "assetId":"asset-001",

 "type":"server",

 "hostname":"WEB01",

 "ip":"10.0.1.25",

 "cloud":"aws",

 "providerId":"i-012345",

 "owner":"Payments",

 "businessService":"Checkout",

 "sources":[
    "aws",
    "servicenow"
 ]
}
```

---

## Network Asset

```json
{
 "networkId":"network-100",

 "type":"subnet",

 "cloud":"aws",

 "vpc":"vpc-12345",

 "subnet":"subnet-456",

 "cidr":"10.0.1.0/24"
}
```

---

# Aurora PostgreSQL Storage

Aurora stores both:

1. Normalized searchable objects.
2. Original JSON payloads.

Example:

```
Aurora

Tables:

Assets

Networks

DNS Records

Security Groups

Firewall Rules

Relationships

Applications

Owners


JSONB:

raw_payload

normalized_payload

metadata
```

---

# Example Database Model

## Assets Table

```
asset_id

hostname

ip_address

cloud

provider_id

owner

business_service

raw_jsonb

normalized_jsonb

last_seen
```

---

# API Layer

The GUI never talks directly to the database.

Example:

```
GET

/api/search?q=10.0.1.25
```

Response:

```json
{
 "asset":"WEB01",

 "cloud":"AWS",

 "network":"vpc-12345",

 "securityGroups":[
    "sg-111"
 ],

 "dns":[
    "web01.company.com"
 ],

 "cmdb":"CI12345",

 "firewallRules":[
    "Allow HTTPS"
 ]
}
```

---

# GUI Capabilities

The frontend provides:

- Dashboard
- Automation Status
- Resource Search
- Asset Explorer
- Relationship Graph
- Cloud Inventory
- Firewall Visibility
- CMDB View
- Excel Export

---

# Example Search Flow

User searches:

```
10.0.1.25
```

The platform resolves:

```
IP Address

 |

 v

EC2 Instance

 |

 v

ENI

 |

 v

Security Groups

 |

 v

Subnet

 |

 v

VPC

 |

 v

DNS Record

 |

 v

ServiceNow CI

 |

 v

Firewall Rules

 |

 v

Business Service

 |

 v

Owner
```

---

# Future Integrations

The architecture supports adding:

- Kubernetes
- EKS
- AKS
- RDS
- Lambda
- Load Balancers
- Transit Gateway
- VPN
- Certificates
- IAM Roles
- Secrets Management
- Containers
- SaaS Applications

---

# Design Principles

## Decoupled Collection

Collectors never depend on each other.

---

## Immutable History

S3 preserves every collection snapshot.

---

## Vendor Neutral

All systems map into a generic asset model.

---

## Relationship First

The value is not individual records.

The value is understanding:

> What connects to what, who owns it, and what security controls affect it.

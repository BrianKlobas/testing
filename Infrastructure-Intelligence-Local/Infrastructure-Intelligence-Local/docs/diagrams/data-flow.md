# Data Flow Examples

## IP / CIDR investigation

```text
User enters IP/CIDR
       |
       v
Flask route in app.py
       |
       +--> AWS indexed lookup
       |      |
       |      +--> direct IP/resource match
       |      +--> ENI / EC2 / SG relationships
       |      +--> subnet/VPC containment
       |      +--> Route53 matches
       |
       +--> Palo indexed lookup
              |
              +--> containing address objects
              +--> containing address groups
              +--> referenced rules
              +--> network containment

       |
       v
Merge + normalize results
       |
       v
Collapsible investigation page
       |
       +--> JSON export
```

## Wiz Security Group correlation

```text
Wiz issue
  |
  +--> entitySnapshot.nativeType == securityGroup
  |
  +--> entitySnapshot.externalId == AWS SG ID
  |
  +--> entitySnapshot.providerId == AWS ARN
                    |
                    v
             SQLite AWS inventory
                    |
                    v
         AWS Security Group record
                    |
          +---------+---------+
          |         |         |
        tags     inbound   outbound
          |       rules      rules
          +---------+---------+
                    |
                    v
             Wiz Policy Check
```

## Automation result flow

```text
Python automation
       |
       | completes run
       v
completion JSON
       |
       v
automation_results/
       |
       v
Automation Results page
       |
       +--> Name
       +--> Status
       +--> Lastrun
       +--> arbitrary additional fields
```

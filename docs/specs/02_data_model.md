# Data Model

## compliance-reports table

Partition key: document_id (String)
Sort key: timestamp (String, ISO 8601)

| Field | Type | Description |
|-------|------|-------------|
| document_id | String | Unique document identifier |
| timestamp | String | Submission time ISO 8601 |
| overall_status | String | compliant, non_compliant, or requires_review |
| frameworks | List | Framework names checked |
| violation_count | Number | Total deduplicated violations |
| summary | String | 2-3 sentence compliance summary |
| reviewer_notes | String | Ambiguities requiring human review |
| model_version | String | Engine version that produced this result |
| audit_hash | String | SHA-256 over key report fields |
| ttl | Number | Unix timestamp for expiry 3653 days |

## compliance-violations table

Partition key: violation_id (String)
Sort key: document_id (String)

| Field | Type | Description |
|-------|------|-------------|
| violation_id | String | Format: document_id-V0001 |
| document_id | String | Parent document identifier |
| framework | String | SEC, FINRA, Dodd_Frank, SOX, or BSA_AML |
| rule_reference | String | Specific rule e.g. Rule 10b-5 |
| description | String | Plain language violation description |
| severity | String | critical, high, medium, or low |
| evidence | String | Quoted document text max 500 chars |
| remediation_steps | List | Three concrete remediation actions |
| sla_deadline | String | ISO 8601 anchored to submitted_at |
| auto_escalated | Boolean | True if SNS escalation was triggered |
| ttl | Number | Unix timestamp for expiry 3653 days |

## SeverityIndex GSI

Index name: SeverityIndex
Partition key: severity (String)
Sort key: sla_deadline (String)

Used by sla_checker.py for hourly breach detection queries.

# Result Schemas

## ComplianceReport fields

document_id:        str
document_type:      str
overall_status:     str   compliant or non_compliant or requires_review
frameworks_checked: list of str
violations:         list of Violation
compliance_summary: str
reviewer_notes:     str
processing_time_ms: float
model_version:      str
timestamp:          str   ISO 8601 anchored to submitted_at
audit_hash:         str   SHA-256 hex digest 64 characters

## Violation fields

violation_id:       str   format document_id-V0001
document_id:        str
framework:          str   SEC or FINRA or Dodd_Frank or SOX or BSA_AML
rule_reference:     str   e.g. Rule 10b-5
description:        str
severity:           str   critical or high or medium or low
evidence:           str   max 500 characters
remediation_steps:  list of str
sla_deadline:       str   ISO 8601
auto_escalated:     bool

## SNS escalation message fields

document_id, document_type, critical_violations list with framework and rule
and description per violation, sla_deadline of first critical violation

## SNS requires_review message fields

document_id, document_type, submitted_by, submitted_at, reviewer_notes, audit_hash

## CloudWatch metrics published

Namespace: Compliance
Metrics: CriticalViolations, TotalViolations, ViolationsByFramework, SLABreaches

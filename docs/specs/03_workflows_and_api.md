# Workflows and API

## Document submission flow

1. Upload document to S3 under documents/ prefix
2. Send SQS message to compliance-docs queue
3. Lambda validates message, fetches S3 object, calls analyse_document()
4. Violations written to compliance-violations table
5. Report written to compliance-reports table
6. Critical violations published to compliance-escalations-sns
7. requires_review documents published to compliance-review-sns
8. CloudWatch metrics published

## SQS message fields

Required: document_id, bucket, key

Optional: document_type (default: regulatory_filing), frameworks (default: all five),
submitted_by (max 256 chars), source_system (max 256 chars)

Valid document_type values:
trade_confirmation, customer_communication, risk_report, audit_document,
policy_document, regulatory_filing, sar_suspicious_activity

Valid frameworks values:
SEC, FINRA, Dodd_Frank, SOX, BSA_AML

## Lambda response

Returns batchItemFailures list. Failed records are retried by SQS up to
max_receive_count (3). After 3 failures the message moves to the DLQ.

## SLA checker flow

EventBridge fires every hour. sla_checker queries SeverityIndex GSI for
violations where sla_deadline is before now and auto_escalated is false.
One SNS notification published per breached violation.
SLABreaches metric emitted to CloudWatch.

## Reprocess CLI

python3 -m src.reprocess --dry-run
python3 -m src.reprocess --status requires_review --older-than-minutes 60 --queue-url URL

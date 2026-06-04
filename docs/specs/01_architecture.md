# Architecture

## Component Map

SQS (compliance-docs) receives a JSON message pointing to a document in S3.
Lambda (compliance-engine) is triggered per message (batch_size=1).
Lambda fetches the S3 object, chunks it, sends each chunk to Claude, deduplicates
violations across chunks, then writes violations and report to DynamoDB.
Critical violations publish to SNS (compliance-escalations-sns).
requires_review documents publish to SNS (compliance-review-sns).
CloudWatch receives CriticalViolations, TotalViolations, ViolationsByFramework metrics.
EventBridge triggers the SLA checker Lambda every hour.

## Data Flow

1. Producer uploads document to S3 under documents/ prefix
2. Producer sends SQS message: {document_id, bucket, key, document_type, frameworks}
3. Lambda validates message, fetches S3 content, calls analyse_document()
4. Violations written to DynamoDB compliance-violations table (write-first)
5. Report written to DynamoDB compliance-reports table (idempotency guard)
6. Critical violations published to escalation SNS topic
7. requires_review documents published to review SNS topic
8. CloudWatch metrics published in finally block regardless of escalation outcome
9. SLA checker Lambda queries SeverityIndex GSI hourly for breached deadlines

## Key Design Decisions

Write ordering: violations persisted before the report. If DynamoDB throttles
mid-violation, the report is never written and SQS retries correctly. No
orphaned report with incomplete violation set is possible.

Idempotency: attribute_not_exists(document_id) ConditionExpression on both
tables. SQS at-least-once delivery cannot produce duplicate records.

Metrics in finally: _publish_metrics() runs after the escalation try/except
in a finally-equivalent position. CloudWatch always receives a data point
even when SNS escalation fails.

Lazy Anthropic client: the anthropic_client property defers Secrets Manager
lookup to first use. Lambda cold start time is not affected by SM latency.

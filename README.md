# Regulatory Compliance Engine

Automated multi-framework regulatory compliance analysis for US financial
institutions. Submit a document. Get back every SEC, FINRA, Dodd-Frank, SOX,
and BSA/AML violation flagged, ranked by severity, SLA-clocked, and escalated
before a human touches it.

![CI](https://github.com/Zi-Stonga/Regulatory-Compliance/actions/workflows/ci.yml/badge.svg)

---

## The problem this solves

Compliance teams at financial institutions review hundreds to thousands of
documents per week. Customer communications, trade confirmations, risk reports,
10-K filings. Each needs simultaneous analysis against five overlapping US
regulatory frameworks. Manual review runs $200-400 per document. Reviewers
miss 8-12% of violations due to volume and fatigue.

This engine sends every document through Claude the moment it arrives. You get
back a structured report: which rule was violated, the exact sentence from the
document that triggered it, three concrete remediation steps, and an SLA
deadline. Critical findings hit SNS within seconds.

At 20,000 documents per month the all-in cost is approximately $394, or $0.02
per document. The same volume reviewed manually costs $4,000,000 per month.

---

## Frameworks

| Framework | Key rules |
|-----------|-----------|
| SEC | Rule 10b-5, Reg FD, Rule 15c3-1, Rule 17a-4 |
| FINRA | Rule 2111, Rule 2210, Rule 4512, Rule 3310 |
| Dodd-Frank | Section 619 Volcker, Title VII, Section 1031 UDAAP |
| SOX | Section 302, Section 404, Section 802 |
| BSA/AML | 31 CFR 1020, 31 CFR 1010.520, OFAC screening |

---

## Severity and SLA

| Level | SLA | Automatic action |
|-------|-----|-----------------|
| Critical | 4 hours | SNS escalation + CloudWatch alarm |
| High | 24 hours | SNS notification |
| Medium | 72 hours | Logged |
| Low | 7 days | Logged |

SLA deadlines are anchored to document submission time, not processing
completion time.

---

## How it works

SQS receives a message pointing to a document in S3. Lambda fetches the
document, splits it into 15,000-character chunks with 500-character overlap
so no context is lost at boundaries, and sends each chunk to Claude for
simultaneous analysis against all five frameworks. Violations are deduplicated
across chunks by framework and rule reference composite key. SLA deadlines are
set from submission time. Everything is written to DynamoDB with a SHA-256
audit hash. Violations are persisted before the report. If DynamoDB throttles
mid-write, nothing is orphaned and SQS retries correctly.

---

## Project structure

```
src/
  compliance_engine.py      Main engine and Lambda handler
  sla_checker.py            Hourly SLA breach detector (EventBridge)
  reprocess.py              CLI to re-queue failed documents
  __init__.py               Package exports and version

tests/
  test_compliance_engine.py 110 tests (Arrange/Act/Assert throughout)

infra/
  cdk_stack.py              Full AWS CDK stack
  app.py                    CDK entry point
  cdk.json                  CDK context and feature flags
  requirements-cdk.txt

configs/
  config.yaml               Engine configuration

docs/specs/
  00_system_overview.md     What this system does and code conventions
  01_architecture.md        Components and data flow
  02_data_model.md          DynamoDB schemas
  03_workflows_and_api.md   SQS message schema and core flows
  04_implementation_plan.md Build phases and status
  05_local_development.md   How to run and test locally
  06_result_schemas.md      Report and violation output schemas
  07_cloud_deployment.md    Infrastructure and deployment

Dockerfile                  Lambda container image
Makefile                    make test | lint | security | coverage | deploy
requirements.txt            All dependencies (pinned exact versions)
requirements-runtime.txt    Runtime-only deps for Lambda image
setup.py
pytest.ini
.env.example
```

---

## Prerequisites

- Python 3.12 or 3.13
- AWS CLI configured with appropriate permissions
- AWS CDK v2: `npm install -g aws-cdk`
- Node.js 18+
- An Anthropic API key

Verify:

```bash
python3 --version
aws --version
cdk --version
node --version
```

---

## Local setup

```bash
git clone https://github.com/Zi-Stonga/Regulatory-Compliance.git
cd Regulatory-Compliance

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
```

Edit `.env` and set `ANTHROPIC_API_KEY`. All other values default correctly
for local testing with moto mocks.

---

## Running the test suite

No AWS credentials or real API key needed. All AWS calls use moto mocks.

```bash
make test
```

Expected output: 110 passed.

Run with coverage:

```bash
make coverage
```

Lint and security scan:

```bash
make lint
make security
```

All checks together:

```bash
make all
```

---

## SQS message schema

| Field | Required | Constraints |
|-------|----------|-------------|
| `document_id` | Yes | Max 200 chars. ASCII letters, digits, `-_.:@`. No `..`. |
| `bucket` | Yes | S3 bucket name. String. |
| `key` | Yes | S3 key. No `..`. Must not start with `/`. |
| `document_type` | No | Defaults to `regulatory_filing`. See valid values. |
| `frameworks` | No | Defaults to all five. Non-empty list. |
| `submitted_by` | No | Max 256 chars. Stored in audit trail. |
| `source_system` | No | Max 256 chars. Stored in audit trail. |

Valid `document_type` values:

```
trade_confirmation  customer_communication  risk_report  audit_document
policy_document  regulatory_filing  sar_suspicious_activity
```

Valid `frameworks` values:

```
SEC  FINRA  Dodd_Frank  SOX  BSA_AML
```

Example message:

```json
{
  "document_id": "DOC-2026-001",
  "bucket": "regulatory-compliance-123456789012",
  "key": "documents/DOC-2026-001.txt",
  "document_type": "customer_communication",
  "frameworks": ["SEC", "FINRA"],
  "submitted_by": "analyst_01",
  "source_system": "email_gateway"
}
```

---

## Deploying to AWS

### Step 1: Store the Anthropic API key

The secret must exist before CDK deploys.

```bash
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export AWS_DEFAULT_REGION=us-east-1

aws secretsmanager create-secret \
  --name compliance/anthropic-api-key \
  --secret-string "{\"ANTHROPIC_API_KEY\":\"$ANTHROPIC_API_KEY\"}"
```

### Step 2: Bootstrap CDK (first time only)

```bash
cd infra
pip install -r requirements-cdk.txt
cdk bootstrap aws://$AWS_ACCOUNT_ID/$AWS_DEFAULT_REGION
```

### Step 3: Deploy

```bash
cdk deploy RegulatoryComplianceStack
```

Deployment takes approximately 10 minutes. Stack outputs:

| Output | Description |
|--------|-------------|
| `DocumentQueueUrl` | SQS queue, send document messages here |
| `BucketName` | S3 bucket, upload documents here |
| `EscalationTopicArn` | SNS topic, subscribe your ops team |
| `ReviewTopicArn` | SNS topic, subscribe your compliance analysts |

### Step 4: Subscribe your team to notifications

```bash
ESCALATION_TOPIC=$(aws cloudformation describe-stacks \
  --stack-name RegulatoryComplianceStack \
  --query "Stacks[0].Outputs[?OutputKey=='EscalationTopicArn'].OutputValue" \
  --output text)

aws sns subscribe \
  --topic-arn $ESCALATION_TOPIC \
  --protocol email \
  --notification-endpoint ops@yourcompany.com
```

### Step 5: Submit a document

```bash
BUCKET=$(aws cloudformation describe-stacks --stack-name RegulatoryComplianceStack \
  --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)

QUEUE=$(aws cloudformation describe-stacks --stack-name RegulatoryComplianceStack \
  --query "Stacks[0].Outputs[?OutputKey=='DocumentQueueUrl'].OutputValue" --output text)

aws s3 cp my_document.txt s3://$BUCKET/documents/DOC-001.txt

aws sqs send-message --queue-url $QUEUE \
  --message-body '{
    "document_id":   "DOC-001",
    "bucket":        "'"$BUCKET"'",
    "key":           "documents/DOC-001.txt",
    "document_type": "customer_communication",
    "frameworks":    ["SEC", "FINRA"],
    "submitted_by":  "analyst_01"
  }'
```

### Step 6: Check results

```bash
aws dynamodb scan \
  --table-name compliance-reports \
  --filter-expression "document_id = :id" \
  --expression-attribute-values '{":id":{"S":"DOC-001"}}'
```

---

## Re-processing failed documents

After an incident such as API key misconfiguration or SDK incompatibility,
use the reprocess utility to re-queue affected documents:

```bash
python3 -m src.reprocess --dry-run

python3 -m src.reprocess \
  --status requires_review \
  --older-than-minutes 60 \
  --queue-url $QUEUE
```

---

## Infrastructure

The CDK stack provisions:

**Compute and messaging**: Lambda (Python 3.12, 1 GB, 300s), SQS with DLQ
(3-retry policy, 14-day DLQ retention), batch_size=1.

**Storage**: S3 with Object Lock COMPLIANCE mode and 3,653-day default
retention (every upload is WORM-protected automatically). DynamoDB
PAY_PER_REQUEST with PITR enabled. 3,653-day TTL on all records.

**Security**: KMS CMK with annual rotation encrypts everything. Lambda in
private VPC subnet, no inbound rules, HTTPS/443 egress only. VPC Flow Logs
capture all traffic and are retained 10 years.

**Alerting**: CriticalViolations alarm (2 evaluation periods, 1 datapoint to
alarm). DLQ depth alarm. DynamoDB write storm alarm. SLA breach detector runs
hourly via EventBridge.

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Dev only | Local development. Production uses Secrets Manager. |
| `AWS_DEFAULT_REGION` | Yes | AWS region. Lambda sets this automatically. |
| `REPORTS_TABLE` | Yes | DynamoDB reports table name. Set by CDK. |
| `VIOLATIONS_TABLE` | Yes | DynamoDB violations table name. Set by CDK. |
| `DOCS_BUCKET` | Yes | S3 bucket name. Set by CDK. |
| `ESCALATION_TOPIC_ARN` | Yes | SNS ARN for critical violations. Set by CDK. |
| `REVIEW_TOPIC_ARN` | No | SNS ARN for requires_review documents. Set by CDK. |
| `DOCUMENT_QUEUE_URL` | Reprocess only | SQS URL for the reprocess CLI. |

---

## CI/CD

GitHub Actions runs on every push and pull request:

```
lint       ruff check src/ tests/
security   bandit -r src/ -ll
test       pytest tests/ -v --cov=src
```

Runs on Python 3.12 and 3.13 in parallel. No real AWS credentials in CI.
All AWS calls use moto mocks.

Run the same checks locally:

```bash
make all
```

---

## Operational runbooks

### A document received requires_review status

```bash
# Check for authentication errors
aws logs filter-log-events \
  --log-group-name /compliance/lambda \
  --filter-pattern "AuthenticationError"

# Check the DLQ
aws sqs get-queue-attributes \
  --queue-url https://sqs.REGION.amazonaws.com/ACCOUNT/compliance-docs-dlq \
  --attribute-names ApproximateNumberOfMessages

# Re-queue once root cause is fixed
python3 -m src.reprocess --status requires_review --dry-run
python3 -m src.reprocess --status requires_review --queue-url $QUEUE
```

### The DLQ alarm fired

```bash
# Inspect the failed message
aws sqs receive-message \
  --queue-url https://sqs.REGION.amazonaws.com/ACCOUNT/compliance-docs-dlq \
  --max-number-of-messages 1

# Redrive after fixing root cause
aws sqs start-message-move-task \
  --source-arn arn:aws:sqs:REGION:ACCOUNT:compliance-docs-dlq \
  --destination-arn arn:aws:sqs:REGION:ACCOUNT:compliance-docs
```

---

## Teardown

```bash
cd infra && cdk destroy RegulatoryComplianceStack
```

DynamoDB tables and S3 bucket have `RemovalPolicy.RETAIN` and survive stack
teardown. The S3 bucket is in Object Lock COMPLIANCE mode. Objects cannot be
deleted until their 3,653-day retention expires. Use a separate bucket for
integration testing.

---

## Version history

| Version | Summary |
|---------|---------|
| v2.0.0 | Full rebuild incorporating AI project standards. Pure helper functions, Arrange/Act/Assert tests, docs/specs bootstrapped, SCREAMING_SNAKE_CASE constants, explicit error handling throughout. |
| v1.4.0 | Structured logging, API key TTL refresh, requires_review routing, SLA checker, reprocess CLI, CloudWatch dashboard. |
| v1.3.0 | 30 issues fixed. Write ordering, SDK incompatibility, auth error surfacing, logging no-op, parallel chunks reverted for Windows. |
| v1.2.0 | 28 issues fixed. Phantom CloudWatch alarm, Object Lock retention, idempotency guard. |
| v1.1.0 | 20 issues fixed. Silent escalation drop, audit hash strengthened, Dockerfile CMD, dead dependencies. |
| v1.0.0 | Initial release. |

---

## Audit history

Three independent audit passes were conducted before v1.0.0 reached
production data. 78 issues were resolved.

| Pass | Version | Issues | Most critical finding |
|------|---------|--------|-----------------------|
| 1 | v1.1.0 | 20 | Silent escalation drop: critical violations never reached SNS |
| 2 | v1.2.0 | 28 | Phantom CloudWatch alarm: never fired despite appearing configured |
| 3 | v1.3.0 | 30 | SDK incompatibility: every document silently received requires_review |

---

## Contributing

```bash
git clone https://github.com/Zi-Stonga/Regulatory-Compliance.git
cd Regulatory-Compliance
git checkout -b feature/your-feature

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

make all
```

Pull requests must:
- Pass all 110 existing tests
- Add tests for new functionality (Arrange/Act/Assert, one assertion focus)
- Pass ruff lint and bandit security scan
- Not reduce test coverage below current level

---

## Licence

MIT
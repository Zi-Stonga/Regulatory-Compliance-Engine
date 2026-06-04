# System Overview

## What This System Does

The Regulatory Compliance Engine analyses financial documents against five US
regulatory frameworks simultaneously using the Claude language model. Documents
arrive via Amazon SQS, are fetched from S3, analysed per framework, and results
are written to DynamoDB. Critical violations escalate immediately via SNS.

## Why It Exists

Manual compliance review costs $200-400 per document and misses 8-12 percent
of violations due to analyst fatigue. This engine reduces per-document cost
to approximately $0.02 while providing consistent, auditable analysis across
SEC, FINRA, Dodd-Frank, SOX, and BSA/AML simultaneously.

## Frameworks Covered

- SEC: Rule 10b-5, Reg FD, Rule 15c3-1, Rule 17a-4
- FINRA: Rule 2111, Rule 2210, Rule 4512, Rule 3310
- Dodd-Frank: Section 619 Volcker, Title VII, Section 1031 UDAAP
- SOX: Section 302, Section 404, Section 802
- BSA/AML: 31 CFR 1020, 31 CFR 1010.520, OFAC screening

## Code Conventions


### Error Handling
- Never swallow exceptions silently
- Catch only specific exception types
- All error messages state what failed, why, and what to check
- All external I/O wrapped in explicit error handling

### Logging
- Structured JSON via python-json-logger in Lambda
- Plain text fallback when library unavailable (local dev)
- DEBUG for tracing, INFO for events, WARNING for recoverable issues, ERROR for failures
- No print() statements in source files

### Testing
- Arrange / Act / Assert structure in every test
- One assertion focus per test function
- moto library mocks all AWS services; no real AWS calls in tests
- autouse clear_singletons fixture resets module globals between tests
- Test names reference the audit finding code they validate where applicable
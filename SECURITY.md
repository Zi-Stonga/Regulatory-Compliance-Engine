# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.0.0   | Yes |
| 1.x.x   | No  |

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Email security findings to the repository owner directly. Include:
- A description of the vulnerability
- Steps to reproduce
- The potential impact
- Any suggested remediation

You will receive an acknowledgement within 48 hours and a resolution
timeline within 5 business days.

## Scope

This policy covers:
- The compliance engine source code (src/)
- The CDK infrastructure definitions (infra/)
- The test suite (tests/)
- All configuration files

## Out of scope

- Third-party dependencies (report these to the upstream maintainer)
- Findings that require physical access to infrastructure
- Social engineering

## Security controls in this project

- All secrets stored in AWS Secrets Manager, never in code or config files
- KMS CMK with annual rotation encrypts all AWS services
- Lambda runs in private VPC subnet with HTTPS/443 egress only
- S3 Object Lock COMPLIANCE mode prevents record deletion or modification
- SHA-256 audit hash on every compliance report for tamper detection
- Input validation on all SQS message fields before any processing
- anthropic SDK pinned to exact version to prevent silent API compatibility failures
- bandit security scan runs in CI on every push
- IAM least privilege: violations table is write-only for the Lambda role

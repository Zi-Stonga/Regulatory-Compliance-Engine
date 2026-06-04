# Changelog

## [2.0.0] - 2026-06-03

### Changed
- Full rebuild 
- analyse_document decomposed into pure testable helper functions
- Arrange/Act/Assert structure throughout all 110 tests
- Explicit error handling on all external IO with actionable messages
- Docstrings on every function covering purpose, args, returns, exceptions

### Added
- docs/specs/ bootstrapped with all 8 required spec files
- pyrightconfig.json to suppress Anthropic SDK false-positive type warnings
- Makefile targets: install, test, coverage, lint, security, clean, all

## [1.4.0] - 2026-05-15

### Added
- Structured JSON logging via python-json-logger
- API key TTL refresh every 12 hours for Secrets Manager key rotation
- requires_review SNS routing via REVIEW_TOPIC_ARN
- Hourly SLA breach detector Lambda (src/sla_checker.py)
- Failed document re-queue CLI (src/reprocess.py)
- CloudWatch dashboard and review SNS topic in CDK stack
- GitHub Actions CI pipeline
- Makefile

### Fixed
- Input validation for submitted_by and source_system fields

## [1.3.0] - 2026-05-01

### Fixed
- V3-01: violations now written before report to prevent orphaned records
- V3-02: metrics now publish even when SNS escalation fails
- V3-06: AuthenticationError no longer swallowed by bare except
- V3-07: SLA deadlines anchored to submission time not processing time
- V3-25: anthropic SDK pinned to 0.40.0 minimum for claude-sonnet-4-6

## [1.2.0] - 2026-04-15

### Fixed
- Phantom CloudWatch alarm now monitors a published metric namespace
- S3 Object Lock default retention added
- DynamoDB idempotency guard added

## [1.1.0] - 2026-04-01

### Fixed
- Silent escalation drop caused by env var name mismatch
- Audit hash strengthened to cover full violation list

## [1.0.0] - 2026-03-15

### Added
- Initial release

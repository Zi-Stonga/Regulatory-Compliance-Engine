"""
tests/test_compliance_engine.py
Tests for src/compliance_engine.py

Structure: Arrange / Act / Assert throughout.
AWS services mocked via moto. Anthropic client injected via setter.
autouse clear_singletons fixture resets module globals between tests.
"""
from __future__ import annotations

import json
import textwrap
import time
from datetime import datetime
from datetime import timezone
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.compliance_engine import (
    CHUNK_OVERLAP,
    CHUNK_SIZE,
    DOCUMENT_ID_MAX_LEN,
    MAX_DOCUMENT_BYTES,
    MAX_EVIDENCE_CHARS,
    RETENTION_DAYS,
    SNS_SUBJECT_MAX_LEN,
    ComplianceDocument,
    ComplianceEngine,
    ComplianceReport,
    Violation,
    _build_analysis_prompt,
    _build_violation_objects,
    _chunk_document,
    _compute_audit_hash,
    _deduplicate_violations,
    _merge_chunk_statuses,
    _validate_sqs_message,
    lambda_handler,
    load_config,
)

AWS_REGION = "us-east-1"
ACCOUNT_ID = "123456789012"
REPORTS_TABLE = "compliance-reports"
VIOLATIONS_TABLE = "compliance-violations"
DOCS_BUCKET = f"regulatory-compliance-{ACCOUNT_ID}"
ESCALATION_ARN = f"arn:aws:sns:{AWS_REGION}:{ACCOUNT_ID}:compliance-escalations-sns"
REVIEW_ARN = f"arn:aws:sns:{AWS_REGION}:{ACCOUNT_ID}:compliance-review-sns"

ENV_VARS = {
    "AWS_DEFAULT_REGION": AWS_REGION,
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "REPORTS_TABLE": REPORTS_TABLE,
    "VIOLATIONS_TABLE": VIOLATIONS_TABLE,
    "DOCS_BUCKET": DOCS_BUCKET,
    "ESCALATION_TOPIC_ARN": ESCALATION_ARN,
    "REVIEW_TOPIC_ARN": REVIEW_ARN,
    "ANTHROPIC_API_KEY": "sk-ant-test-key",
}

SAMPLE_VIOLATION = {
    "framework": "SEC",
    "rule_reference": "Rule 10b-5",
    "description": "Material misstatement detected.",
    "severity": "high",
    "evidence": "guaranteed returns with zero risk",
    "remediation_steps": ["Remove language", "Legal review", "Reissue"],
}

SAMPLE_CRITICAL = {
    "framework": "BSA_AML",
    "rule_reference": "31 CFR 1020",
    "description": "Suspicious activity not reported.",
    "severity": "critical",
    "evidence": "structured transactions to avoid reporting",
    "remediation_steps": ["File SAR immediately", "Freeze account", "Notify compliance"],
}

CLAUDE_NON_COMPLIANT = {
    "overall_status": "non_compliant",
    "violations": [SAMPLE_VIOLATION],
    "compliance_summary": "One high-severity SEC violation detected.",
    "reviewer_notes": "Legal review required.",
}

CLAUDE_COMPLIANT = {
    "overall_status": "compliant",
    "violations": [],
    "compliance_summary": "No violations found.",
    "reviewer_notes": "Document appears compliant.",
}

CLAUDE_CRITICAL = {
    "overall_status": "non_compliant",
    "violations": [SAMPLE_CRITICAL],
    "compliance_summary": "Critical BSA/AML violation detected.",
    "reviewer_notes": "Immediate SAR filing required.",
}


def make_mock_claude(response_dict: dict) -> MagicMock:
    """
    Return a mock Anthropic client that returns response_dict as JSON text.
    Mocked because real Anthropic API calls are unavailable in CI.
    """
    mock = MagicMock()
    mock.messages.create.return_value = MagicMock(
        content=[MagicMock(text=json.dumps(response_dict))]
    )
    return mock


def make_document(
    document_id: str = "DOC-001",
    content: str = "We guarantee 20 percent returns with zero risk.",
    frameworks: list[str] | None = None,
    document_type: str = "customer_communication",
) -> ComplianceDocument:
    """Create a ComplianceDocument with sensible test defaults."""
    return ComplianceDocument(
        document_id=document_id,
        document_type=document_type,
        content=content,
        source_system="test",
        submitted_by="tester",
        submitted_at=datetime.now(timezone.utc),
        frameworks_to_check=frameworks or ["SEC", "FINRA"],
    )


def make_report(violations: list[Violation] | None = None, **overrides) -> ComplianceReport:
    """Create a ComplianceReport with sensible test defaults."""
    defaults = dict(
        document_id="DOC-001",
        document_type="risk_report",
        overall_status="non_compliant",
        frameworks_checked=["SEC"],
        violations=violations or [],
        compliance_summary="Test summary.",
        reviewer_notes="Test notes.",
        processing_time_ms=100.0,
        model_version="2.0.0",
        timestamp="2026-01-01T00:00:00+00:00",
        audit_hash="",
    )
    defaults.update(overrides)
    return ComplianceReport(**defaults)


def make_violation(severity: str = "high", framework: str = "SEC") -> Violation:
    """Create a Violation with sensible test defaults."""
    return Violation(
        violation_id="DOC-001-V0001",
        document_id="DOC-001",
        framework=framework,
        rule_reference="Rule 10b-5",
        description="Test violation.",
        severity=severity,
        evidence="test evidence",
        remediation_steps=["step 1", "step 2"],
        sla_deadline="2026-01-02T00:00:00+00:00",
    )


@pytest.fixture(autouse=True)
def clear_singletons():
    """
    Reset all module-level AWS client singletons between tests.
    Without this a moto mock from test A bleeds into test B.
    """
    import src.compliance_engine as engine_module
    saved = {
        "_dynamodb_resource": engine_module._dynamodb_resource,
        "_sns_client": engine_module._sns_client,
        "_s3_client": engine_module._s3_client,
        "_cloudwatch_client": engine_module._cloudwatch_client,
        "_engine": engine_module._engine,
    }
    for key in saved:
        setattr(engine_module, key, None)
    yield
    for key, value in saved.items():
        setattr(engine_module, key, value)


@pytest.fixture
def aws_env(monkeypatch):
    """Inject moto magic credentials and resource name env vars."""
    for key, value in ENV_VARS.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def minimal_config(tmp_path) -> Path:
    """Write a minimal valid config.yaml to a temp directory."""
    config = tmp_path / "config.yaml"
    config.write_text(
        textwrap.dedent("""\
            aws:
              region: "us-east-1"
              account_id: "123456789012"
            compliance:
              secret_name: "compliance/anthropic-api-key"
              reports_table: "compliance-reports"
              violations_table: "compliance-violations"
              frameworks:
                - name: "SEC"
                  jurisdiction: "US"
                - name: "FINRA"
                  jurisdiction: "US"
                - name: "Dodd_Frank"
                  jurisdiction: "US"
                - name: "SOX"
                  jurisdiction: "US"
                - name: "BSA_AML"
                  jurisdiction: "US"
              classification:
                model: "claude-sonnet-4-6"
                max_tokens: 1000
              severity_levels:
                critical: 4
                high: 3
                medium: 2
                low: 1
              remediation:
                auto_escalate_critical: true
                escalation_topic: "compliance-escalations-sns"
                sla_hours:
                  critical: 4
                  high: 24
                  medium: 72
                  low: 168
              security:
                document_encryption: true
                immutable_audit_trail: true
        """),
        encoding="utf-8",
    )
    return config


def create_dynamodb_tables():
    """Create both DynamoDB tables needed for persistence tests."""
    ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
    ddb.create_table(
        TableName=REPORTS_TABLE,
        KeySchema=[
            {"AttributeName": "document_id", "KeyType": "HASH"},
            {"AttributeName": "timestamp", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "document_id", "AttributeType": "S"},
            {"AttributeName": "timestamp", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.create_table(
        TableName=VIOLATIONS_TABLE,
        KeySchema=[
            {"AttributeName": "violation_id", "KeyType": "HASH"},
            {"AttributeName": "document_id", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "violation_id", "AttributeType": "S"},
            {"AttributeName": "document_id", "AttributeType": "S"},
            {"AttributeName": "severity", "AttributeType": "S"},
            {"AttributeName": "sla_deadline", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[{
            "IndexName": "SeverityIndex",
            "KeySchema": [
                {"AttributeName": "severity", "KeyType": "HASH"},
                {"AttributeName": "sla_deadline", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )
    return ddb


def make_engine(minimal_config):
    """Create a ComplianceEngine with mocked boto3 construction."""
    with patch("src.compliance_engine.boto3.client"):
        return ComplianceEngine(config_path=minimal_config)


class TestChunkDocument:
    def test_empty_string_returns_empty_list(self):
        # Arrange
        text = ""
        # Act
        result = _chunk_document(text)
        # Assert
        assert result == []

    def test_short_document_returns_single_chunk(self):
        # Arrange
        text = "Short compliance document."
        # Act
        result = _chunk_document(text)
        # Assert
        assert result == [text]

    def test_exactly_chunk_size_returns_single_chunk(self):
        # Arrange
        text = "x" * CHUNK_SIZE
        # Act
        result = _chunk_document(text)
        # Assert
        assert len(result) == 1

    def test_one_char_over_chunk_size_splits(self):
        # Arrange
        text = "x" * (CHUNK_SIZE * 2 + 1)
        # Act
        result = _chunk_document(text)
        # Assert
        assert len(result) >= 2

    def test_paragraph_boundary_preferred_over_hard_split(self):
        # Arrange
        mid = CHUNK_SIZE * 3 // 4
        text = ("a" * mid) + "\n\n" + ("b" * (CHUNK_SIZE * 2))
        # Act
        result = _chunk_document(text)
        # Assert
        assert not result[0].endswith("b")

    def test_overlap_present_in_consecutive_chunks(self):
        # Arrange
        text = "a" * (CHUNK_SIZE + CHUNK_OVERLAP + 100)
        # Act
        result = _chunk_document(text)
        # Assert
        assert len(result) >= 2
        tail = result[0][-CHUNK_OVERLAP:]
        assert result[1].startswith(tail)

    def test_doc_shorter_than_overlap_no_infinite_loop(self):
        # Arrange
        text = "x" * (CHUNK_OVERLAP - 1)
        # Act
        result = _chunk_document(text)
        # Assert
        assert len(result) == 1

    def test_all_content_covered_across_chunks(self):
        # Arrange
        text = "compliance content " * (CHUNK_SIZE // 10)
        # Act
        result = _chunk_document(text)
        combined = "".join(result)
        # Assert
        assert text[:200] in combined
        assert text[-200:] in combined

    def test_large_document_produces_reasonable_chunk_count(self):
        # Arrange
        text = "regulatory document content " * 5000
        # Act
        result = _chunk_document(text)
        # Assert
        assert 5 <= len(result) <= 20


class TestBuildAnalysisPrompt:
    def test_framework_names_appear_in_prompt(self):
        # Arrange / Act
        result = _build_analysis_prompt(["SEC", "FINRA"], "customer_communication", "email", "content")
        # Assert
        assert "SEC" in result
        assert "FINRA" in result

    def test_document_type_appears_in_prompt(self):
        # Arrange / Act
        result = _build_analysis_prompt(["SEC"], "trade_confirmation", "system", "content")
        # Assert
        assert "trade_confirmation" in result

    def test_content_appears_after_delimiter(self):
        # Arrange
        content = "Document content here."
        # Act
        result = _build_analysis_prompt(["SEC"], "audit_document", "system", content)
        # Assert
        delimiter_pos = result.find("=== BEGIN DOCUMENT ===")
        content_pos = result.find(content)
        assert delimiter_pos < content_pos

    def test_dollar_signs_not_corrupted(self):
        # Arrange
        content = "The price is $100 and $$200 for premium."
        # Act
        result = _build_analysis_prompt(["SEC"], "customer_communication", "email", content)
        # Assert
        assert "$100" in result
        assert "$$200" in result

    def test_curly_braces_not_corrupted(self):
        # Arrange
        content = "Rule {10b-5} applies to {frameworks} disclosures."
        # Act
        result = _build_analysis_prompt(["SEC"], "policy_document", "system", content)
        # Assert
        assert "{10b-5}" in result

    def test_begin_and_end_delimiters_present(self):
        # Arrange / Act
        result = _build_analysis_prompt(["SEC"], "audit_document", "system", "content")
        # Assert
        assert "=== BEGIN DOCUMENT ===" in result
        assert "=== END DOCUMENT ===" in result

    def test_json_schema_present_in_prompt(self):
        # Arrange / Act
        result = _build_analysis_prompt(["SEC"], "risk_report", "system", "text")
        # Assert
        assert "overall_status" in result
        assert "violations" in result


class TestValidateSqsMessage:
    def _valid(self, **overrides) -> dict:
        base = {
            "bucket": "my-bucket",
            "key": "documents/doc-001.txt",
            "document_id": "DOC-001",
            "document_type": "customer_communication",
            "frameworks": ["SEC"],
        }
        base.update(overrides)
        return base

    def test_valid_message_passes(self):
        _validate_sqs_message(self._valid())

    def test_missing_bucket_raises(self):
        msg = self._valid()
        del msg["bucket"]
        with pytest.raises(ValueError, match="bucket"):
            _validate_sqs_message(msg)

    def test_missing_key_raises(self):
        msg = self._valid()
        del msg["key"]
        with pytest.raises(ValueError, match="key"):
            _validate_sqs_message(msg)

    def test_missing_document_id_raises(self):
        msg = self._valid()
        del msg["document_id"]
        with pytest.raises(ValueError, match="document_id"):
            _validate_sqs_message(msg)

    def test_non_string_bucket_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_sqs_message(self._valid(bucket=123))

    def test_non_string_key_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_sqs_message(self._valid(key=["bad"]))

    def test_non_string_document_id_raises(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_sqs_message(self._valid(document_id={"k": "v"}))

    def test_document_id_over_max_length_raises(self):
        with pytest.raises(ValueError, match="exceeds maximum"):
            _validate_sqs_message(self._valid(document_id="A" * (DOCUMENT_ID_MAX_LEN + 1)))

    def test_document_id_at_max_length_passes(self):
        _validate_sqs_message(self._valid(document_id="A" * DOCUMENT_ID_MAX_LEN))

    def test_document_id_with_dotdot_raises(self):
        with pytest.raises(ValueError, match="Path traversal"):
            _validate_sqs_message(self._valid(document_id="a/../b"))

    def test_document_id_unicode_raises(self):
        with pytest.raises(ValueError, match="invalid characters"):
            _validate_sqs_message(self._valid(document_id="doc\u0100"))

    def test_document_id_valid_special_chars_pass(self):
        for doc_id in ["DOC-001", "doc_001", "doc.001", "doc:001", "doc@001"]:
            _validate_sqs_message(self._valid(document_id=doc_id))

    def test_document_id_must_start_alphanumeric(self):
        with pytest.raises(ValueError, match="invalid characters"):
            _validate_sqs_message(self._valid(document_id="-bad"))

    def test_invalid_document_type_raises(self):
        with pytest.raises(ValueError, match="Unknown document_type"):
            _validate_sqs_message(self._valid(document_type="invoice"))

    def test_all_valid_document_types_pass(self):
        for doc_type in [
            "trade_confirmation", "customer_communication", "risk_report",
            "audit_document", "policy_document", "regulatory_filing",
            "sar_suspicious_activity",
        ]:
            _validate_sqs_message(self._valid(document_type=doc_type))

    def test_invalid_framework_raises(self):
        with pytest.raises(ValueError, match="Unknown framework"):
            _validate_sqs_message(self._valid(frameworks=["GDPR"]))

    def test_frameworks_not_list_raises(self):
        with pytest.raises(ValueError, match="must be a list"):
            _validate_sqs_message(self._valid(frameworks="SEC"))

    def test_s3_key_with_dotdot_raises(self):
        with pytest.raises(ValueError, match="path traversal"):
            _validate_sqs_message(self._valid(key="docs/../etc/passwd"))

    def test_s3_key_starting_with_slash_raises(self):
        with pytest.raises(ValueError, match="path traversal"):
            _validate_sqs_message(self._valid(key="/etc/passwd"))

    def test_missing_document_type_defaults_without_error(self):
        msg = self._valid()
        del msg["document_type"]
        _validate_sqs_message(msg)

    def test_empty_document_id_raises(self):
        with pytest.raises(ValueError, match="document_id"):
            _validate_sqs_message(self._valid(document_id=""))

    def test_submitted_by_over_256_chars_raises(self):
        with pytest.raises(ValueError, match="submitted_by"):
            _validate_sqs_message(self._valid(submitted_by="x" * 257))

    def test_non_string_submitted_by_raises(self):
        with pytest.raises(ValueError, match="submitted_by"):
            _validate_sqs_message(self._valid(submitted_by=123))


class TestLoadConfig:
    def test_loads_valid_config(self, minimal_config):
        # Arrange / Act
        config = load_config(minimal_config)
        # Assert
        assert config["aws"]["region"] == "us-east-1"
        assert config["compliance"]["classification"]["model"] == "claude-sonnet-4-6"

    def test_env_var_substitution(self, minimal_config, monkeypatch):
        # Arrange
        monkeypatch.setenv("AWS_ACCOUNT_ID", "999888777666")
        original = minimal_config.read_text(encoding="utf-8")
        minimal_config.write_text(
            original.replace('"123456789012"', '"${AWS_ACCOUNT_ID}"'),
            encoding="utf-8",
        )
        # Act
        config = load_config(minimal_config)
        # Assert
        assert config["aws"]["account_id"] == "999888777666"

    def test_missing_env_var_kept_as_placeholder(self, minimal_config, monkeypatch):
        # Arrange
        monkeypatch.delenv("UNSET_VAR", raising=False)
        minimal_config.write_text(
            "aws:\n  region: \"${UNSET_VAR}\"\n"
            "compliance:\n  secret_name: x\n  frameworks: []\n"
            "  classification:\n    model: m\n    max_tokens: 100\n"
            "  severity_levels: {}\n  remediation:\n"
            "    auto_escalate_critical: false\n    escalation_topic: t\n"
            "    sla_hours: {}\n  security: {}\n",
            encoding="utf-8",
        )
        # Act
        config = load_config(minimal_config)
        # Assert
        assert config["aws"]["region"] == "${UNSET_VAR}"

    def test_oversized_config_raises(self, tmp_path):
        # Arrange
        oversized = tmp_path / "big.yaml"
        oversized.write_bytes(b"x: " + b"a" * (1024 * 1024 + 1))
        # Act / Assert
        with pytest.raises(ValueError, match="1 MB"):
            load_config(oversized)

    def test_default_config_file_loads(self):
        # Arrange / Act
        config = load_config()
        # Assert
        assert "compliance" in config
        assert "aws" in config


class TestComputeAuditHash:
    def test_hash_is_deterministic(self):
        # Arrange
        report = make_report()
        # Act / Assert
        assert _compute_audit_hash(report) == _compute_audit_hash(report)

    def test_hash_changes_when_status_changes(self):
        # Arrange
        report_a = make_report(overall_status="non_compliant")
        report_b = make_report(overall_status="compliant")
        # Act / Assert
        assert _compute_audit_hash(report_a) != _compute_audit_hash(report_b)

    def test_hash_changes_when_model_version_changes(self):
        # Arrange
        report_a = make_report(model_version="2.0.0")
        report_b = make_report(model_version="3.0.0")
        # Act / Assert
        assert _compute_audit_hash(report_a) != _compute_audit_hash(report_b)

    def test_hash_changes_when_violation_severity_changes(self):
        # Arrange
        report_a = make_report(violations=[make_violation(severity="high")])
        report_b = make_report(violations=[make_violation(severity="critical")])
        # Act / Assert
        assert _compute_audit_hash(report_a) != _compute_audit_hash(report_b)

    def test_hash_changes_when_evidence_changes(self):
        # Arrange
        v1 = make_violation()
        v1.evidence = "evidence A"
        v2 = make_violation()
        v2.evidence = "evidence B"
        # Act / Assert
        assert _compute_audit_hash(make_report(violations=[v1])) != _compute_audit_hash(make_report(violations=[v2]))

    def test_hash_is_64_char_hex_string(self):
        # Arrange / Act
        result = _compute_audit_hash(make_report())
        # Assert
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestDeduplicateViolations:
    def test_single_violation_unchanged(self):
        violations = [{"framework": "SEC", "rule_reference": "Rule 10b-5"}]
        assert len(_deduplicate_violations(violations)) == 1

    def test_duplicate_pair_removed(self):
        dup = {"framework": "SEC", "rule_reference": "Rule 10b-5"}
        assert len(_deduplicate_violations([dup, dup])) == 1

    def test_same_rule_different_framework_both_kept(self):
        violations = [
            {"framework": "SEC", "rule_reference": "Rule 10b-5"},
            {"framework": "FINRA", "rule_reference": "Rule 10b-5"},
        ]
        assert len(_deduplicate_violations(violations)) == 2

    def test_empty_list_returns_empty(self):
        assert _deduplicate_violations([]) == []

    def test_first_occurrence_preserved(self):
        violations = [
            {"framework": "SEC", "rule_reference": "Rule 10b-5", "description": "first"},
            {"framework": "SEC", "rule_reference": "Rule 10b-5", "description": "second"},
        ]
        assert _deduplicate_violations(violations)[0]["description"] == "first"


class TestMergeChunkStatuses:
    def test_all_compliant_returns_compliant(self):
        assert _merge_chunk_statuses(["compliant", "compliant"]) == "compliant"

    def test_any_non_compliant_returns_non_compliant(self):
        assert _merge_chunk_statuses(["compliant", "non_compliant"]) == "non_compliant"

    def test_non_compliant_overrides_requires_review(self):
        assert _merge_chunk_statuses(["requires_review", "non_compliant"]) == "non_compliant"

    def test_requires_review_overrides_compliant(self):
        assert _merge_chunk_statuses(["compliant", "requires_review"]) == "requires_review"

    def test_single_status_returned_unchanged(self):
        assert _merge_chunk_statuses(["compliant"]) == "compliant"


class TestBuildViolationObjects:
    def test_violation_id_format(self):
        # Arrange
        raw = [{"framework": "SEC", "rule_reference": "Rule 10b-5",
                "description": "d", "severity": "high", "evidence": "e",
                "remediation_steps": []}]
        submission = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Act
        result = _build_violation_objects(raw, "DOC-001", submission, {"high": 24})
        # Assert
        assert result[0].violation_id == "DOC-001-V0001"

    def test_sla_anchored_to_submission_time(self):
        # Arrange
        raw = [{"framework": "SEC", "rule_reference": "Rule 10b-5",
                "description": "d", "severity": "high", "evidence": "e",
                "remediation_steps": []}]
        submission = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        # Act
        result = _build_violation_objects(raw, "DOC-001", submission, {"high": 24})
        # Assert
        assert "2026-01-02" in result[0].sla_deadline

    def test_evidence_truncated_to_max(self):
        # Arrange
        raw = [{"framework": "SEC", "rule_reference": "R", "description": "d",
                "severity": "low", "evidence": "x" * 1000, "remediation_steps": []}]
        # Act
        result = _build_violation_objects(raw, "DOC-001", datetime.now(timezone.utc), {})
        # Assert
        assert len(result[0].evidence) <= MAX_EVIDENCE_CHARS

    def test_empty_input_returns_empty_list(self):
        result = _build_violation_objects([], "DOC-001", datetime.now(timezone.utc), {})
        assert result == []


class TestEngineConstruction:
    def test_empty_model_name_raises(self, minimal_config):
        # Arrange
        text = minimal_config.read_text(encoding="utf-8")
        minimal_config.write_text(
            text.replace('model: "claude-sonnet-4-6"', 'model: ""'),
            encoding="utf-8",
        )
        # Act / Assert
        with patch("src.compliance_engine.boto3.client"):
            with pytest.raises(ValueError, match="model"):
                ComplianceEngine(config_path=minimal_config)

    def test_anthropic_client_not_created_at_construction(self, minimal_config):
        # Arrange / Act
        with patch("src.compliance_engine.boto3.client"):
            engine = ComplianceEngine(config_path=minimal_config)
        # Assert
        assert engine._anthropic_client is None

    def test_setter_suppresses_ttl_refresh(self, minimal_config):
        # Arrange
        mock_client = MagicMock()
        with patch("src.compliance_engine.boto3.client"):
            engine = ComplianceEngine(config_path=minimal_config)
        # Act
        engine.anthropic_client = mock_client
        # Assert
        assert engine._client_set_manually is True
        assert engine.anthropic_client is mock_client


class TestFetchAnthropicClient:
    def test_reads_key_from_secrets_manager(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {
            "SecretString": json.dumps({"ANTHROPIC_API_KEY": "sk-test"})
        }
        # Act / Assert
        with patch("src.compliance_engine.boto3.client", return_value=mock_sm):
            with patch("src.compliance_engine.anthropic.Anthropic") as mock_anth:
                _ = engine.anthropic_client
        mock_anth.assert_called_once_with(api_key="sk-test")

    def test_falls_back_to_env_on_resource_not_found(self, minimal_config, monkeypatch):
        # Arrange
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-fallback")
        engine = make_engine(minimal_config)
        from botocore.exceptions import ClientError
        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
            "GetSecretValue",
        )
        # Act / Assert
        with patch("src.compliance_engine.boto3.client", return_value=mock_sm):
            with patch("src.compliance_engine.anthropic.Anthropic") as mock_anth:
                _ = engine.anthropic_client
        mock_anth.assert_called_once_with(api_key="sk-env-fallback")

    def test_missing_key_in_secret_raises(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {
            "SecretString": json.dumps({"WRONG_KEY": "value"})
        }
        # Act / Assert
        with patch("src.compliance_engine.boto3.client", return_value=mock_sm):
            with pytest.raises(KeyError, match="ANTHROPIC_API_KEY"):
                _ = engine.anthropic_client

    def test_no_env_fallback_raises_runtime_error(self, minimal_config, monkeypatch):
        # Arrange
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        engine = make_engine(minimal_config)
        from botocore.exceptions import ClientError
        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
            "GetSecretValue",
        )
        # Act / Assert
        with patch("src.compliance_engine.boto3.client", return_value=mock_sm):
            with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
                _ = engine.anthropic_client

    def test_unexpected_aws_error_propagates(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        from botocore.exceptions import ClientError
        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "throttled"}},
            "GetSecretValue",
        )
        # Act / Assert
        with patch("src.compliance_engine.boto3.client", return_value=mock_sm):
            with pytest.raises(ClientError):
                _ = engine.anthropic_client


@mock_aws
class TestPersistence:
    def setup_engine(self, minimal_config, aws_env):
        create_dynamodb_tables()
        engine = make_engine(minimal_config)
        engine.anthropic_client = make_mock_claude(CLAUDE_NON_COMPLIANT)
        return engine, boto3.resource("dynamodb", region_name=AWS_REGION)

    def test_report_written_to_dynamodb(self, minimal_config, aws_env):
        # Arrange
        engine, ddb = self.setup_engine(minimal_config, aws_env)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        item = ddb.Table(REPORTS_TABLE).get_item(
            Key={"document_id": "DOC-001", "timestamp": report.timestamp}
        )["Item"]
        assert item["overall_status"] == "non_compliant"

    def test_violations_written_to_dynamodb(self, minimal_config, aws_env):
        # Arrange
        engine, ddb = self.setup_engine(minimal_config, aws_env)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            engine.analyse_document(make_document())
        # Assert
        items = ddb.Table(VIOLATIONS_TABLE).scan()["Items"]
        assert len(items) == 1

    def test_violations_written_before_report(self, minimal_config, aws_env):
        """Regression test for write ordering bug V3-01."""
        # Arrange
        engine, ddb = self.setup_engine(minimal_config, aws_env)
        violations_existed: list[bool] = []
        original = engine._save_report

        def spy(report):
            count = ddb.Table(VIOLATIONS_TABLE).scan()["Count"]
            violations_existed.append(count > 0)
            original(report)

        engine._save_report = spy
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            engine.analyse_document(make_document())
        # Assert
        assert violations_existed[0] is True

    def test_duplicate_delivery_is_idempotent(self, minimal_config, aws_env):
        # Arrange
        engine, ddb = self.setup_engine(minimal_config, aws_env)
        fixed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        doc_a = make_document()
        doc_a.submitted_at = fixed
        doc_b = make_document()
        doc_b.submitted_at = fixed
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            engine.analyse_document(doc_a)
            engine.analyse_document(doc_b)
        # Assert
        assert ddb.Table(REPORTS_TABLE).scan()["Count"] == 1

    def test_ttl_set_on_report(self, minimal_config, aws_env):
        # Arrange
        engine, ddb = self.setup_engine(minimal_config, aws_env)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        item = ddb.Table(REPORTS_TABLE).get_item(
            Key={"document_id": "DOC-001", "timestamp": report.timestamp}
        )["Item"]
        assert item["ttl"] >= int(time.time()) + (RETENTION_DAYS - 1) * 86400


@mock_aws
class TestAnalyseDocument:
    def setup_engine(self, minimal_config, aws_env):
        create_dynamodb_tables()
        return make_engine(minimal_config)

    def test_compliant_status(self, minimal_config, aws_env):
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = make_mock_claude(CLAUDE_COMPLIANT)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        assert report.overall_status == "compliant"

    def test_non_compliant_status(self, minimal_config, aws_env):
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = make_mock_claude(CLAUDE_NON_COMPLIANT)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        assert report.overall_status == "non_compliant"
        assert len(report.violations) == 1

    def test_audit_hash_set(self, minimal_config, aws_env):
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = make_mock_claude(CLAUDE_COMPLIANT)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        assert len(report.audit_hash) == 64

    def test_violation_id_format(self, minimal_config, aws_env):
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = make_mock_claude(CLAUDE_NON_COMPLIANT)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        assert report.violations[0].violation_id == "DOC-001-V0001"

    def test_dedup_across_chunks(self, minimal_config, aws_env):
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = MagicMock()
        engine.anthropic_client.messages.create.side_effect = [
            MagicMock(content=[MagicMock(text=json.dumps(CLAUDE_NON_COMPLIANT))]),
            MagicMock(content=[MagicMock(text=json.dumps(CLAUDE_NON_COMPLIANT))]),
        ]
        large_doc = make_document(content="x" * (CHUNK_SIZE + 1000))
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(large_doc)
        # Assert
        assert len(report.violations) == 1

    def test_unparseable_json_gives_requires_review(self, minimal_config, aws_env):
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = MagicMock()
        engine.anthropic_client.messages.create.return_value = MagicMock(
            content=[MagicMock(text="this is not json")]
        )
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        assert report.overall_status == "requires_review"

    def test_auth_error_propagates(self, minimal_config, aws_env):
        """Regression test for bare-except bug V3-06."""
        # Arrange
        import anthropic as _anth
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = MagicMock()
        engine.anthropic_client.messages.create.side_effect = _anth.AuthenticationError(
            message="bad key", response=MagicMock(), body={}
        )
        # Act / Assert
        with pytest.raises(_anth.AuthenticationError):
            engine.analyse_document(make_document())

    def test_sla_anchored_to_submission(self, minimal_config, aws_env):
        """Regression test for SLA anchoring bug V3-07."""
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = make_mock_claude(CLAUDE_NON_COMPLIANT)
        fixed = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        doc = make_document()
        doc.submitted_at = fixed
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(doc)
        # Assert
        assert "2026-01-02" in report.violations[0].sla_deadline

    def test_evidence_truncated(self, minimal_config, aws_env):
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        long_evidence = {"framework": "SEC", "rule_reference": "Rule 10b-5",
                         "description": "d", "severity": "high",
                         "evidence": "x" * 1000, "remediation_steps": []}
        engine.anthropic_client = make_mock_claude({
            "overall_status": "non_compliant",
            "violations": [long_evidence],
            "compliance_summary": "s",
            "reviewer_notes": "n",
        })
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            report = engine.analyse_document(make_document())
        # Assert
        assert len(report.violations[0].evidence) <= MAX_EVIDENCE_CHARS

    def test_metrics_fire_even_when_escalation_fails(self, minimal_config, aws_env):
        """Regression test for metrics-skipping bug V3-02."""
        # Arrange
        engine = self.setup_engine(minimal_config, aws_env)
        engine.anthropic_client = make_mock_claude(CLAUDE_CRITICAL)
        mock_cw = MagicMock()
        # Act / Assert
        with patch("src.compliance_engine._get_cloudwatch", return_value=mock_cw):
            with patch("src.compliance_engine._get_sns") as mock_sns_factory:
                mock_sns_factory.return_value.publish.side_effect = Exception("SNS down")
                with pytest.raises(Exception, match="SNS down"):
                    engine.analyse_document(make_document())
        mock_cw.put_metric_data.assert_called_once()


class TestEscalateCritical:
    def test_critical_publishes_to_sns(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._escalate_critical_violations([make_violation("critical")], make_document())
        # Assert
        mock_sns.publish.assert_called_once()
        assert "[CRITICAL]" in mock_sns.publish.call_args[1]["Subject"]

    def test_high_not_escalated(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._escalate_critical_violations([make_violation("high")], make_document())
        # Assert
        mock_sns.publish.assert_not_called()

    def test_no_violations_no_sns(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._escalate_critical_violations([], make_document())
        # Assert
        mock_sns.publish.assert_not_called()

    def test_subject_truncated_to_max(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        long_doc = make_document(document_id="A" * 200)
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._escalate_critical_violations([make_violation("critical")], long_doc)
        # Assert
        assert len(mock_sns.publish.call_args[1]["Subject"]) <= SNS_SUBJECT_MAX_LEN

    def test_auto_escalated_flag_set(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        v = make_violation("critical")
        # Act
        with patch("src.compliance_engine._get_sns", return_value=MagicMock()):
            engine._escalate_critical_violations([v], make_document())
        # Assert
        assert v.auto_escalated is True

    def test_missing_topic_arn_skips(self, minimal_config, monkeypatch):
        # Arrange
        monkeypatch.delenv("ESCALATION_TOPIC_ARN", raising=False)
        monkeypatch.setenv("AWS_DEFAULT_REGION", AWS_REGION)
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._escalate_critical_violations([make_violation("critical")], make_document())
        # Assert
        mock_sns.publish.assert_not_called()


class TestRouteRequiresReview:
    def test_requires_review_publishes(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        report = make_report(overall_status="requires_review")
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._route_requires_review(report, make_document())
        # Assert
        mock_sns.publish.assert_called_once()
        assert mock_sns.publish.call_args[1]["TopicArn"] == REVIEW_ARN

    def test_compliant_does_not_publish(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._route_requires_review(make_report(overall_status="compliant"), make_document())
        # Assert
        mock_sns.publish.assert_not_called()

    def test_non_compliant_does_not_publish(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._route_requires_review(make_report(overall_status="non_compliant"), make_document())
        # Assert
        mock_sns.publish.assert_not_called()

    def test_missing_review_arn_skips(self, minimal_config, monkeypatch):
        # Arrange
        monkeypatch.delenv("REVIEW_TOPIC_ARN", raising=False)
        monkeypatch.setenv("AWS_DEFAULT_REGION", AWS_REGION)
        engine = make_engine(minimal_config)
        mock_sns = MagicMock()
        # Act
        with patch("src.compliance_engine._get_sns", return_value=mock_sns):
            engine._route_requires_review(make_report(overall_status="requires_review"), make_document())
        # Assert
        mock_sns.publish.assert_not_called()


class TestPublishMetrics:
    def test_correct_namespace_used(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_cw = MagicMock()
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=mock_cw):
            engine._publish_metrics([make_violation("critical")])
        # Assert
        assert mock_cw.put_metric_data.call_args[1]["Namespace"] == "Compliance"

    def test_critical_and_total_both_emitted(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_cw = MagicMock()
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=mock_cw):
            engine._publish_metrics([make_violation("critical"), make_violation("high")])
        # Assert
        names = {m["MetricName"] for m in mock_cw.put_metric_data.call_args[1]["MetricData"]}
        assert "CriticalViolations" in names
        assert "TotalViolations" in names

    def test_zero_violations_emits_zero(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_cw = MagicMock()
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=mock_cw):
            engine._publish_metrics([])
        # Assert
        data = mock_cw.put_metric_data.call_args[1]["MetricData"]
        crit = next(m for m in data if m["MetricName"] == "CriticalViolations")
        assert crit["Value"] == 0

    def test_cloudwatch_failure_does_not_raise(self, minimal_config, aws_env):
        # Arrange
        engine = make_engine(minimal_config)
        mock_cw = MagicMock()
        mock_cw.put_metric_data.side_effect = Exception("CW unavailable")
        # Act / Assert: no exception propagates
        with patch("src.compliance_engine._get_cloudwatch", return_value=mock_cw):
            engine._publish_metrics([make_violation("critical")])


@mock_aws
class TestLambdaHandler:
    def setup_environment(self, minimal_config, aws_env):
        create_dynamodb_tables()
        s3 = boto3.client("s3", region_name=AWS_REGION)
        s3.create_bucket(Bucket=DOCS_BUCKET)
        s3.put_object(
            Bucket=DOCS_BUCKET,
            Key="documents/test-doc.txt",
            Body=b"We guarantee 20 percent returns with zero risk.",
        )
        engine = make_engine(minimal_config)
        engine.anthropic_client = make_mock_claude(CLAUDE_NON_COMPLIANT)
        import src.compliance_engine as eng_module
        eng_module._engine = engine

    def make_event(self, document_id="DOC-001", message_id="msg-001",
                   bucket=DOCS_BUCKET, key="documents/test-doc.txt") -> dict:
        return {"Records": [{"messageId": message_id, "body": json.dumps({
            "document_id": document_id, "bucket": bucket, "key": key,
            "document_type": "customer_communication", "frameworks": ["SEC", "FINRA"],
        })}]}

    def test_happy_path_returns_no_failures(self, minimal_config, aws_env):
        # Arrange
        self.setup_environment(minimal_config, aws_env)
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            result = lambda_handler(self.make_event(), None)
        # Assert
        assert result["batchItemFailures"] == []

    def test_invalid_message_returns_failure(self, minimal_config, aws_env):
        # Arrange
        self.setup_environment(minimal_config, aws_env)
        event = {"Records": [{"messageId": "msg-bad", "body": json.dumps({"bad": "data"})}]}
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            result = lambda_handler(event, None)
        # Assert
        assert result["batchItemFailures"] == [{"itemIdentifier": "msg-bad"}]

    def test_missing_message_id_skipped(self, minimal_config, aws_env):
        # Arrange
        self.setup_environment(minimal_config, aws_env)
        event = {"Records": [{"body": json.dumps({"document_id": "X", "bucket": DOCS_BUCKET, "key": "documents/test-doc.txt"})}]}
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            result = lambda_handler(event, None)
        # Assert
        assert result["batchItemFailures"] == []

    def test_oversized_document_returns_failure(self, minimal_config, aws_env):
        # Arrange
        self.setup_environment(minimal_config, aws_env)
        mock_s3 = MagicMock()
        mock_s3.head_object.return_value = {"ContentLength": MAX_DOCUMENT_BYTES + 1}
        # Act
        with patch("src.compliance_engine._get_s3", return_value=mock_s3):
            with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
                result = lambda_handler(self.make_event(), None)
        # Assert
        assert result["batchItemFailures"] == [{"itemIdentifier": "msg-001"}]

    def test_mixed_batch_only_failed_returned(self, minimal_config, aws_env):
        # Arrange
        self.setup_environment(minimal_config, aws_env)
        event = {"Records": [
            {"messageId": "msg-good", "body": json.dumps({
                "document_id": "DOC-GOOD", "bucket": DOCS_BUCKET,
                "key": "documents/test-doc.txt",
                "document_type": "customer_communication", "frameworks": ["SEC"],
            })},
            {"messageId": "msg-bad", "body": json.dumps({"garbage": True})},
        ]}
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            result = lambda_handler(event, None)
        # Assert
        ids = [f["itemIdentifier"] for f in result["batchItemFailures"]]
        assert "msg-bad" in ids
        assert "msg-good" not in ids

    def test_empty_records_returns_no_failures(self, minimal_config, aws_env):
        # Arrange
        self.setup_environment(minimal_config, aws_env)
        # Act
        result = lambda_handler({"Records": []}, None)
        # Assert
        assert result == {"batchItemFailures": []}

    def test_non_json_body_returns_failure(self, minimal_config, aws_env):
        # Arrange
        self.setup_environment(minimal_config, aws_env)
        event = {"Records": [{"messageId": "msg-nj", "body": "NOT JSON {{{"}]}
        # Act
        with patch("src.compliance_engine._get_cloudwatch", return_value=MagicMock()):
            result = lambda_handler(event, None)
        # Assert
        assert result["batchItemFailures"] == [{"itemIdentifier": "msg-nj"}]


class TestPackageVersion:
    def test_version_string(self):
        from src import __version__
        assert __version__ == "2.0.0"

    def test_public_symbols_importable(self):
        from src import (
            ComplianceDocument, ComplianceEngine, ComplianceReport,
            Violation, lambda_handler, load_config,
        )
        assert all([ComplianceDocument, ComplianceEngine, ComplianceReport,
                    Violation, lambda_handler, load_config])
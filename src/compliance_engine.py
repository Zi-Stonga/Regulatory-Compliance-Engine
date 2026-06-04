"""
compliance_engine.py
Automated multi-framework regulatory compliance analysis using Claude.

Frameworks: SEC, FINRA, Dodd-Frank, SOX, BSA/AML

Architecture:
    SQS triggers Lambda per document (batch_size=1).
    Lambda fetches the S3 object, chunks it into overlapping segments,
    sends each chunk to Claude for parallel analysis, deduplicates
    violations across chunks, then persists violations before the report
    so that partial DynamoDB failures leave nothing orphaned.
    Critical violations escalate via SNS immediately.
    requires_review documents route to a separate analyst SNS topic.
    CloudWatch metrics publish in a finally-equivalent block so alarms
    always receive data points even when escalation fails.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from typing import Any

import boto3
import yaml
from botocore.exceptions import ClientError

import anthropic

log = logging.getLogger(__name__)
if not log.handlers:
    try:
        from pythonjsonlogger import jsonlogger
        _handler = logging.StreamHandler()
        _handler.setFormatter(
            jsonlogger.JsonFormatter(
                fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
                rename_fields={"levelname": "level", "asctime": "timestamp"},
            )
        )
    except ImportError:
        _handler = logging.StreamHandler()
        _handler.setFormatter(
            logging.Formatter("%(levelname)s | %(name)s | %(message)s")
        )
    log.addHandler(_handler)
    log.setLevel(logging.INFO)
    log.propagate = False


_PACKAGE_ROOT = Path(__file__).parent.parent.resolve()
_DEFAULT_CONFIG = _PACKAGE_ROOT / "configs" / "config.yaml"

MAX_DOCUMENT_BYTES = 50 * 1024 * 1024
MAX_CONFIG_BYTES = 1 * 1024 * 1024
MAX_EVIDENCE_CHARS = 500
RETENTION_DAYS = 3653
SNS_SUBJECT_MAX_LEN = 80
DOCUMENT_ID_MAX_LEN = 200
MAX_CHUNK_WORKERS = 5
CHUNK_SIZE = 15_000
CHUNK_OVERLAP = 500

_DOCUMENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_.:@]{0,199}$")

_VALID_FRAMEWORKS = frozenset({"SEC", "FINRA", "Dodd_Frank", "SOX", "BSA_AML"})
_VALID_DOCUMENT_TYPES = frozenset({
    "trade_confirmation",
    "customer_communication",
    "risk_report",
    "audit_document",
    "policy_document",
    "regulatory_filing",
    "sar_suspicious_activity",
})

_AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

_dynamodb_resource = None
_sns_client = None
_s3_client = None
_cloudwatch_client = None


def _get_dynamodb():
    """Return the cached DynamoDB resource, creating it on first call."""
    global _dynamodb_resource
    if _dynamodb_resource is None:
        _dynamodb_resource = boto3.resource("dynamodb", region_name=_AWS_REGION)
    return _dynamodb_resource


def _get_sns():
    """Return the cached SNS client, creating it on first call."""
    global _sns_client
    if _sns_client is None:
        _sns_client = boto3.client("sns", region_name=_AWS_REGION)
    return _sns_client


def _get_s3():
    """Return the cached S3 client, creating it on first call."""
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3", region_name=_AWS_REGION)
    return _s3_client


def _get_cloudwatch():
    """Return the cached CloudWatch client, creating it on first call."""
    global _cloudwatch_client
    if _cloudwatch_client is None:
        _cloudwatch_client = boto3.client("cloudwatch", region_name=_AWS_REGION)
    return _cloudwatch_client


def load_config(path: str | Path | None = None) -> dict:
    """
    Load YAML configuration with environment variable substitution.

    Substitutes dollar-brace VAR_NAME patterns with environment variable values.
    Resolves any relative path to absolute. Blocks path traversal outside
    the package root. Enforces a 1 MB file size cap before reading.

    Args:
        path: Config file path. Defaults to configs/config.yaml.

    Returns:
        Parsed configuration dictionary.

    Raises:
        ValueError: If path traverses outside the package root or exceeds size cap.
    """
    if path is None:
        resolved = _DEFAULT_CONFIG
    else:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = _PACKAGE_ROOT / candidate
        resolved = candidate.resolve()
        if not candidate.is_absolute():
            try:
                resolved.relative_to(_PACKAGE_ROOT)
            except ValueError:
                raise ValueError(
                    f"Config path {str(resolved)!r} escapes the package root. "
                    "Path traversal is not permitted."
                )

    file_size = resolved.stat().st_size
    if file_size > MAX_CONFIG_BYTES:
        raise ValueError(
            f"Config file is {file_size:,} bytes which exceeds the 1 MB cap."
        )

    with resolved.open(encoding="utf-8") as config_file:
        raw_content = config_file.read()

    def _substitute_env_var(match: re.Match) -> str:
        return os.environ.get(match.group(1), match.group(0))

    substituted = re.sub(r"\$\{([^}]+)\}", _substitute_env_var, raw_content)
    return yaml.safe_load(substituted)


@dataclass
class ComplianceDocument:
    """A financial document submitted for regulatory compliance analysis."""

    document_id: str
    document_type: str
    content: str
    source_system: str
    submitted_by: str
    submitted_at: datetime
    frameworks_to_check: list[str] = field(default_factory=list)


@dataclass
class Violation:
    """A single regulatory violation identified within a compliance document."""

    violation_id: str
    document_id: str
    framework: str
    rule_reference: str
    description: str
    severity: str
    evidence: str
    remediation_steps: list[str]
    sla_deadline: str
    auto_escalated: bool = False


@dataclass
class ComplianceReport:
    """The complete compliance analysis result for a single document."""

    document_id: str
    document_type: str
    overall_status: str
    frameworks_checked: list[str]
    violations: list[Violation]
    compliance_summary: str
    reviewer_notes: str
    processing_time_ms: float
    model_version: str
    timestamp: str
    audit_hash: str


_RESPONSE_SCHEMA = (
    '{"overall_status":"compliant|non_compliant|requires_review",'
    '"violations":[{"framework":"SEC|FINRA|Dodd_Frank|SOX|BSA_AML",'
    '"rule_reference":"...","description":"...","severity":"critical|high|medium|low",'
    '"evidence":"...","remediation_steps":["step1","step2","step3"]}],'
    '"compliance_summary":"2-3 sentence executive summary",'
    '"reviewer_notes":"Ambiguities or items requiring human judgment"}'
)


def _build_analysis_prompt(
    frameworks: list[str],
    document_type: str,
    source_system: str,
    content: str,
) -> str:
    """
    Build the Claude analysis prompt for a single document chunk.

    Document content is isolated after a sentinel delimiter so that
    adversarial document text cannot modify the instruction section.

    Args:
        frameworks: Framework names to analyse against.
        document_type: Classification of the document being analysed.
        source_system: Origin system identifier for context.
        content: Document text for this chunk.

    Returns:
        Formatted prompt string ready for the Claude messages API.
    """
    framework_list = ", ".join(frameworks)
    return (
        f"You are a senior regulatory compliance officer with expertise in {framework_list}.\n\n"
        f"Document Type: {document_type}\n"
        f"Source System: {source_system}\n\n"
        f"Analyse the document below for violations across: {framework_list}\n\n"
        f"For each violation identify:\n"
        f"1. Regulatory framework\n"
        f"2. Specific rule reference (e.g. SEC Rule 10b-5, FINRA Rule 2111, "
        f"Dodd-Frank Section 619, SOX Section 302, BSA 31 CFR 1020)\n"
        f"3. Severity: critical|high|medium|low\n"
        f"4. Exact evidence from the document\n"
        f"5. Three concrete remediation steps\n\n"
        f"Return ONLY this JSON structure, nothing else:\n{_RESPONSE_SCHEMA}\n\n"
        f"=== BEGIN DOCUMENT ===\n{content}\n=== END DOCUMENT ==="
    )


def _chunk_document(text: str) -> list[str]:
    """
    Split a large document into overlapping chunks for multi-pass analysis.

    Prefers paragraph boundaries over hard character splits. Includes a
    guard against infinite loops when document length is at or below the
    overlap size.

    Args:
        text: Full document text to split.

    Returns:
        List of string chunks. Returns empty list for empty input.
    """
    if not text:
        return []
    if len(text) <= CHUNK_SIZE:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + CHUNK_SIZE, len(text))
        if end < len(text):
            paragraph_break = text.rfind("\n\n", start, end)
            if paragraph_break > start + CHUNK_SIZE // 2:
                end = paragraph_break

        chunks.append(text[start:end])
        next_start = end - CHUNK_OVERLAP
        if next_start <= start:
            next_start = end
        start = next_start

    return chunks


def _call_claude_with_retry(
    client: anthropic.Anthropic,
    model: str,
    max_tokens: int,
    messages: list[dict],
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> anthropic.types.Message:
    """
    Call the Claude messages API with exponential backoff retry.

    Retries on RateLimitError, InternalServerError, and APIConnectionError.
    Re-raises AuthenticationError immediately without retry because retrying
    a bad API key wastes the retry budget and masks the root cause.

    Args:
        client: Authenticated Anthropic client instance.
        model: Claude model identifier string.
        max_tokens: Maximum tokens in the completion response.
        messages: Message list in Claude API format.
        max_retries: Number of attempts before raising the last exception.
        base_delay: Base delay in seconds for exponential backoff.

    Returns:
        Claude API Message response object.

    Raises:
        anthropic.AuthenticationError: Immediately, without retry.
        anthropic.RateLimitError: After all retries exhausted.
        anthropic.InternalServerError: After all retries exhausted.
        anthropic.APIConnectionError: After all retries exhausted.
    """
    rng = secrets.SystemRandom()
    last_exception: Exception | None = None

    for attempt in range(max_retries):
        try:
            return client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=messages,
            )
        except anthropic.AuthenticationError:
            raise
        except anthropic.RateLimitError as exc:
            last_exception = exc
            if attempt == max_retries - 1:
                break
            delay = base_delay * (2 ** attempt) + rng.uniform(0, 0.5)
            log.warning(
                "Rate limit on attempt %d of %d; retrying in %.1fs",
                attempt + 1,
                max_retries,
                delay,
            )
            time.sleep(delay)
        except (anthropic.InternalServerError, anthropic.APIConnectionError) as exc:
            last_exception = exc
            if attempt == max_retries - 1:
                break
            time.sleep(base_delay * (2 ** attempt))

    assert last_exception is not None
    raise last_exception


def _validate_sqs_message(message: dict[str, Any]) -> None:
    """
    Validate all fields in an incoming SQS message before processing.

    Args:
        message: Parsed JSON body from the SQS record.

    Raises:
        ValueError: Describing the specific field that failed validation.
    """
    for field_name in ("bucket", "key", "document_id"):
        value = message.get(field_name)
        if not value:
            raise ValueError(
                f"Required field {field_name!r} is missing or empty. "
                "Check the SQS message schema."
            )
        if not isinstance(value, str):
            raise ValueError(
                f"Field {field_name!r} must be a string, "
                f"got {type(value).__name__}. Check the message producer."
            )

    document_id = message["document_id"]
    if len(document_id) > DOCUMENT_ID_MAX_LEN:
        raise ValueError(
            f"document_id length {len(document_id)} exceeds maximum {DOCUMENT_ID_MAX_LEN}."
        )
    if ".." in document_id:
        raise ValueError(
            "document_id must not contain '..' sequences. "
            "Path traversal characters are not permitted."
        )
    if not _DOCUMENT_ID_PATTERN.match(document_id):
        raise ValueError(
            f"document_id {document_id!r} contains invalid characters. "
            "Use ASCII letters, digits, hyphens, underscores, dots, colons, or @."
        )

    document_type = message.get("document_type", "regulatory_filing")
    if not isinstance(document_type, str) or document_type not in _VALID_DOCUMENT_TYPES:
        raise ValueError(
            f"Unknown document_type {document_type!r}. "
            f"Valid types are: {sorted(_VALID_DOCUMENT_TYPES)}."
        )

    frameworks = message.get("frameworks", [])
    if not isinstance(frameworks, list):
        raise ValueError(
            "Field 'frameworks' must be a list. "
            "Check the message producer sends a JSON array."
        )
    invalid = set(frameworks) - _VALID_FRAMEWORKS
    if invalid:
        raise ValueError(
            f"Unknown framework(s): {invalid}. "
            f"Valid frameworks are: {sorted(_VALID_FRAMEWORKS)}."
        )

    s3_key = message["key"]
    if ".." in s3_key or s3_key.startswith("/"):
        raise ValueError(
            f"S3 key {s3_key!r} contains path traversal components. "
            "Keys must not contain '..' or start with '/'."
        )

    for optional_field in ("submitted_by", "source_system"):
        value = message.get(optional_field)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(
                    f"Optional field {optional_field!r} must be a string when provided."
                )
            if len(value) > 256:
                raise ValueError(
                    f"Optional field {optional_field!r} exceeds 256 character limit."
                )


def _deduplicate_violations(raw_violations: list[dict]) -> list[dict]:
    """
    Remove duplicate violations by framework and rule_reference composite key.

    Args:
        raw_violations: Flat list of violation dicts from all chunk results.

    Returns:
        Deduplicated list preserving first-occurrence order.
    """
    seen_keys: set[str] = set()
    deduplicated: list[dict] = []

    for violation in raw_violations:
        composite_key = (
            f"{violation.get('framework', '')}::{violation.get('rule_reference', '')}"
        )
        if composite_key not in seen_keys:
            seen_keys.add(composite_key)
            deduplicated.append(violation)

    return deduplicated


def _merge_chunk_statuses(statuses: list[str]) -> str:
    """
    Merge per-chunk overall_status values into a single document status.

    Priority order: non_compliant overrides requires_review overrides compliant.

    Args:
        statuses: List of status strings from each chunk analysis.

    Returns:
        Single merged status string.
    """
    if "non_compliant" in statuses:
        return "non_compliant"
    if "requires_review" in statuses:
        return "requires_review"
    return "compliant"


def _build_violation_objects(
    raw_violations: list[dict],
    document_id: str,
    submission_time: datetime,
    sla_config: dict[str, int],
) -> list[Violation]:
    """
    Convert raw violation dicts from Claude into typed Violation objects.

    SLA deadlines are anchored to the document submission time, not the
    processing completion time.

    Args:
        raw_violations: Deduplicated violation dicts from Claude.
        document_id: Parent document identifier for violation IDs.
        submission_time: When the document was submitted; anchors SLA deadlines.
        sla_config: Mapping of severity to SLA hours.

    Returns:
        List of typed Violation dataclass instances.
    """
    violations: list[Violation] = []

    for index, raw in enumerate(raw_violations):
        severity = raw.get("severity", "low")
        sla_hours = sla_config.get(severity, 168)
        deadline = (submission_time + timedelta(hours=sla_hours)).isoformat()

        violations.append(
            Violation(
                violation_id=f"{document_id}-V{index + 1:04d}",
                document_id=document_id,
                framework=raw.get("framework", ""),
                rule_reference=raw.get("rule_reference", ""),
                description=raw.get("description", ""),
                severity=severity,
                evidence=raw.get("evidence", "")[:MAX_EVIDENCE_CHARS],
                remediation_steps=raw.get("remediation_steps", []),
                sla_deadline=deadline,
            )
        )

    return violations


def _compute_audit_hash(report: ComplianceReport) -> str:
    """
    Compute a SHA-256 audit hash for a compliance report.

    Covers: document_id, overall_status, timestamp, model_version, and the
    full violation list. sort_keys=True ensures deterministic serialisation.

    Args:
        report: The ComplianceReport to hash.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    payload = json.dumps(
        {
            "document_id": report.document_id,
            "status": report.overall_status,
            "timestamp": report.timestamp,
            "model_version": report.model_version,
            "violations": [
                {
                    "violation_id": v.violation_id,
                    "framework": v.framework,
                    "rule_reference": v.rule_reference,
                    "severity": v.severity,
                    "evidence": v.evidence,
                }
                for v in report.violations
            ],
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _require_env(key: str, fallback: str = "") -> str:
    """
    Return an environment variable value, raising if it is absent.

    Args:
        key: Environment variable name.
        fallback: Value to use if the env var is absent (local dev only).

    Returns:
        The resolved value.

    Raises:
        RuntimeError: If neither env var nor fallback provides a value.
    """
    value = os.environ.get(key, fallback)
    if not value:
        raise RuntimeError(
            f"Required environment variable {key!r} is not set and "
            "no config fallback is available. "
            "Check Lambda environment variables or your .env file."
        )
    return value


class ComplianceEngine:
    """
    Orchestrates multi-framework regulatory compliance analysis.

    Manages the Claude API client lifecycle, document chunking, parallel
    chunk analysis, violation deduplication, DynamoDB persistence, SNS
    escalation, and CloudWatch metrics emission.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        """
        Initialise the engine by loading configuration.

        Does not call Secrets Manager or create the Anthropic client at
        construction time. The Anthropic client is lazy-initialised on first
        use so Lambda cold start time is not affected by SM network latency.

        Args:
            config_path: Path to config.yaml. Defaults to configs/config.yaml.

        Raises:
            ValueError: If the configured model name is empty.
        """
        self.cfg = load_config(config_path)
        self.cc = self.cfg["compliance"]
        self.version = "2.0.0"

        model_name = self.cc.get("classification", {}).get("model", "")
        if not model_name:
            raise ValueError(
                "config.yaml classification.model is empty or missing. "
                "Set it to a valid Claude model identifier."
            )

        log.info(
            "ComplianceEngine v%s initialised with model %s",
            self.version,
            model_name,
        )

        self._anthropic_client: anthropic.Anthropic | None = None
        self._client_set_manually: bool = False
        self._client_refreshed_at: float = 0.0

    @property
    def anthropic_client(self) -> anthropic.Anthropic:
        """
        Return the Anthropic client, creating it on first access.

        Defers the Secrets Manager call to the first Claude invocation.
        When a client has been set via the setter (as in tests), the TTL
        refresh path is suppressed so mock clients are never replaced.
        """
        now = time.time()
        client_age_seconds = now - self._client_refreshed_at
        ttl_seconds = 43_200

        should_refresh = (
            self._anthropic_client is None
            or (not self._client_set_manually and client_age_seconds > ttl_seconds)
        )
        if should_refresh:
            self._anthropic_client = self._fetch_anthropic_client()
            self._client_refreshed_at = now

        return self._anthropic_client

    @anthropic_client.setter
    def anthropic_client(self, client: anthropic.Anthropic) -> None:
        """
        Inject an Anthropic client directly.

        Used in tests to inject a MagicMock without triggering Secrets Manager.
        Sets _client_set_manually so the TTL refresh path never replaces it.
        """
        self._anthropic_client = client
        self._client_set_manually = True
        self._client_refreshed_at = time.time()

    def _fetch_anthropic_client(self) -> anthropic.Anthropic:
        """
        Fetch the Anthropic API key from Secrets Manager and return a client.

        Falls back to the ANTHROPIC_API_KEY environment variable when the
        secret is not found or access is denied.

        Returns:
            Authenticated Anthropic client.

        Raises:
            KeyError: If the secret JSON does not contain ANTHROPIC_API_KEY.
            RuntimeError: If no key is found in either Secrets Manager or env.
            ClientError: For unexpected AWS errors.
        """
        try:
            sm_client = boto3.client("secretsmanager", region_name=_AWS_REGION)
            secret_string = sm_client.get_secret_value(
                SecretId=self.cc["secret_name"]
            )["SecretString"]
            secret_data = json.loads(secret_string)

            if "ANTHROPIC_API_KEY" not in secret_data:
                raise KeyError(
                    f"Secret {self.cc['secret_name']!r} does not contain "
                    "ANTHROPIC_API_KEY. Check the secret JSON structure."
                )

            return anthropic.Anthropic(api_key=secret_data["ANTHROPIC_API_KEY"])

        except ClientError as error:
            error_code = error.response["Error"]["Code"]
            if error_code in ("ResourceNotFoundException", "AccessDeniedException"):
                log.warning(
                    "Secrets Manager returned %s; falling back to env var.",
                    error_code,
                )
                api_key = os.environ.get("ANTHROPIC_API_KEY", "")
                if not api_key:
                    raise RuntimeError(
                        "ANTHROPIC_API_KEY not found in Secrets Manager or "
                        "environment. Set the env var for local development."
                    ) from error
                return anthropic.Anthropic(api_key=api_key)
            raise

    def _analyse_single_chunk(
        self,
        chunk_content: str,
        document: ComplianceDocument,
        frameworks: list[str],
    ) -> dict:
        """
        Analyse one document chunk via Claude.

        AuthenticationError is re-raised immediately. A bad API key must
        surface to the DLQ, not silently produce misleading results.

        Args:
            chunk_content: Text content of this document chunk.
            document: The parent ComplianceDocument for context fields.
            frameworks: Framework names to include in the prompt.

        Returns:
            Parsed analysis dict with keys: overall_status, violations,
            compliance_summary, reviewer_notes.
        """
        prompt = _build_analysis_prompt(
            frameworks=frameworks,
            document_type=document.document_type,
            source_system=document.source_system,
            content=chunk_content,
        )
        try:
            response = _call_claude_with_retry(
                client=self.anthropic_client,
                model=self.cc["classification"]["model"],
                max_tokens=self.cc["classification"]["max_tokens"],
                messages=[{"role": "user", "content": prompt}],
            )
            raw_text = response.content[0].text.strip()
            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```[a-z]*\n?", "", raw_text)
                raw_text = re.sub(r"\n?```$", "", raw_text.strip())
            return json.loads(raw_text)

        except anthropic.AuthenticationError:
            raise

        except json.JSONDecodeError as error:
            log.error("Claude returned non-JSON response: %s", error)
            return {
                "overall_status": "requires_review",
                "violations": [],
                "compliance_summary": "LLM returned unparseable response. Manual review required.",
                "reviewer_notes": f"JSON decode error: {error}",
            }

        except Exception as error:
            log.error("Chunk analysis failed: %s", error)
            return {
                "overall_status": "requires_review",
                "violations": [],
                "compliance_summary": "Analysis failed. Manual review required.",
                "reviewer_notes": str(error),
            }

    def analyse_document(self, document: ComplianceDocument) -> ComplianceReport:
        """
        Run multi-framework compliance analysis on a single document.

        Args:
            document: The document to analyse.

        Returns:
            ComplianceReport with violations, status, and audit hash.

        Raises:
            ValueError: If no frameworks are configured.
            anthropic.AuthenticationError: Propagated immediately.
        """
        submission_time = document.submitted_at
        start_time = time.time()

        frameworks = document.frameworks_to_check or [
            f["name"] for f in self.cc["frameworks"]
        ]
        if not frameworks:
            raise ValueError(
                "No frameworks configured. Set frameworks_to_check on the document "
                "or configure at least one framework in config.yaml."
            )

        chunks = _chunk_document(document.content)
        worker_count = min(MAX_CHUNK_WORKERS, len(chunks))

        def analyse_chunk(chunk: str) -> dict:
            return self._analyse_single_chunk(chunk, document, frameworks)

        if worker_count <= 1:
            chunk_results = [analyse_chunk(c) for c in chunks]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
                chunk_results = list(pool.map(analyse_chunk, chunks))

        all_raw_violations: list[dict] = []
        chunk_statuses: list[str] = []
        chunk_summaries: list[str] = []
        chunk_notes: list[str] = []

        for result in chunk_results:
            chunk_statuses.append(result.get("overall_status", "requires_review"))
            all_raw_violations.extend(result.get("violations", []))
            if result.get("compliance_summary"):
                chunk_summaries.append(result["compliance_summary"])
            if result.get("reviewer_notes"):
                chunk_notes.append(result["reviewer_notes"])

        deduplicated = _deduplicate_violations(all_raw_violations)
        merged_status = _merge_chunk_statuses(chunk_statuses)

        violations = _build_violation_objects(
            raw_violations=deduplicated,
            document_id=document.document_id,
            submission_time=submission_time,
            sla_config=self.cc["remediation"]["sla_hours"],
        )

        compliance_summary = (
            " | ".join(chunk_summaries)
            if chunk_summaries
            else f"Analysed {len(chunks)} chunk(s). Status: {merged_status}."
        )
        reviewer_notes = (
            " | ".join(chunk_notes)
            if chunk_notes
            else f"{len(deduplicated)} unique violations found across {len(chunks)} chunks."
        )

        report = ComplianceReport(
            document_id=document.document_id,
            document_type=document.document_type,
            overall_status=merged_status,
            frameworks_checked=frameworks,
            violations=violations,
            compliance_summary=compliance_summary,
            reviewer_notes=reviewer_notes,
            processing_time_ms=(time.time() - start_time) * 1000,
            model_version=self.version,
            timestamp=submission_time.isoformat(),
            audit_hash="",
        )
        report.audit_hash = _compute_audit_hash(report)

        self._save_violations(violations)
        self._save_report(report)

        escalation_error: Exception | None = None
        try:
            self._escalate_critical_violations(violations, document)
            self._route_requires_review(report, document)
        except Exception as error:
            escalation_error = error
            log.error(
                "Escalation failed for document %s: %s",
                document.document_id,
                error,
            )
        finally:
            self._publish_metrics(violations)

        if escalation_error:
            raise escalation_error

        log.info(
            "Document %s analysed: status=%s violations=%d duration_ms=%.0f",
            document.document_id,
            report.overall_status,
            len(violations),
            report.processing_time_ms,
        )
        return report

    def _save_report(self, report: ComplianceReport) -> None:
        """
        Persist the compliance report to DynamoDB.

        Uses attribute_not_exists ConditionExpression so that a redelivered
        SQS message does not overwrite a successfully completed analysis.

        Args:
            report: The ComplianceReport to persist.

        Raises:
            ClientError: For unexpected DynamoDB errors.
        """
        table_name = _require_env("REPORTS_TABLE", self.cc.get("reports_table", ""))
        table = _get_dynamodb().Table(table_name)
        ttl = int(datetime.now(timezone.utc).timestamp()) + (RETENTION_DAYS * 86400)

        try:
            table.put_item(
                Item={
                    "document_id": report.document_id,
                    "timestamp": report.timestamp,
                    "overall_status": report.overall_status,
                    "frameworks": report.frameworks_checked,
                    "violation_count": len(report.violations),
                    "summary": report.compliance_summary,
                    "reviewer_notes": report.reviewer_notes,
                    "model_version": report.model_version,
                    "audit_hash": report.audit_hash,
                    "ttl": ttl,
                },
                ConditionExpression="attribute_not_exists(document_id)",
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
                log.warning(
                    "Report for %s already exists; skipping duplicate SQS delivery.",
                    report.document_id,
                )
            else:
                raise

    def _save_violations(self, violations: list[Violation]) -> None:
        """
        Persist all violations for a document to DynamoDB.

        Collects all failures and raises a composite error after attempting
        all writes so that partial success is maximised on throttle events.

        Args:
            violations: List of Violation objects to persist.

        Raises:
            RuntimeError: If one or more violations failed to persist.
        """
        if not violations:
            return

        table_name = _require_env("VIOLATIONS_TABLE", self.cc.get("violations_table", ""))
        table = _get_dynamodb().Table(table_name)
        ttl = int(datetime.now(timezone.utc).timestamp()) + (RETENTION_DAYS * 86400)
        failures: list[str] = []

        for violation in violations:
            try:
                table.put_item(
                    Item={
                        "violation_id": violation.violation_id,
                        "document_id": violation.document_id,
                        "framework": violation.framework,
                        "rule_reference": violation.rule_reference,
                        "description": violation.description,
                        "severity": violation.severity,
                        "evidence": violation.evidence,
                        "remediation_steps": violation.remediation_steps,
                        "sla_deadline": violation.sla_deadline,
                        "auto_escalated": violation.auto_escalated,
                        "ttl": ttl,
                    },
                    ConditionExpression="attribute_not_exists(violation_id)",
                )
            except ClientError as error:
                code = error.response["Error"]["Code"]
                if code == "ConditionalCheckFailedException":
                    log.warning(
                        "Violation %s already exists; skipping.",
                        violation.violation_id,
                    )
                else:
                    failures.append(f"{violation.violation_id}: {error}")

        if failures:
            raise RuntimeError(
                f"Failed to persist {len(failures)} violation(s): {'; '.join(failures)}"
            )

    def _escalate_critical_violations(
        self,
        violations: list[Violation],
        document: ComplianceDocument,
    ) -> None:
        """
        Publish critical violations to the escalation SNS topic.

        Args:
            violations: All violations for the document.
            document: The source document for context fields.
        """
        critical_violations = [v for v in violations if v.severity == "critical"]
        if not critical_violations:
            return
        if not self.cc["remediation"]["auto_escalate_critical"]:
            return

        topic_arn = os.environ.get("ESCALATION_TOPIC_ARN", "")
        if not topic_arn:
            log.warning(
                "ESCALATION_TOPIC_ARN not configured; skipping escalation for %s.",
                document.document_id,
            )
            return

        raw_subject = f"[CRITICAL] {document.document_id}"
        subject = (
            raw_subject[: SNS_SUBJECT_MAX_LEN - 3] + "..."
            if len(raw_subject) > SNS_SUBJECT_MAX_LEN
            else raw_subject
        )

        _get_sns().publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=json.dumps(
                {
                    "document_id": document.document_id,
                    "document_type": document.document_type,
                    "critical_violations": [
                        {
                            "framework": v.framework,
                            "rule": v.rule_reference,
                            "description": v.description,
                        }
                        for v in critical_violations
                    ],
                    "sla_deadline": critical_violations[0].sla_deadline,
                },
                indent=2,
            ),
            MessageAttributes={
                "severity": {"DataType": "String", "StringValue": "critical"}
            },
        )

        for violation in critical_violations:
            violation.auto_escalated = True

        log.warning(
            "Escalated %d critical violation(s) for document %s.",
            len(critical_violations),
            document.document_id,
        )

    def _route_requires_review(
        self,
        report: ComplianceReport,
        document: ComplianceDocument,
    ) -> None:
        """
        Publish requires_review documents to the analyst review SNS topic.

        Args:
            report: The completed compliance report.
            document: The source document.
        """
        if report.overall_status != "requires_review":
            return

        topic_arn = os.environ.get("REVIEW_TOPIC_ARN", "")
        if not topic_arn:
            log.warning(
                "REVIEW_TOPIC_ARN not configured; no notification sent for %s.",
                document.document_id,
            )
            return

        raw_subject = f"[REVIEW REQUIRED] {document.document_id}"
        subject = (
            raw_subject[: SNS_SUBJECT_MAX_LEN - 3] + "..."
            if len(raw_subject) > SNS_SUBJECT_MAX_LEN
            else raw_subject
        )

        try:
            _get_sns().publish(
                TopicArn=topic_arn,
                Subject=subject,
                Message=json.dumps(
                    {
                        "document_id": document.document_id,
                        "document_type": document.document_type,
                        "submitted_by": document.submitted_by,
                        "submitted_at": document.submitted_at.isoformat(),
                        "reviewer_notes": report.reviewer_notes,
                        "audit_hash": report.audit_hash,
                    },
                    indent=2,
                ),
                MessageAttributes={
                    "status": {"DataType": "String", "StringValue": "requires_review"}
                },
            )
            log.info("Routed document %s to review queue.", document.document_id)
        except Exception as error:
            log.error(
                "Failed to route requires_review for %s: %s",
                document.document_id,
                error,
            )

    def _publish_metrics(self, violations: list[Violation]) -> None:
        """
        Emit compliance metrics to CloudWatch.

        Called in a finally-equivalent block so CloudWatch always receives
        a data point even when SNS escalation raises an exception.

        Args:
            violations: All violations for the current document.
        """
        critical_count = sum(1 for v in violations if v.severity == "critical")
        metric_data = [
            {
                "MetricName": "CriticalViolations",
                "Value": critical_count,
                "Unit": "Count",
                "Dimensions": [],
            },
            {
                "MetricName": "TotalViolations",
                "Value": len(violations),
                "Unit": "Count",
                "Dimensions": [],
            },
        ]

        framework_counts: dict[str, int] = {}
        for violation in violations:
            framework_counts[violation.framework] = (
                framework_counts.get(violation.framework, 0) + 1
            )

        for framework, count in framework_counts.items():
            metric_data.append({
                "MetricName": "ViolationsByFramework",
                "Value": count,
                "Unit": "Count",
                "Dimensions": [{"Name": "Framework", "Value": framework}],
            })

        try:
            _get_cloudwatch().put_metric_data(
                Namespace="Compliance",
                MetricData=metric_data,
            )
        except Exception as error:
            log.error("Failed to publish CloudWatch metrics: %s", error)


_engine: ComplianceEngine | None = None


def _get_engine() -> ComplianceEngine:
    """
    Return the module-level ComplianceEngine singleton.

    Creates the engine on first call (Lambda cold start).

    Returns:
        Singleton ComplianceEngine instance.
    """
    global _engine
    if _engine is None:
        log.info("Cold start: initialising ComplianceEngine v2.0.0.")
        _engine = ComplianceEngine()
    return _engine


def lambda_handler(event: dict, context: object) -> dict:
    """
    AWS Lambda entry point for SQS-triggered compliance analysis.

    Args:
        event: Lambda event dict from SQS trigger.
        context: Lambda context object (unused).

    Returns:
        Dict with batchItemFailures list for SQS partial batch handling.
    """
    engine = _get_engine()
    s3_client = _get_s3()
    failed_items: list[dict] = []

    for record in event.get("Records", []):
        message_id = record.get("messageId")
        if not message_id:
            log.error("SQS record is missing messageId; skipping.")
            continue

        try:
            message = json.loads(record["body"])
            _validate_sqs_message(message)

            bucket = message["bucket"]
            key = message["key"]
            document_id = message["document_id"]
            document_type = message.get("document_type", "regulatory_filing")
            frameworks = message.get(
                "frameworks", [f["name"] for f in engine.cc["frameworks"]]
            )

            if not frameworks:
                raise ValueError(
                    "frameworks list is empty. "
                    "Check the SQS message or config.yaml frameworks list."
                )

            head_response = s3_client.head_object(Bucket=bucket, Key=key)
            if head_response.get("ContentLength", 0) > MAX_DOCUMENT_BYTES:
                raise ValueError(
                    f"Document {key!r} exceeds the {MAX_DOCUMENT_BYTES:,} byte limit."
                )

            content = (
                s3_client.get_object(Bucket=bucket, Key=key)["Body"]
                .read(MAX_DOCUMENT_BYTES)
                .decode("utf-8", errors="replace")
            )

            engine.analyse_document(
                ComplianceDocument(
                    document_id=document_id,
                    document_type=document_type,
                    content=content,
                    source_system=message.get("source_system", "s3"),
                    submitted_by=message.get("submitted_by", "lambda"),
                    submitted_at=datetime.now(timezone.utc),
                    frameworks_to_check=frameworks,
                )
            )

        except Exception as error:
            log.error(
                "Failed to process record %s: %s",
                message_id,
                error,
            )
            failed_items.append({"itemIdentifier": message_id})

    return {"batchItemFailures": failed_items}
"""
sla_checker.py
Scheduled SLA breach detector for the Regulatory Compliance Engine.

Runs hourly via EventBridge. Queries the DynamoDB SeverityIndex GSI for
violations where sla_deadline is in the past and auto_escalated is False,
then publishes one SNS breach notification per violation and emits a
SLABreaches CloudWatch metric.

Deploy as: Lambda compliance-sla-checker
Trigger:   EventBridge rate(1 hour) pointing to sla_checker.lambda_handler
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from datetime import timezone

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)
if not log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(levelname)s | %(name)s | %(message)s")
    )
    log.addHandler(_handler)
    log.setLevel(logging.INFO)
    log.propagate = False

_AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
_VIOLATIONS_TABLE = os.environ.get("VIOLATIONS_TABLE", "compliance-violations")
_ESCALATION_TOPIC_ARN = os.environ.get("ESCALATION_TOPIC_ARN", "")
_SEVERITY_LEVELS = ("critical", "high", "medium", "low")


def _get_dynamodb():
    """Return a boto3 DynamoDB resource for this module."""
    return boto3.resource("dynamodb", region_name=_AWS_REGION)


def _get_sns():
    """Return a boto3 SNS client for this module."""
    return boto3.client("sns", region_name=_AWS_REGION)


def _get_cloudwatch():
    """Return a boto3 CloudWatch client for this module."""
    return boto3.client("cloudwatch", region_name=_AWS_REGION)


def _fetch_breached_violations() -> list[dict]:
    """
    Query DynamoDB SeverityIndex GSI for violations past their SLA deadline.

    Runs a separate query per severity level because the GSI partition key
    must be specified. A DynamoDB error on one severity level is logged and
    skipped rather than aborting the entire scan so partial results are
    still actionable.

    Returns:
        Flat list of DynamoDB violation item dicts across all severity levels.
    """
    table = _get_dynamodb().Table(_VIOLATIONS_TABLE)
    now = datetime.now(timezone.utc).isoformat()
    breached: list[dict] = []

    for severity in _SEVERITY_LEVELS:
        try:
            response = table.query(
                IndexName="SeverityIndex",
                KeyConditionExpression=(
                    "severity = :sev AND sla_deadline < :now"
                ),
                FilterExpression="auto_escalated = :false",
                ExpressionAttributeValues={
                    ":sev": severity,
                    ":now": now,
                    ":false": False,
                },
            )
            breached.extend(response.get("Items", []))
            log.info(
                "SLA scan: severity=%s breached=%d",
                severity,
                len(response.get("Items", [])),
            )
        except ClientError as error:
            log.error(
                "DynamoDB query failed for severity=%s: %s",
                severity,
                error,
            )

    return breached


def _publish_breach_notification(violation: dict) -> None:
    """
    Publish a single SLA breach SNS notification.

    Silently returns when ESCALATION_TOPIC_ARN is not configured so that the
    function works in environments without an SNS topic.

    Args:
        violation: DynamoDB violation item dict.
    """
    if not _ESCALATION_TOPIC_ARN:
        log.error("ESCALATION_TOPIC_ARN not configured; breach notification skipped.")
        return

    document_id = violation.get("document_id", "unknown")
    violation_id = violation.get("violation_id", "unknown")
    severity = violation.get("severity", "unknown")

    raw_subject = f"[SLA BREACH] {severity.upper()} {document_id}"
    subject = raw_subject[:97] + "..." if len(raw_subject) > 100 else raw_subject

    try:
        _get_sns().publish(
            TopicArn=_ESCALATION_TOPIC_ARN,
            Subject=subject,
            Message=json.dumps(
                {
                    "alert_type": "sla_breach",
                    "violation_id": violation_id,
                    "document_id": document_id,
                    "severity": severity,
                    "framework": violation.get("framework"),
                    "rule_reference": violation.get("rule_reference"),
                    "sla_deadline": violation.get("sla_deadline"),
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            ),
            MessageAttributes={
                "alert_type": {"DataType": "String", "StringValue": "sla_breach"},
                "severity": {"DataType": "String", "StringValue": severity},
            },
        )
        log.warning(
            "SLA breach notification published: %s severity=%s",
            violation_id,
            severity,
        )
    except ClientError as error:
        log.error(
            "Failed to publish SLA breach notification for %s: %s",
            violation_id,
            error,
        )


def lambda_handler(event: dict, context: object) -> dict:
    """
    EventBridge scheduled handler for SLA breach detection.

    Args:
        event: EventBridge event dict (unused).
        context: Lambda context object (unused).

    Returns:
        Dict with breaches_found count.
    """
    log.info("SLA checker starting at %s", datetime.now(timezone.utc).isoformat())

    breached = _fetch_breached_violations()

    if not breached:
        log.info("No SLA breaches detected.")
        return {"breaches_found": 0}

    log.warning("Found %d SLA breach(es); publishing notifications.", len(breached))
    for violation in breached:
        _publish_breach_notification(violation)

    try:
        _get_cloudwatch().put_metric_data(
            Namespace="Compliance",
            MetricData=[{
                "MetricName": "SLABreaches",
                "Value": len(breached),
                "Unit": "Count",
                "Dimensions": [],
            }],
        )
    except Exception as error:
        log.error("Failed to publish SLABreaches metric: %s", error)

    return {"breaches_found": len(breached)}
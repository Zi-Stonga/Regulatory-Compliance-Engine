"""
reprocess.py
CLI utility to re-queue failed or requires_review documents to SQS.

Use this after incidents such as API key misconfiguration or SDK incompatibility
where documents received requires_review status without genuine analysis.

Usage:
    python3 -m src.reprocess --dry-run
    python3 -m src.reprocess --status requires_review --older-than-minutes 60
    python3 -m src.reprocess --status requires_review --queue-url https://sqs...
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)

_AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
_REPORTS_TABLE = os.environ.get("REPORTS_TABLE", "compliance-reports")
_DOCS_BUCKET = os.environ.get("DOCS_BUCKET", "")
_QUEUE_URL = os.environ.get("DOCUMENT_QUEUE_URL", "")


def _fetch_matching_reports(status: str, older_than_minutes: int) -> list[dict]:
    """
    Scan compliance-reports for documents matching a status and age filter.

    Uses ExpressionAttributeNames to avoid collision with the DynamoDB
    reserved word 'timestamp'. Paginates via LastEvaluatedKey so that tables
    larger than the 1 MB DynamoDB scan page are fully traversed.

    Args:
        status: overall_status value to filter on.
        older_than_minutes: Only return documents older than this many minutes.

    Returns:
        List of DynamoDB item dicts matching the filter criteria.
    """
    ddb = boto3.resource("dynamodb", region_name=_AWS_REGION)
    table = ddb.Table(_REPORTS_TABLE)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=older_than_minutes)).isoformat()

    log.info(
        "Scanning %s for status=%r older than %d minutes (before %s).",
        _REPORTS_TABLE,
        status,
        older_than_minutes,
        cutoff,
    )

    items: list[dict] = []
    scan_kwargs: dict = {
        "FilterExpression": "overall_status = :s AND #ts < :cutoff",
        "ExpressionAttributeValues": {":s": status, ":cutoff": cutoff},
        "ExpressionAttributeNames": {"#ts": "timestamp"},
    }

    while True:
        response = table.scan(**scan_kwargs)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            break
        scan_kwargs["ExclusiveStartKey"] = last_key

    log.info("Found %d matching document(s).", len(items))
    return items


def _requeue_document(report: dict, queue_url: str, is_dry_run: bool) -> bool:
    """
    Send one document back to SQS for reprocessing.

    Sets submitted_by and source_system to identify reprocessed documents
    in the audit trail. Infers the S3 key from document_id by convention.

    Args:
        report: DynamoDB report item dict.
        queue_url: SQS queue URL to send to.
        is_dry_run: When True, logs the action without sending.

    Returns:
        True on success or dry run, False on send failure.
    """
    document_id = report.get("document_id", "")
    document_type = report.get("document_type", "regulatory_filing")

    message = {
        "document_id": document_id,
        "bucket": _DOCS_BUCKET,
        "key": f"documents/{document_id}.txt",
        "document_type": document_type,
        "submitted_by": "reprocess-utility",
        "source_system": "reprocess",
    }

    if is_dry_run:
        log.info("[DRY RUN] Would requeue: %s", document_id)
        return True

    try:
        boto3.client("sqs", region_name=_AWS_REGION).send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(message),
        )
        log.info("Requeued: %s", document_id)
        return True
    except ClientError as error:
        log.error("Failed to requeue %s: %s", document_id, error)
        return False


def main() -> int:
    """
    CLI entry point for the reprocess utility.

    Returns:
        Exit code: 0 for success, 1 for configuration error or partial failure.
    """
    parser = argparse.ArgumentParser(
        description="Re-queue compliance documents for reprocessing."
    )
    parser.add_argument(
        "--status",
        default="requires_review",
        choices=["requires_review", "non_compliant", "compliant"],
        help="Document status to reprocess (default: requires_review).",
    )
    parser.add_argument(
        "--older-than-minutes",
        type=int,
        default=60,
        dest="minutes",
        help="Only reprocess documents older than N minutes (default: 60).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="is_dry_run",
        help="Preview which documents would be requeued without sending.",
    )
    parser.add_argument(
        "--queue-url",
        dest="queue_url",
        default=_QUEUE_URL,
        help="SQS queue URL. Defaults to DOCUMENT_QUEUE_URL env var.",
    )
    args = parser.parse_args()

    if not args.queue_url and not args.is_dry_run:
        log.error(
            "Set DOCUMENT_QUEUE_URL or pass --queue-url, or use --dry-run to preview."
        )
        return 1

    if not _DOCS_BUCKET and not args.is_dry_run:
        log.error("Set DOCS_BUCKET env var before requeuing.")
        return 1

    reports = _fetch_matching_reports(args.status, args.minutes)

    if not reports:
        log.info("No documents to reprocess.")
        return 0

    print(f"\nFound {len(reports)} document(s) with status={args.status!r}:")
    for report in reports:
        print(f"  {report.get('document_id')}  {report.get('timestamp')}")

    if args.is_dry_run:
        print(f"\n[DRY RUN] Would requeue {len(reports)} document(s).")
        return 0

    confirmation = input(f"\nRequeue {len(reports)} document(s)? [y/N] ").strip().lower()
    if confirmation != "y":
        print("Aborted.")
        return 0

    success_count = sum(
        1
        for report in reports
        if _requeue_document(report, args.queue_url, args.is_dry_run)
    )
    log.info("Requeued %d of %d document(s).", success_count, len(reports))
    return 0 if success_count == len(reports) else 1


if __name__ == "__main__":
    sys.exit(main())
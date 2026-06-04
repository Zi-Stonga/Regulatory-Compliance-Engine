"""
Regulatory Compliance Engine.

Public API surface for the src package.

Additional modules available for direct invocation:
    src.sla_checker    - EventBridge scheduled SLA breach detector
    src.reprocess      - CLI utility to re-queue failed documents
"""
from .compliance_engine import (
    ComplianceDocument,
    ComplianceEngine,
    ComplianceReport,
    Violation,
    lambda_handler,
    load_config,
)

__version__ = "2.0.0"

__all__ = [
    "ComplianceDocument",
    "ComplianceEngine",
    "ComplianceReport",
    "Violation",
    "lambda_handler",
    "load_config",
]

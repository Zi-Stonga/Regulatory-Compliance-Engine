"""CDK application entry point for the Regulatory Compliance Engine."""
import aws_cdk as cdk
from cdk_stack import RegulatoryComplianceStack

app = cdk.App()
RegulatoryComplianceStack(
    app,
    "RegulatoryComplianceStack",
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region="us-east-1",
    ),
)
app.synth()

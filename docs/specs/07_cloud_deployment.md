# Cloud Deployment

## Prerequisites

- AWS CLI configured with CDK bootstrap permissions
- AWS CDK v2: npm install -g aws-cdk
- Node.js 18+
- Python 3.12+
- Anthropic API key

## First-time setup

Create the Secrets Manager secret before deploying.

aws secretsmanager create-secret   --name compliance/anthropic-api-key   --secret-string ANTHROPIC_API_KEY=your-key-here

Bootstrap CDK (first time only per account and region):

export AWS_ACCOUNT_ID=467350349576
cd infra
pip install -r requirements-cdk.txt
cdk bootstrap aws://AWS_ACCOUNT_ID/us-east-1

## Deploy

cdk deploy RegulatoryComplianceStack

## Stack outputs

DocumentQueueUrl: SQS queue for document messages
BucketName: S3 bucket for document uploads
EscalationTopicArn: SNS for critical violations and alarms
ReviewTopicArn: SNS for requires_review documents

## Subscribe ops team

aws sns subscribe   --topic-arn ESCALATION_TOPIC_ARN   --protocol email   --notification-endpoint ops@yourcompany.com

## IAM policies

Before deploying policies/iam_policies.json replace all occurrences of
ACCOUNT_ID_HERE and REGION_HERE with your AWS account ID and region.

## Teardown

cd infra && cdk destroy RegulatoryComplianceStack

DynamoDB tables and S3 bucket survive teardown (RemovalPolicy.RETAIN).
S3 Object Lock COMPLIANCE mode prevents object deletion within retention period.
Use a separate bucket for integration testing.

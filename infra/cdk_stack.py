"""
cdk_stack.py
AWS infrastructure for the Regulatory Compliance Engine v2.0.0.

All resources defined here. One cdk deploy creates the full environment.
RemovalPolicy.RETAIN on DynamoDB and S3 protects data during stack teardown.
"""
from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_dynamodb as dynamodb,
    aws_ec2 as ec2,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_kms as kms,
    aws_lambda as lambda_,
    aws_lambda_event_sources as lambda_events,
    aws_logs as logs,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    aws_sns as sns,
    aws_sqs as sqs,
)
from constructs import Construct


class RegulatoryComplianceStack(Stack):
    """
    Full AWS infrastructure stack for the Regulatory Compliance Engine.

    Provisions: KMS CMK, VPC, SQS queues, S3 bucket with Object Lock,
    DynamoDB tables, SNS topics, IAM role, Lambda function, CloudWatch
    alarms and dashboard, and an EventBridge rule for the SLA checker.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        encryption_key = kms.Key(
            self,
            "ComplianceKey",
            description="Compliance data encryption key with annual rotation.",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
        )

        vpc = ec2.Vpc(
            self,
            "ComplianceVPC",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
            ],
        )

        vpc.add_flow_log(
            "VpcFlowLog",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                logs.LogGroup(
                    self,
                    "VpcFlowLogGroup",
                    log_group_name=f"/vpc-flow-logs/{construct_id}",
                    retention=logs.RetentionDays.TEN_YEARS,
                    removal_policy=RemovalPolicy.RETAIN,
                ),
            ),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )

        lambda_sg = ec2.SecurityGroup(
            self,
            "LambdaSG",
            vpc=vpc,
            description="Compliance Lambda SG. HTTPS/443 egress only.",
            allow_all_outbound=False,
        )
        lambda_sg.add_egress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(443),
            "HTTPS to AWS services and Anthropic API via NAT.",
        )

        dead_letter_queue = sqs.Queue(
            self,
            "ComplianceDLQ",
            queue_name="compliance-docs-dlq",
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=encryption_key,
            retention_period=Duration.days(14),
        )

        document_queue = sqs.Queue(
            self,
            "ComplianceDocQueue",
            queue_name="compliance-docs",
            encryption=sqs.QueueEncryption.KMS,
            encryption_master_key=encryption_key,
            visibility_timeout=Duration.seconds(1800),
            dead_letter_queue=sqs.DeadLetterQueue(
                queue=dead_letter_queue,
                max_receive_count=3,
            ),
        )

        docs_bucket = s3.Bucket(
            self,
            "ComplianceDocs",
            bucket_name=f"regulatory-compliance-{self.account}",
            encryption=s3.BucketEncryption.KMS,
            encryption_key=encryption_key,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            object_lock_enabled=True,
            object_lock_default_retention=s3.ObjectLockRetention.compliance(
                Duration.days(3653)
            ),
            removal_policy=RemovalPolicy.RETAIN,
        )

        reports_table = dynamodb.Table(
            self,
            "ComplianceReports",
            table_name="compliance-reports",
            partition_key=dynamodb.Attribute(
                name="document_id",
                type=dynamodb.AttributeType.STRING,
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=encryption_key,
            point_in_time_recovery=True,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN,
        )

        violations_table = dynamodb.Table(
            self,
            "ComplianceViolations",
            table_name="compliance-violations",
            partition_key=dynamodb.Attribute(
                name="violation_id",
                type=dynamodb.AttributeType.STRING,
            ),
            sort_key=dynamodb.Attribute(
                name="document_id",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=encryption_key,
            point_in_time_recovery=True,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN,
        )
        violations_table.add_global_secondary_index(
            index_name="SeverityIndex",
            partition_key=dynamodb.Attribute(
                name="severity",
                type=dynamodb.AttributeType.STRING,
            ),
            sort_key=dynamodb.Attribute(
                name="sla_deadline",
                type=dynamodb.AttributeType.STRING,
            ),
        )

        escalation_topic = sns.Topic(
            self,
            "ComplianceEscalations",
            topic_name="compliance-escalations-sns",
            master_key=encryption_key,
        )

        review_topic = sns.Topic(
            self,
            "ComplianceReview",
            topic_name="compliance-review-sns",
            master_key=encryption_key,
        )

        api_key_secret = secretsmanager.Secret.from_secret_complete_arn(
            self,
            "AnthropicKey",
            secret_complete_arn=(
                f"arn:aws:secretsmanager:{self.region}:{self.account}"
                ":secret:compliance/anthropic-api-key"
            ),
        )

        lambda_role = iam.Role(
            self,
            "ComplianceLambdaRole",
            role_name="compliance-engine-lambda-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Least-privilege execution role for the compliance Lambda.",
        )
        lambda_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaVPCAccessExecutionRole"
            )
        )

        document_queue.grant_consume_messages(lambda_role)
        encryption_key.grant_encrypt_decrypt(lambda_role)
        docs_bucket.grant_read(lambda_role)
        reports_table.grant_read_write_data(lambda_role)
        violations_table.grant_write_data(lambda_role)
        escalation_topic.grant_publish(lambda_role)
        review_topic.grant_publish(lambda_role)
        api_key_secret.grant_read(lambda_role)

        lambda_role.add_to_principal_policy(
            iam.PolicyStatement(
                sid="CloudWatchPutMetricsComplianceOnly",
                effect=iam.Effect.ALLOW,
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
                conditions={"StringEquals": {"cloudwatch:namespace": "Compliance"}},
            )
        )

        escalation_topic.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowComplianceLambdaPublish",
                effect=iam.Effect.ALLOW,
                principals=[iam.ArnPrincipal(lambda_role.role_arn)],
                actions=["sns:Publish"],
                resources=[escalation_topic.topic_arn],
            )
        )

        log_group = logs.LogGroup(
            self,
            "ComplianceLogs",
            log_group_name="/compliance/lambda",
            retention=logs.RetentionDays.TEN_YEARS,
            encryption_key=encryption_key,
            removal_policy=RemovalPolicy.RETAIN,
        )

        compliance_lambda = lambda_.Function(
            self,
            "ComplianceEngine",
            function_name="compliance-engine",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="src.compliance_engine.lambda_handler",
            code=lambda_.Code.from_asset(
                "..",
                exclude=[
                    ".venv/**", "venv/**", "cdk.out/**", ".cdk.staging/**",
                    "infra/**", "tests/**", "**/__pycache__/**", "**/*.pyc",
                    ".git/**", "*.md", ".env", ".env.*", "htmlcov/**",
                    ".coverage", "requirements.txt", "requirements-runtime.txt",
                    "setup.py", "pytest.ini", "policies/**", "docs/**",
                ],
            ),
            timeout=Duration.seconds(300),
            memory_size=1024,
            role=lambda_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[lambda_sg],
            log_group=log_group,
            environment={
                "REPORTS_TABLE": reports_table.table_name,
                "VIOLATIONS_TABLE": violations_table.table_name,
                "ESCALATION_TOPIC_ARN": escalation_topic.topic_arn,
                "REVIEW_TOPIC_ARN": review_topic.topic_arn,
                "DOCS_BUCKET": docs_bucket.bucket_name,
                "SECRET_NAME": "compliance/anthropic-api-key",
            },
            reserved_concurrent_executions=10,
            tracing=lambda_.Tracing.ACTIVE,
        )

        compliance_lambda.add_event_source(
            lambda_events.SqsEventSource(
                document_queue,
                batch_size=1,
                max_batching_window=Duration.seconds(30),
                report_batch_item_failures=True,
            )
        )

        sla_checker_lambda = lambda_.Function(
            self,
            "SLAChecker",
            function_name="compliance-sla-checker",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="src.sla_checker.lambda_handler",
            code=lambda_.Code.from_asset(".."),
            timeout=Duration.minutes(5),
            memory_size=512,
            role=lambda_role,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[lambda_sg],
            environment={
                "VIOLATIONS_TABLE": violations_table.table_name,
                "ESCALATION_TOPIC_ARN": escalation_topic.topic_arn,
            },
        )
        violations_table.grant_read_data(sla_checker_lambda)
        escalation_topic.grant_publish(sla_checker_lambda)

        events.Rule(
            self,
            "SLACheckerSchedule",
            schedule=events.Schedule.rate(Duration.hours(1)),
            targets=[targets.LambdaFunction(sla_checker_lambda)],
        )

        cloudwatch.Alarm(
            self,
            "CriticalViolationsAlarm",
            metric=cloudwatch.Metric(
                namespace="Compliance",
                metric_name="CriticalViolations",
                statistic="Sum",
                period=Duration.minutes(5),
            ),
            threshold=1,
            evaluation_periods=2,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            alarm_description="Critical compliance violation detected. 4-hour SLA is active.",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(escalation_topic))

        cloudwatch.Alarm(
            self,
            "DLQDepthAlarm",
            metric=dead_letter_queue.metric_approximate_number_of_messages_visible(),
            threshold=1,
            evaluation_periods=1,
            alarm_description="Compliance DLQ has messages. Processing failed after 3 retries.",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(escalation_topic))

        cloudwatch.Alarm(
            self,
            "DynamoDBWriteStormAlarm",
            metric=violations_table.metric_consumed_write_capacity_units(
                period=Duration.minutes(5),
                statistic="Sum",
            ),
            threshold=10000,
            evaluation_periods=1,
            alarm_description="DynamoDB violations table write surge. Possible runaway processor.",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        ).add_alarm_action(cw_actions.SnsAction(escalation_topic))

        dashboard = cloudwatch.Dashboard(
            self,
            "ComplianceDashboard",
            dashboard_name="RegulatoryCompliance",
        )
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Violations",
                left=[
                    cloudwatch.Metric(
                        namespace="Compliance",
                        metric_name="CriticalViolations",
                        statistic="Sum",
                        period=Duration.hours(1),
                    ),
                    cloudwatch.Metric(
                        namespace="Compliance",
                        metric_name="TotalViolations",
                        statistic="Sum",
                        period=Duration.hours(1),
                    ),
                ],
                width=12,
            ),
            cloudwatch.GraphWidget(
                title="DLQ Depth",
                left=[
                    dead_letter_queue.metric_approximate_number_of_messages_visible(
                        period=Duration.minutes(5)
                    )
                ],
                width=12,
            ),
        )

        CfnOutput(self, "DocumentQueueUrl", value=document_queue.queue_url)
        CfnOutput(self, "BucketName", value=docs_bucket.bucket_name)
        CfnOutput(self, "EscalationTopicArn", value=escalation_topic.topic_arn)
        CfnOutput(self, "ReviewTopicArn", value=review_topic.topic_arn)
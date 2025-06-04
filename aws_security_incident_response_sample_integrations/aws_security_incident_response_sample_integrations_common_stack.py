from os import path
from aws_cdk import (
    CfnParameter,
    Duration,
    RemovalPolicy,
    Stack,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_lambda,
    aws_lambda_python_alpha as py_lambda,
    aws_dynamodb as dynamodb,
    aws_events as events,
    aws_logs,
    aws_sqs,
)
from .event_bus_logger_construct import EventBusLoggerConstruct
from cdk_nag import NagSuppressions
from constructs import Construct
from .constants import SECURITY_IR_EVENT_SOURCE

class AwsSecurityIncidentResponseSampleIntegrationsCommonStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create log level parameter
        self.log_level_param = CfnParameter(
            self,
            "logLevel",
            type="String",
            description="The log level for Lambda functions (info or debug). Error logs are always enabled.",
            allowed_values=["info", "debug", "error"],
            default="error"
        )
        
        # Create DynamoDB table
        self.table = dynamodb.Table(
            self,
            "IncidentsTable",
            partition_key=dynamodb.Attribute(
                name="PK", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
        )
        
        # Create a custom event bus for security incident events
        self.event_bus = events.EventBus(
            self,
            "SecurityIncidentEventBus",
            event_bus_name="security-incident-event-bus",
        )
        
        # Create an EventBusLogger to log all events from the event bus to CloudWatch Logs
        self.event_bus_logger = EventBusLoggerConstruct(
            self,
            "SecurityIncidentEventBusLogger",
            event_bus=self.event_bus,
            log_group_name=f"/aws/events/{self.event_bus.event_bus_name}",
            log_retention=aws_logs.RetentionDays.ONE_WEEK
        )
        
        # Create Lambda layers
        self.domain_layer = aws_lambda.LayerVersion(
            self,
            "DomainLayer",
            code=aws_lambda.Code.from_asset(
                path.join(path.dirname(__file__), "..", "assets/domain"),
            ),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_13],
            description="Layer containing domain models for security incident response",
        )

        self.mappers_layer = aws_lambda.LayerVersion(
            self,
            "MappersLayer",
            code=aws_lambda.Code.from_asset(
                path.join(path.dirname(__file__), "..", "assets/mappers"),
            ),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_13],
            description="Layer containing field mappers for security incident response",
        )
        
        self.wrappers_layer = aws_lambda.LayerVersion(
            self,
            "WrappersLayer",
            code=aws_lambda.Code.from_asset(
                path.join(path.dirname(__file__), "..", "assets/wrappers"),
            ),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_13],
            description="Layer containing field mappers for security incident response",
        )
        
        # Create security incident response poller
        poller_role = aws_iam.Role(
            self,
            "SecurityIncidentResponsePollerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Poller Lambda function"
        )
        
        poller_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ]
            )
        )
        
        self.poller = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponsePoller",
            entry=path.join(path.dirname(__file__), "..", "assets/security_ir_poller"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.millis(30000),
            layers=[self.domain_layer],
            environment={
                "INCIDENTS_TABLE_NAME": self.table.table_name,
                "EVENT_BUS_NAME": self.event_bus.event_bus_name,
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "LOG_LEVEL": self.log_level_param.value_as_string
            },
            role=poller_role
        )

        aws_events.Rule(
            self,
            "SecurityIncidentResponsePollerRule",
            schedule=aws_events.Schedule.rate(duration=Duration.minutes(1)),
            targets=[aws_events_targets.LambdaFunction(self.poller)],
        )

        self.poller.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:GetCase",
                    "security-ir:UpdateCase",
                    "security-ir:ListCases",
                    "security-ir:CreateCase",
                    "security-ir:ListComments",
                    "events:PutEvents",
                    "events:DescribeRule",
                    "events:ListRules",
                    "events:PutRule",
                    "lambda:GetFunctionConfiguration",
                    "lambda:UpdateFunctionConfiguration",
                ],
                resources=["*"],
            )
        )

        self.poller.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["events:PutEvents"],
                resources=[self.event_bus.event_bus_arn],
            )
        )

        self.table.grant_read_write_data(self.poller)
        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            self.poller,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir, events, and lambda actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )
        
        # Add stack-level suppressions for all resources
        NagSuppressions.add_stack_suppressions(
            self,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Built-in LogRetention Lambda role requires AWSLambdaBasicExecutionRole managed policy"
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Built-in LogRetention Lambda and EventBusLogger need these permissions to manage logs",
                    "applies_to": ["Resource::*", "Action::logs:*"]
                },
                {
                    "id": "AwsSolutions-SQS3",
                    "reason": "DLQs are used appropriately in the architecture and don't need their own DLQs"
                },
                {
                    "id": "AwsSolutions-L1",
                    "reason": "Using the latest available runtime for Python (3.13)"
                }
            ]
        )
        
        # Add direct suppressions to the EventBusLogger construct
        NagSuppressions.add_resource_suppressions(
            self.event_bus_logger,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "EventBusLogger requires these permissions to log events to CloudWatch",
                    "applies_to": ["Resource::*", "Action::logs:*"]
                },
                {
                    "id": "AwsSolutions-SQS3",
                    "reason": "This is a DLQ for the EventBusLogger and doesn't need its own DLQ"
                }
            ],
            True
        )
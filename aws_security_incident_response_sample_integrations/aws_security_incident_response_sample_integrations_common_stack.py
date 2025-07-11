from os import path
from aws_cdk import (
    CfnOutput,
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
from .constants import SECURITY_IR_EVENT_SOURCE, JIRA_EVENT_SOURCE

class AwsSecurityIncidentResponseSampleIntegrationsCommonStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        """
        cdk for log_level_parameter
        """
        # Create log level parameter
        self.log_level_param = CfnParameter(
            self,
            "logLevel",
            type="String",
            description="The log level for Lambda functions (info or debug). Error logs are always enabled.",
            allowed_values=["info", "debug", "error"],
            default="error"
        )
        
        """
        cdk for dynamoDb
        """
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
        
        """
        cdk for event_bus
        """
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
        
        """
        cdk for lambda_layers
        """
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
        
        """
        cdk for assets/security_ir_poller
        """
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
            timeout=Duration.minutes(15),
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
        
        """
        cdk for assets/security_ir_client
        """
        # Create a custom role for the Security IR Client Lambda function
        security_ir_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Client Lambda function"
        )
        
        # Add custom policy for CloudWatch Logs permissions
        security_ir_client_role.add_to_policy(
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
        
        security_ir_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseClient",
            entry=path.join(path.dirname(__file__), "..", "assets/security_ir_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(15),
            layers=[self.domain_layer, self.mappers_layer, self.wrappers_layer],
            environment={
                "JIRA_EVENT_SOURCE": JIRA_EVENT_SOURCE,
                # Add ServiceNow event source
                "INCIDENTS_TABLE_NAME": self.table.table_name
            },
            role=security_ir_client_role
        )
        
        # create Event Bridge rule for Security Incident Response Client Lambda function
        security_ir_client_rule = aws_events.Rule(
            self,
            "security-ir-client-rule",
            description="Rule to send all events to Security Incident Response Client lambda function",
            event_pattern=aws_events.EventPattern(source=[JIRA_EVENT_SOURCE]),
            event_bus=self.event_bus,
        )
        security_ir_client_rule.add_target(aws_events_targets.LambdaFunction(security_ir_client))
        
        # Add permissions for Security IR API
        security_ir_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "dynamodb:PutItem", 
                    "dynamodb:GetItem", 
                    "dynamodb:UpdateItem",
                    "security-ir:UpdateCase",
                    "security-ir:CreateCaseComment",
                    "security-ir:UpdateCaseComment",
                    "security-ir:UpdateCaseStatus",
                    "security-ir:ListComments",
                    "security-ir:GetCase",
                    "security-ir:CreateCase",
                    "security-ir:CloseCase",
                    "security-ir:GetCaseAttachmentUploadUrl"
                ],
                resources=["*"],
            )
        )
        
        # Grant specific DynamoDB permissions instead of full access
        self.table.grant_read_write_data(security_ir_client)
        
        CfnOutput(
            self,
            "SecurityIRClientLambdaArn",
            value=security_ir_client.function_arn,
            description="Security Incident Response Client Lambda Function ARN",
        )
        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            security_ir_client,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for DynamoDB actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )
        
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
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
)
from .event_bus_logger_construct import EventBusLoggerConstruct
from cdk_nag import NagSuppressions
from constructs import Construct
from .constants import (
    SECURITY_IR_EVENT_SOURCE,
    JIRA_EVENT_SOURCE,
    SERVICE_NOW_EVENT_SOURCE,
    SLACK_EVENT_SOURCE,
)


class AwsSecurityIncidentResponseSampleIntegrationsCommonStack(Stack):
    """AWS CDK Stack for common Security Incident Response integration resources.

    This stack creates shared infrastructure components including DynamoDB table,
    EventBridge event bus, Lambda layers, and the Security IR client Lambda function.
    """

    def __init__(
        self, scope: Construct, construct_id: str, service_now_params=None, **kwargs
    ) -> None:
        """Initialize the common stack.

        Args:
            scope (Construct): The scope in which to define this construct
            construct_id (str): The scoped construct ID
            service_now_params (dict, optional): ServiceNow configuration parameters
            **kwargs: Additional keyword arguments passed to Stack
        """
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
            default="error",
        )

        # Create integration module parameter
        self.integration_module_param = CfnParameter(
            self,
            "integrationModule",
            type="String",
            description="Integration module type ('itsm' or 'ir')",
            allowed_values=["itsm", "ir"],
            default="itsm",
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
            log_retention=aws_logs.RetentionDays.ONE_WEEK,
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
            description="Custom role for Security Incident Response Poller Lambda function",
        )

        poller_role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
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
                "LOG_LEVEL": self.log_level_param.value_as_string,
            },
            role=poller_role,
        )

        self.poller_rule = aws_events.Rule(
            self,
            "SecurityIncidentResponsePollerRule",
            schedule=aws_events.Schedule.rate(duration=Duration.minutes(1)),
            targets=[aws_events_targets.LambdaFunction(self.poller)],
            enabled=False,  # Start disabled
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
            description="Custom role for Security Incident Response Client Lambda function",
        )

        # Add basic execution role permissions
        security_ir_client_role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole"
            )
        )

        # Build environment variables for security_ir_client
        environment_vars = {
            "JIRA_EVENT_SOURCE": JIRA_EVENT_SOURCE,
            "SERVICE_NOW_EVENT_SOURCE": SERVICE_NOW_EVENT_SOURCE,
            "INCIDENTS_TABLE_NAME": self.table.table_name,
            "LOG_LEVEL": self.log_level_param.value_as_string,
            "INTEGRATION_MODULE": self.integration_module_param.value_as_string,
        }

        # Add ServiceNow environment variables if provided
        if service_now_params:
            environment_vars.update(
                {
                    "SERVICE_NOW_INSTANCE_ID": service_now_params[
                        "instance_id_param_name"
                    ],
                    "SERVICE_NOW_CLIENT_ID": service_now_params.get("client_id_param_name", ""),
                    "SERVICE_NOW_CLIENT_SECRET_ARN": "/SecurityIncidentResponse/serviceNowClientSecretArn",  # SSM param containing secret ARN
                    "SERVICE_NOW_USER_ID": service_now_params.get("user_id_param_name", ""),
                    "PRIVATE_KEY_ASSET_BUCKET": service_now_params.get("private_key_asset_bucket_param_name", ""),
                    "PRIVATE_KEY_ASSET_KEY": service_now_params.get("private_key_asset_key_param_name", ""),
                }
            )

        self.security_ir_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseClient",
            entry=path.join(path.dirname(__file__), "..", "assets/security_ir_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(15),
            layers=[self.domain_layer, self.mappers_layer, self.wrappers_layer],
            environment={
                **environment_vars,
                "SLACK_EVENT_SOURCE": SLACK_EVENT_SOURCE,
            },
            role=security_ir_client_role,
        )

        # create Event Bridge rule for Security Incident Response Client Lambda function
        security_ir_client_rule = aws_events.Rule(
            self,
            "security-ir-client-rule",
            description="Rule to send all events to Security Incident Response Client lambda function",
            event_pattern=aws_events.EventPattern(
                source=[JIRA_EVENT_SOURCE, SERVICE_NOW_EVENT_SOURCE, SLACK_EVENT_SOURCE]
            ),
            event_bus=self.event_bus,
        )
        security_ir_client_rule.add_target(
            aws_events_targets.LambdaFunction(self.security_ir_client)
        )

        # Add permissions for Security IR API
        self.security_ir_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:UpdateCase",
                    "security-ir:CreateCaseComment",
                    "security-ir:UpdateCaseComment",
                    "security-ir:UpdateCaseStatus",
                    "security-ir:ListComments",
                    "security-ir:GetCase",
                    "security-ir:CreateCase",
                    "security-ir:CloseCase",
                    "security-ir:GetCaseAttachmentUploadUrl",
                ],
                resources=["*"],
            )
        )

        # Add S3 permissions for attachment upload via presigned URLs
        self.security_ir_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "s3:PutObject",
                    "s3:PutObjectAcl",
                ],
                resources=["arn:aws:s3:::security-ir-*/*"],
            )
        )

        # Add SSM permissions for ServiceNow parameters if provided
        if service_now_params:
            ssm_resources = [f"arn:aws:ssm:{self.region}:{self.account}:parameter{service_now_params['instance_id_param_name']}"]
            
            # Add OAuth parameters if they exist (excluding client_secret which is now in Secrets Manager)
            for param_key in ['client_id_param_name', 'user_id_param_name', 'private_key_asset_bucket_param_name', 'private_key_asset_key_param_name']:
                if param_key in service_now_params and service_now_params[param_key]:
                    ssm_resources.append(f"arn:aws:ssm:{self.region}:{self.account}:parameter{service_now_params[param_key]}")
            
            # Add SSM parameter for client secret ARN
            ssm_resources.append(f"arn:aws:ssm:{self.region}:{self.account}:parameter/SecurityIncidentResponse/serviceNowClientSecretArn")
            
            self.security_ir_client.add_to_role_policy(
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["ssm:GetParameter"],
                    resources=ssm_resources,
                )
            )
            
            # Add Secrets Manager permissions with wildcard to avoid cyclic dependency
            # Wildcard is required because the secret is created in ServiceNow stack, and referencing
            # its specific ARN here would create a circular dependency between common and ServiceNow stacks
            self.security_ir_client.add_to_role_policy(
                aws_iam.PolicyStatement(
                    effect=aws_iam.Effect.ALLOW,
                    actions=["secretsmanager:GetSecretValue"],
                    resources=[f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:*"],
                )
            )
            
            # Add S3 permissions for ServiceNow private key if bucket is specified
            if service_now_params.get('private_key_asset_bucket_param_name'):
                # Get bucket name from SSM parameter and construct specific S3 ARN
                bucket_param_name = service_now_params['private_key_asset_bucket_param_name']
                key_param_name = service_now_params.get('private_key_asset_key_param_name', '/SecurityIncidentResponse/privateKeyAssetKey')
                
                self.security_ir_client.add_to_role_policy(
                    aws_iam.PolicyStatement(
                        effect=aws_iam.Effect.ALLOW,
                        actions=["s3:GetObject"],
                        resources=[
                            f"arn:aws:s3:::snow-key-{self.account}/private.key"
                        ],
                    )
                )
                
                # Add KMS decrypt permissions for S3 objects using AWS-managed S3 key
                self.security_ir_client.add_to_role_policy(
                    aws_iam.PolicyStatement(
                        effect=aws_iam.Effect.ALLOW,
                        actions=["kms:Decrypt"],
                        resources=[f"arn:aws:kms:{self.region}:{self.account}:alias/aws/s3"],
                    )
                )

        # Grant specific DynamoDB permissions instead of full access
        self.table.grant_read_write_data(self.security_ir_client)

        CfnOutput(
            self,
            "SecurityIRClientLambdaArn",
            value=self.security_ir_client.function_arn,
            description="Security Incident Response Client Lambda Function ARN",
        )

        # Add suppressions for IAM5 findings related to wildcard resources
        suppressions = [
            {
                "id": "AwsSolutions-IAM5",
                "reason": "Wildcard resources are required for security-ir actions",
                "applies_to": ["Resource::*"],
            }
        ]

        # Add SSM suppression if ServiceNow parameters are provided
        if service_now_params:
            suppressions.extend([
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "SSM parameter access required for ServiceNow integration",
                    "applies_to": [
                        "Resource::arn:aws:ssm:*:*:parameter/SecurityIncidentResponse/*"
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Secrets Manager wildcard required to avoid cyclic dependency between stacks",
                    "applies_to": [
                        "Resource::arn:aws:secretsmanager:*:*:secret:*"
                    ],
                }
            ])

        NagSuppressions.add_resource_suppressions(
            self.security_ir_client,
            suppressions,
            True,
        )

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            self.poller,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir, events, and lambda actions",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        # Add suppressions for poller role policy
        NagSuppressions.add_resource_suppressions(
            poller_role,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Poller role requires AWSLambdaBasicExecutionRole managed policy for CloudWatch Logs",
                    "applies_to": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir actions which don't support resource-level permissions",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        # Add suppressions for security IR client role policy
        NagSuppressions.add_resource_suppressions(
            security_ir_client_role,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Security IR client role requires AWSLambdaBasicExecutionRole managed policy for CloudWatch Logs",
                    "applies_to": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir actions and S3 attachments which don't support resource-level permissions",
                    "applies_to": [
                        "Resource::*",
                        "Resource::arn:aws:s3:::security-ir-*/*",
                    ],
                }
            ],
            True,
        )

    def update_security_ir_client_env(self, service_now_params: dict) -> None:
        """Update security_ir_client environment variables with ServiceNow parameters.

        Args:
            service_now_params (dict): ServiceNow configuration parameters
        """
        if service_now_params:
            # Add ServiceNow environment variables to existing environment
            self.security_ir_client.add_environment(
                "SERVICE_NOW_INSTANCE_ID", service_now_params["instance_id_param_name"]
            )
            self.security_ir_client.add_environment(
                "SERVICE_NOW_CLIENT_ID", service_now_params.get("client_id_param_name", "")
            )
            self.security_ir_client.add_environment(
                "SERVICE_NOW_CLIENT_SECRET_ARN",
                service_now_params.get("client_secret_arn", ""),
            )
            self.security_ir_client.add_environment(
                "SERVICE_NOW_USER_ID", service_now_params.get("user_id_param_name", "")
            )
            self.security_ir_client.add_environment(
                "PRIVATE_KEY_ASSET_BUCKET", service_now_params.get("private_key_asset_bucket_param_name", "")
            )
            self.security_ir_client.add_environment(
                "PRIVATE_KEY_ASSET_KEY", service_now_params.get("private_key_asset_key_param_name", "")
            )
            self.security_ir_client.add_environment(
                "INTEGRATION_MODULE",
                service_now_params.get("integration_module", "itsm"),
            )

        # Add stack-level suppressions for all resources
        NagSuppressions.add_stack_suppressions(
            self,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Built-in LogRetention Lambda role requires AWSLambdaBasicExecutionRole managed policy",
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Built-in LogRetention Lambda and EventBusLogger need these permissions to manage logs",
                    "applies_to": ["Resource::*", "Action::logs:*"],
                },
                {
                    "id": "AwsSolutions-SQS3",
                    "reason": "DLQs are used appropriately in the architecture and don't need their own DLQs",
                },
                {
                    "id": "AwsSolutions-L1",
                    "reason": "Using the latest available runtime for Python (3.13)",
                },
            ],
        )

        # Add suppressions for the DLQ in EventBusLogger
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/SecurityIncidentEventBusLogger/deadletter-queue",
            [
                {
                    "id": "AwsSolutions-SQS3",
                    "reason": "This is a DLQ for EventBridge events and doesn't need its own DLQ",
                }
            ],
        )

        # Add suppressions for EventBridge custom resource policy
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/EventsLogGroupPolicysecurityteststackSecurityIncidentEventBusLoggerEventBusLoggerRule9FE75D93/CustomResourcePolicy",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "EventBridge custom resource requires wildcard permissions to manage log group policies",
                    "applies_to": ["Resource::*"],
                }
            ],
        )

        # Add suppressions for AWS managed policy in custom resource
        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/AWS679f53fac002430cb0da5b7982bd2287/ServiceRole",
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "AWS CDK custom resource provider requires AWSLambdaBasicExecutionRole managed policy",
                    "applies_to": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                }
            ],
        )

        # Add direct suppressions to the EventBusLogger construct
        NagSuppressions.add_resource_suppressions(
            self.event_bus_logger,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "EventBusLogger requires these permissions to log events to CloudWatch",
                    "applies_to": ["Resource::*", "Action::logs:*"],
                },
                {
                    "id": "AwsSolutions-SQS3",
                    "reason": "This is a DLQ for the EventBusLogger and doesn't need its own DLQ",
                },
            ],
            True,
        )
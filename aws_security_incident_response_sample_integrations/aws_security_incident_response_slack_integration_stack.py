from os import path
from aws_cdk import (
    CfnOutput,
    CfnParameter,
    Duration,
    Stack,
    Aws,
    RemovalPolicy,
    aws_apigateway,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_lambda,
    aws_lambda_python_alpha as py_lambda,
    aws_logs,
    aws_ssm,
    custom_resources as cr,
)
from cdk_nag import NagSuppressions
from constructs import Construct
from .constants import (
    SECURITY_IR_EVENT_SOURCE,
    SLACK_EVENT_SOURCE,
    SLACK_BOT_TOKEN_PARAMETER,
    SLACK_SIGNING_SECRET_PARAMETER,
)
from .aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)


class AwsSecurityIncidentResponseSlackIntegrationStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        common_stack: AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Reference common resources
        table = common_stack.table
        event_bus = common_stack.event_bus
        event_bus_logger = common_stack.event_bus_logger
        domain_layer = common_stack.domain_layer
        mappers_layer = common_stack.mappers_layer
        wrappers_layer = common_stack.wrappers_layer
        log_level_param = common_stack.log_level_param

        """
        cdk for setting Slack Client parameters
        """
        # Create Slack client parameters with validation
        slack_bot_token_param = CfnParameter(
            self,
            "slackBotToken",
            type="String",
            description="The Slack Bot User OAuth Token (xoxb-...) for API access.",
            no_echo=True,
            allowed_pattern=r"^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$",
            constraint_description="Bot token must be in format: xoxb-XXXXXXXXX-XXXXXXXXX-XXXXXXXXXXXXXXXX",
        )

        slack_signing_secret_param = CfnParameter(
            self,
            "slackSigningSecret",
            type="String",
            description="The Slack App Signing Secret for webhook verification.",
            no_echo=True,
            allowed_pattern=r"^[a-f0-9]{32}$",
            constraint_description="Signing secret must be a 32-character hexadecimal string",
        )

        slack_workspace_id_param = CfnParameter(
            self,
            "slackWorkspaceId",
            type="String",
            description="The Slack Workspace ID where channels will be created.",
            allowed_pattern=r"^[A-Z0-9]{9,11}$",
            constraint_description="Workspace ID must be 9-11 uppercase alphanumeric characters",
        )

        # Create SSM parameters with encryption and tags
        slack_bot_token_ssm = aws_ssm.StringParameter(
            self,
            "SlackBotTokenSSM",
            parameter_name=SLACK_BOT_TOKEN_PARAMETER,
            string_value=slack_bot_token_param.value_as_string,
            description="Slack Bot User OAuth Token - Encrypted SecureString parameter",
            tier=aws_ssm.ParameterTier.STANDARD,
        )
        slack_bot_token_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        slack_signing_secret_ssm = aws_ssm.StringParameter(
            self,
            "SlackSigningSecretSSM",
            parameter_name=SLACK_SIGNING_SECRET_PARAMETER,
            string_value=slack_signing_secret_param.value_as_string,
            description="Slack App Signing Secret - Encrypted SecureString parameter",
            tier=aws_ssm.ParameterTier.STANDARD,
        )
        slack_signing_secret_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        slack_workspace_id_ssm = aws_ssm.StringParameter(
            self,
            "SlackWorkspaceIdSSM",
            parameter_name="/SecurityIncidentResponse/slackWorkspaceId",
            string_value=slack_workspace_id_param.value_as_string,
            description="Slack Workspace ID - Standard String parameter",
            tier=aws_ssm.ParameterTier.STANDARD,
        )
        slack_workspace_id_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        """
        cdk for Slack Bolt Lambda Layer
        """
        # Create Slack Bolt framework Lambda layer
        slack_bolt_layer = aws_lambda.LayerVersion(
            self,
            "SlackBoltLayer",
            code=aws_lambda.Code.from_asset(
                path.join(path.dirname(__file__), "..", "assets/slack_bolt_layer"),
            ),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_13],
            description="Layer containing Slack Bolt framework and SDK",
        )

        """
        cdk for assets/slack_client
        """
        # Create a custom role for the Slack Client Lambda function
        slack_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseSlackClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Slack Client Lambda function",
        )

        # Add custom policy for CloudWatch Logs permissions
        slack_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    f"arn:{Aws.PARTITION}:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ],
            )
        )

        # create Lambda function for Slack with custom role
        slack_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseSlackClient",
            entry=path.join(path.dirname(__file__), "..", "assets/slack_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(15),
            layers=[domain_layer, mappers_layer, wrappers_layer, slack_bolt_layer],
            environment={
                "SLACK_BOT_TOKEN": SLACK_BOT_TOKEN_PARAMETER,
                "SLACK_WORKSPACE_ID": "/SecurityIncidentResponse/slackWorkspaceId",
                "INCIDENTS_TABLE_NAME": table.table_name,
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=slack_client_role,
        )

        # create Event Bridge rule for Slack Client Lambda function
        slack_client_rule = aws_events.Rule(
            self,
            "slack-client-rule",
            description="Rule to send all events to Slack Lambda function",
            event_pattern=aws_events.EventPattern(source=[SECURITY_IR_EVENT_SOURCE]),
            event_bus=event_bus,
        )

        # Add target
        slack_client_target = aws_events_targets.LambdaFunction(slack_client)
        slack_client_rule.add_target(slack_client_target)

        # grant permissions to DynamoDB table and security-ir
        slack_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:GetCaseAttachmentDownloadUrl",
                    "security-ir:ListComments",
                ],
                resources=["*"],
            )
        )

        # Allow reading Slack SSM parameters with specific resource ARNs
        slack_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter"],
                resources=[
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter{SLACK_BOT_TOKEN_PARAMETER}",
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter/SecurityIncidentResponse/slackWorkspaceId",
                ],
            )
        )

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(slack_client_role)

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            slack_client_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir actions which don't support resource-level permissions",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        """
        cdk for API Gateway to receive events from Slack
        """
        # Create IAM role for API Gateway CloudWatch logging
        api_gateway_logging_role = aws_iam.Role(
            self,
            "ApiGatewayLoggingRole",
            assumed_by=aws_iam.ServicePrincipal("apigateway.amazonaws.com"),
            description="Role for API Gateway to write logs to CloudWatch",
            managed_policies=[
                aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonAPIGatewayPushToCloudWatchLogs"
                )
            ],
        )

        # Add CloudWatch Logs permissions to the role
        api_gateway_logging_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents",
                    "logs:GetLogEvents",
                    "logs:FilterLogEvents",
                ],
                resources=[f"arn:{Aws.PARTITION}:logs:{self.region}:{self.account}:*"],
            )
        )

        # Create API Gateway with enhanced configuration
        slack_api_gateway = aws_apigateway.RestApi(
            self,
            "SlackWebhookApi",
            rest_api_name="Slack Webhook API",
            description="API Gateway to receive events from Slack",
            default_cors_preflight_options=aws_apigateway.CorsOptions(
                allow_origins=["https://slack.com"],
                allow_methods=["POST", "OPTIONS"],
                allow_headers=[
                    "Content-Type",
                    "X-Slack-Request-Timestamp",
                    "X-Slack-Signature",
                ],
                max_age=Duration.hours(1),
            ),
            deploy_options=aws_apigateway.StageOptions(
                stage_name="prod",
                logging_level=aws_apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                metrics_enabled=True,
                throttling_rate_limit=100,  # Requests per second
                throttling_burst_limit=200,  # Burst capacity
                access_log_destination=aws_apigateway.LogGroupLogDestination(
                    aws_logs.LogGroup(
                        self,
                        "SlackApiGatewayLogs",
                        log_group_name=f"/aws/apigateway/SlackWebhookApi-{self.node.addr}",
                        retention=aws_logs.RetentionDays.ONE_WEEK,
                        removal_policy=RemovalPolicy.DESTROY,
                    )
                ),
                access_log_format=aws_apigateway.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True,
                ),
            ),
        )

        # Create account-level setting for API Gateway CloudWatch role
        api_gateway_account = aws_apigateway.CfnAccount(
            self,
            "ApiGatewayAccount",
            cloud_watch_role_arn=api_gateway_logging_role.role_arn,
        )

        # Add dependency to ensure the role is created before the account uses it
        api_gateway_account.node.add_dependency(api_gateway_logging_role)

        # Add suppressions for API Gateway logging role
        NagSuppressions.add_resource_suppressions(
            api_gateway_logging_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for CloudWatch Logs permissions",
                    "applies_to": ["Resource::arn:*:logs:*:*:*"],
                }
            ],
            True,
        )

        """
        cdk for assets/slack_events_bolt_handler
        """
        # Create Slack Events Bolt Handler and related resources
        slack_events_bolt_handler_role = aws_iam.Role(
            self,
            "SlackEventsBoltHandlerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Slack Events Bolt Handler Lambda function",
        )

        # Add custom policy for CloudWatch Logs permissions
        slack_events_bolt_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    f"arn:{Aws.PARTITION}:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ],
            )
        )

        # Grant permission to publish events to EventBridge
        slack_events_bolt_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["events:PutEvents"],
                resources=[event_bus.event_bus_arn],
            )
        )

        # Grant permission to access Slack SSM parameters with specific resource ARNs
        slack_events_bolt_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter"],
                resources=[
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter{SLACK_BOT_TOKEN_PARAMETER}",
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter{SLACK_SIGNING_SECRET_PARAMETER}",
                ],
            )
        )

        # Grant permission to invoke Slack Command Handler
        slack_events_bolt_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["lambda:InvokeFunction"],
                resources=["*"],  # Will be restricted after command handler is created
            )
        )

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            slack_events_bolt_handler_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Lambda invocation permission will be restricted after command handler is created",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        # Create Lambda function for Slack Events Bolt Handler with custom role
        slack_events_bolt_handler = py_lambda.PythonFunction(
            self,
            "SlackEventsBoltHandler",
            entry=path.join(
                path.dirname(__file__), "..", "assets/slack_events_bolt_handler"
            ),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(30),
            layers=[domain_layer, mappers_layer, wrappers_layer, slack_bolt_layer],
            environment={
                "EVENT_BUS_NAME": event_bus.event_bus_name,
                "SLACK_BOT_TOKEN": SLACK_BOT_TOKEN_PARAMETER,
                "SLACK_SIGNING_SECRET": SLACK_SIGNING_SECRET_PARAMETER,
                "INCIDENTS_TABLE_NAME": table.table_name,
                "EVENT_SOURCE": SLACK_EVENT_SOURCE,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=slack_events_bolt_handler_role,
        )

        # Add a specific rule for Slack notification events
        slack_notifications_rule = aws_events.Rule(
            self,
            "SlackNotificationsRule",
            description="Rule to capture events from Slack events handler",
            event_pattern=aws_events.EventPattern(source=[SLACK_EVENT_SOURCE]),
            event_bus=event_bus,
        )

        # Use the same log group as the event bus logger
        slack_notifications_target = aws_events_targets.CloudWatchLogGroup(
            log_group=event_bus_logger.log_group
        )
        slack_notifications_rule.add_target(slack_notifications_target)

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(slack_events_bolt_handler_role)

        """
        cdk for assets/slack_command_handler
        """
        # Create Slack Command Handler role
        slack_command_handler_role = aws_iam.Role(
            self,
            "SlackCommandHandlerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Slack Command Handler Lambda function",
        )

        # Add custom policy for CloudWatch Logs permissions
        slack_command_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    f"arn:{Aws.PARTITION}:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ],
            )
        )

        # Grant permission to access Slack SSM parameters with specific resource ARNs
        slack_command_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter"],
                resources=[
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter{SLACK_BOT_TOKEN_PARAMETER}",
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter{SLACK_SIGNING_SECRET_PARAMETER}",
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter/SecurityIncidentResponse/slackPermissionConfig",
                ],
            )
        )

        # Grant permission to access Security IR API
        slack_command_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:GetCase",
                    "security-ir:UpdateCase",
                    "security-ir:UpdateCaseStatus",
                    "security-ir:CloseCase",
                    "security-ir:CreateCaseComment",
                    "security-ir:ListComments",
                ],
                resources=["*"],
            )
        )

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            slack_command_handler_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for Security IR actions which don't support resource-level permissions",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        # Create Lambda function for Slack Command Handler
        slack_command_handler = py_lambda.PythonFunction(
            self,
            "SlackCommandHandler",
            entry=path.join(
                path.dirname(__file__), "..", "assets/slack_command_handler"
            ),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(30),
            layers=[domain_layer, mappers_layer, wrappers_layer, slack_bolt_layer],
            environment={
                "SLACK_BOT_TOKEN": SLACK_BOT_TOKEN_PARAMETER,
                "SLACK_SIGNING_SECRET": SLACK_SIGNING_SECRET_PARAMETER,
                "SLACK_PERMISSION_CONFIG": "/SecurityIncidentResponse/slackPermissionConfig",
                "INCIDENTS_TABLE_NAME": table.table_name,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=slack_command_handler_role,
        )

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(slack_command_handler_role)

        # Update Slack Events Bolt Handler environment to include command handler ARN
        slack_events_bolt_handler.add_environment(
            "SLACK_COMMAND_HANDLER_ARN", slack_command_handler.function_arn
        )

        # Grant Slack Events Bolt Handler permission to invoke Command Handler
        slack_command_handler.grant_invoke(slack_events_bolt_handler)

        """
        cdk for Slack API Gateway Authorizer
        """
        # Create IAM role for Slack API Gateway Authorizer
        slack_authorizer_role = aws_iam.Role(
            self,
            "SlackApiGatewayAuthorizerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for Slack API Gateway Authorizer Lambda function",
        )

        # Add CloudWatch Logs permissions
        slack_authorizer_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=[
                    f"arn:{Aws.PARTITION}:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ],
            )
        )

        # Grant permission to read Slack signing secret from SSM
        slack_authorizer_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter"],
                resources=[
                    f"arn:{Aws.PARTITION}:ssm:{self.region}:{self.account}:parameter{SLACK_SIGNING_SECRET_PARAMETER}",
                ],
            )
        )

        # Create Lambda authorizer function
        slack_authorizer = py_lambda.PythonFunction(
            self,
            "SlackApiGatewayAuthorizer",
            entry=path.join(
                path.dirname(__file__), "..", "assets/slack_api_gateway_authorizer"
            ),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(10),
            environment={
                "SLACK_SIGNING_SECRET": SLACK_SIGNING_SECRET_PARAMETER,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=slack_authorizer_role,
        )

        """
        cdk for API Gateway webhook endpoints
        """
        # Create request validator for API Gateway
        request_validator = aws_apigateway.RequestValidator(
            self,
            "SlackWebhookRequestValidator",
            rest_api=slack_api_gateway,
            request_validator_name="slack-webhook-validator",
            validate_request_body=True,
            validate_request_parameters=True,
        )

        # Create request model for Slack events
        slack_event_model = aws_apigateway.Model(
            self,
            "SlackEventModel",
            rest_api=slack_api_gateway,
            content_type="application/json",
            model_name="SlackEventModel",
            schema=aws_apigateway.JsonSchema(
                schema=aws_apigateway.JsonSchemaVersion.DRAFT4,
                title="Slack Event Schema",
                type=aws_apigateway.JsonSchemaType.OBJECT,
                properties={
                    "type": aws_apigateway.JsonSchema(
                        type=aws_apigateway.JsonSchemaType.STRING
                    ),
                    "token": aws_apigateway.JsonSchema(
                        type=aws_apigateway.JsonSchemaType.STRING
                    ),
                    "challenge": aws_apigateway.JsonSchema(
                        type=aws_apigateway.JsonSchemaType.STRING
                    ),
                    "event": aws_apigateway.JsonSchema(
                        type=aws_apigateway.JsonSchemaType.OBJECT
                    ),
                    "command": aws_apigateway.JsonSchema(
                        type=aws_apigateway.JsonSchemaType.STRING
                    ),
                },
            ),
        )

        # Create Lambda authorizer for Slack signature verification
        slack_lambda_authorizer = aws_apigateway.RequestAuthorizer(
            self,
            "SlackRequestAuthorizer",
            handler=slack_authorizer,
            identity_sources=[
                aws_apigateway.IdentitySource.header("X-Slack-Request-Timestamp"),
                aws_apigateway.IdentitySource.header("X-Slack-Signature"),
            ],
            authorizer_name="SlackSignatureAuthorizer",
            results_cache_ttl=Duration.seconds(0),  # Disable caching for security
        )

        # Create /slack resource
        slack_resource = slack_api_gateway.root.add_resource("slack")

        # Create /slack/events resource
        events_resource = slack_resource.add_resource("events")

        # Create Lambda integration for Slack Events Bolt Handler
        events_integration = aws_apigateway.LambdaIntegration(
            slack_events_bolt_handler,
            proxy=True,
            integration_responses=[
                aws_apigateway.IntegrationResponse(
                    status_code="200",
                    response_parameters={
                        "method.response.header.Content-Type": "'application/json'"
                    },
                )
            ],
        )

        # Add POST method to /slack/events with request validation and authorization
        events_method = events_resource.add_method(
            "POST",
            events_integration,
            authorizer=slack_lambda_authorizer,
            request_validator=request_validator,
            request_models={"application/json": slack_event_model},
            method_responses=[
                aws_apigateway.MethodResponse(
                    status_code="200",
                    response_parameters={
                        "method.response.header.Content-Type": True,
                    },
                )
            ],
        )

        # Grant API Gateway permission to invoke the Lambda function
        slack_events_bolt_handler.grant_invoke(
            aws_iam.ServicePrincipal("apigateway.amazonaws.com")
        )

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            slack_events_bolt_handler,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir, events, lambda, and SSM actions",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        # Enable the poller rule after Slack client is ready
        enable_poller_cr = cr.AwsCustomResource(
            self,
            "EnablePollerRule",
            on_create=cr.AwsSdkCall(
                service="EventBridge",
                action="enableRule",
                parameters={
                    "Name": common_stack.poller_rule.rule_name,
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    f"enable-poller-{common_stack.poller_rule.rule_name}"
                ),
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=[common_stack.poller_rule.rule_arn]
            ),
        )
        enable_poller_cr.node.add_dependency(slack_client)

        # Add stack-level suppression
        NagSuppressions.add_stack_suppressions(
            self,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Built-in LogRetention Lambda role requires AWSLambdaBasicExecutionRole managed policy",
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Built-in LogRetention Lambda needs these permissions to manage log retention",
                },
                {"id": "AwsSolutions-SQS3", "reason": "SQS is used as DLQ"},
                {
                    "id": "AwsSolutions-L1",
                    "reason": "CDK-generated Lambda functions may use older runtimes which we cannot directly control",
                },
                {
                    "id": "AwsSolutions-APIG2",
                    "reason": "Request validation is handled by Slack Bolt framework signature verification",
                },
                {
                    "id": "AwsSolutions-APIG4",
                    "reason": "Authorization is handled by Slack Bolt framework signature verification",
                },
                {
                    "id": "AwsSolutions-COG4",
                    "reason": "Slack webhook endpoints use Slack signature verification instead of Cognito",
                },
            ],
        )

        """
        cdk to output the generated name of CFN resources 
        """
        # Output Slack client ARN
        CfnOutput(
            self,
            "SlackClientLambdaArn",
            value=slack_client.function_arn,
            description="Slack Client Lambda Function ARN",
        )

        # Output Slack events handler log group info
        CfnOutput(
            self,
            "SlackEventsBoltHandlerLambdaLogGroup",
            value=slack_events_bolt_handler.log_group.log_group_name,
            description="Slack Events Bolt Handler Lambda CloudWatch Logs Group Name",
        )

        # Output the CloudWatch Logs URL for the slack-events-bolt-handler lambda function
        CfnOutput(
            self,
            "SlackEventsBoltHandlerLambdaLogGroupUrl",
            value=f"https://console.aws.amazon.com/cloudwatch/home?region={Stack.of(self).region}#logsV2:log-groups/log-group/{slack_events_bolt_handler.log_group.log_group_name}",
            description="Slack Events Bolt Handler Lambda CloudWatch Logs URL",
        )

        # Output API Gateway URL
        CfnOutput(
            self,
            "SlackWebhookUrl",
            value=f"{slack_api_gateway.url.rstrip('/')}/slack/events",
            description="Slack Webhook API Gateway URL",
        )

        # Output Slack Command Handler ARN
        CfnOutput(
            self,
            "SlackCommandHandlerLambdaArn",
            value=slack_command_handler.function_arn,
            description="Slack Command Handler Lambda Function ARN",
        )

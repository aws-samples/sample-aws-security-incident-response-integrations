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
    aws_secretsmanager,
    aws_ssm,
    aws_s3_assets,
    CustomResource,
    custom_resources as cr,
)
from cdk_nag import NagSuppressions
from constructs import Construct
from .constants import (
    SECURITY_IR_EVENT_SOURCE,
    SERVICE_NOW_EVENT_SOURCE,
)
from .aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)


class AwsSecurityIncidentResponseServiceNowIntegrationStack(Stack):
    """AWS CDK Stack for ServiceNow integration with Security Incident Response."""
    
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        common_stack: AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
        **kwargs,
    ) -> None:
        """Initialize the ServiceNow integration stack.

        Args:
            scope (Construct): The scope in which to define this construct
            construct_id (str): The scoped construct ID
            common_stack (AwsSecurityIncidentResponseSampleIntegrationsCommonStack): Common stack instance
            **kwargs: Additional keyword arguments passed to Stack
        """
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
        cdk for setting Service Now Client parameters
        """
        # Create Service Now Client parameters
        service_now_instance_id_param = CfnParameter(
            self,
            "serviceNowInstanceId",
            type="String",
            description="The instance id that will be used with the Service Now API.",
            no_echo=True,
        )

        # Store Service Now Client ID parameter
        service_now_client_id_param = CfnParameter(
            self,
            "serviceNowClientId",
            type="String",
            description="The OAuth client ID for the ServiceNow API.",
        )

        # Store Service Now Client Secret parameter
        service_now_client_secret_param = CfnParameter(
            self,
            "serviceNowClientSecret",
            type="String",
            description="The OAuth client secret that will be used with the Service Now API.",
            no_echo=True,
        )

        # Store Service Now User ID parameter
        service_now_user_id_param = CfnParameter(
            self,
            "serviceNowUserId",
            type="String",
            description="The ServiceNow user ID for JWT authentication.",
        )

        # Store Private Key Asset Path parameter
        private_key_asset_path_param = CfnParameter(
            self,
            "privateKeyAssetPath",
            type="String",
            description="Local path to the private key file (e.g., ./private.key).",
        )

        # Integration module parameter
        self.integration_module_param = CfnParameter(
            self,
            "integrationModule",
            type="String",
            description="ServiceNow integration module: 'itsm' for IT Service Management or 'ir' for Incident Response",
            allowed_values=["itsm", "ir"],
            default="itsm",
        )

        # Create SSM parameters
        service_now_client_secret_ssm_param = aws_ssm.StringParameter(
            self,
            "serviceNowClientSecretSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowClientSecret",
            string_value=service_now_client_secret_param.value_as_string,
            description="Service Now OAuth client secret",
        )
        service_now_client_secret_ssm_param.apply_removal_policy(RemovalPolicy.DESTROY)

        service_now_client_id_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowClientIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowClientId",
            string_value=service_now_client_id_param.value_as_string,
            description="Service Now OAuth client ID",
        )
        service_now_client_id_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        service_now_user_id_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowUserIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowUserId",
            string_value=service_now_user_id_param.value_as_string,
            description="Service Now user ID",
        )
        service_now_user_id_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        # Create S3 asset for private key
        private_key_asset = aws_s3_assets.Asset(
            self,
            "PrivateKeyAsset",
            path=private_key_asset_path_param.value_as_string,
        )

        private_key_asset_bucket_ssm = aws_ssm.StringParameter(
            self,
            "PrivateKeyAssetBucketSSM",
            parameter_name="/SecurityIncidentResponse/privateKeyAssetBucket",
            string_value=private_key_asset.s3_bucket_name,
            description="S3 bucket for private key asset",
        )
        private_key_asset_bucket_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        private_key_asset_key_ssm = aws_ssm.StringParameter(
            self,
            "PrivateKeyAssetKeySSM",
            parameter_name="/SecurityIncidentResponse/privateKeyAssetKey",
            string_value=private_key_asset.s3_object_key,
            description="S3 object key for private key asset",
        )
        private_key_asset_key_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        service_now_instance_id_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowInstanceIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowInstanceId",
            string_value=service_now_instance_id_param.value_as_string,
            description="Service Now instance id",
        )
        service_now_instance_id_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        """
        cdk for assets/service_now_client
        """
        # Create a custom role for the ServiceNow Client Lambda function
        service_now_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseServiceNowClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Service Now Client Lambda function",
        )

        # Add custom policy for CloudWatch Logs permissions
        service_now_client_role.add_to_policy(
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

        # create Lambda function for Service Now with custom role
        service_now_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseServiceNowClient",
            entry=path.join(path.dirname(__file__), "..", "assets/service_now_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(15),
            layers=[domain_layer, mappers_layer, wrappers_layer],
            environment={
                "SERVICE_NOW_INSTANCE_ID": service_now_instance_id_ssm.parameter_name,
                "SERVICE_NOW_CLIENT_ID": service_now_client_id_ssm.parameter_name,
                "SERVICE_NOW_USER_ID": service_now_user_id_ssm.parameter_name,
                "PRIVATE_KEY_ASSET_BUCKET": private_key_asset_bucket_ssm.parameter_name,
                "PRIVATE_KEY_ASSET_KEY": private_key_asset_key_ssm.parameter_name,
                "INCIDENTS_TABLE_NAME": table.table_name,
                "SERVICE_NOW_CLIENT_SECRET_PARAM": service_now_client_secret_ssm_param.parameter_name,
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "INTEGRATION_MODULE": self.integration_module_param.value_as_string,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=service_now_client_role,
        )

        # create Event Bridge rule for Service Now Client Lambda function
        service_now_client_rule = aws_events.Rule(
            self,
            "service-now-client-rule",
            description="Rule to send all events to Service Now Lambda function",
            event_pattern=aws_events.EventPattern(source=[SECURITY_IR_EVENT_SOURCE]),
            event_bus=event_bus,
        )

        # Add target
        service_now_client_target = aws_events_targets.LambdaFunction(
            service_now_client
        )
        service_now_client_rule.add_target(service_now_client_target)

        # grant permissions to DynamoDB table and security-ir
        service_now_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:GetCaseAttachmentDownloadUrl",
                    "security-ir:ListComments",
                ],
                resources=["*"],
            )
        )

        # allow adding SSM values
        service_now_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:PutParameter"],
                resources=["*"],
            )
        )

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(service_now_client_role)

        # Enable the poller rule after ServiceNow client is ready
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
        enable_poller_cr.node.add_dependency(service_now_client)

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            service_now_client_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir and SSM actions",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        """
        cdk for API Gateway to receive events from ServiceNow
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

        # Create API Gateway
        service_now_api_gateway = aws_apigateway.RestApi(
            self,
            "ServiceNowWebhookApi",
            rest_api_name="ServiceNow Webhook API",
            description="API Gateway to receive events from ServiceNow",
            default_cors_preflight_options=aws_apigateway.CorsOptions(
                allow_origins=aws_apigateway.Cors.ALL_ORIGINS,
                allow_methods=aws_apigateway.Cors.ALL_METHODS,
            ),
            deploy_options=aws_apigateway.StageOptions(
                stage_name="prod",
                logging_level=aws_apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                metrics_enabled=True,
                access_log_destination=aws_apigateway.LogGroupLogDestination(
                    aws_logs.LogGroup(
                        self,
                        "ServiceNowApiGatewayLogs",
                        log_group_name=f"/aws/apigateway/ServiceNowWebhookApi-{self.node.addr}",
                        retention=aws_logs.RetentionDays.ONE_WEEK,
                        removal_policy=RemovalPolicy.DESTROY,
                    )
                ),
                access_log_format=aws_apigateway.AccessLogFormat.clf(),
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

        """
        cdk for Secrets Manager secret with rotation for API Gateway authorization
        """
        # Create rotation Lambda role
        service_now_secret_rotation_handler_role = aws_iam.Role(
            self,
            "ServiceNowSecretRotationHandlerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for ServiceNow secret rotation Lambda function",
        )

        service_now_secret_rotation_handler_role.add_to_policy(
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

        service_now_secret_rotation_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecretVersionStage",
                ],
                resources=["*"],
            )
        )

        # Create rotation Lambda function
        service_now_secret_rotation_handler = py_lambda.PythonFunction(
            self,
            "SecretRotationLambda",
            entry=path.join(
                path.dirname(__file__),
                "..",
                "assets/service_now_secret_rotation_handler",
            ),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(5),
            role=service_now_secret_rotation_handler_role,
        )

        # Create the secret with rotation
        secret_template = '{"token": ""}'  # nosec B105
        api_auth_secret = aws_secretsmanager.Secret(
            self,
            "ApiAuthSecret",
            description="API Gateway authorization token for ServiceNow webhook",
            generate_secret_string=aws_secretsmanager.SecretStringGenerator(
                secret_string_template=secret_template,
                generate_string_key="token",
                exclude_characters=" %+~`#$&*()|[]{}:;<>?!'/\"\\@",
                password_length=32,
            ),
        )

        # Configure rotation
        api_auth_secret.add_rotation_schedule(
            "RotationSchedule",
            rotation_lambda=service_now_secret_rotation_handler,
            automatically_after=Duration.days(30),
        )

        # Add suppression for rotation role
        NagSuppressions.add_resource_suppressions(
            service_now_secret_rotation_handler_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for Secrets Manager rotation",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        """
        cdk for assets/service_now_notifications_handler
        """
        # Create Service Now notifications handler and related resources
        service_now_notifications_handler_role = aws_iam.Role(
            self,
            "ServiceNowNotificationsHandlerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Service Now Notifications Handler Lambda function",
        )

        # Add custom policy for CloudWatch Logs permissions
        service_now_notifications_handler_role.add_to_policy(
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
        service_now_notifications_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["events:PutEvents"],
                resources=[event_bus.event_bus_arn],
            )
        )

        # Grant permission to access SSM parameters
        service_now_notifications_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter"],
                resources=["*"],
            )
        )

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            service_now_notifications_handler_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for SSM parameters",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        # Create Lambda function for Service Now Notifications handler with custom role
        service_now_notifications_handler = py_lambda.PythonFunction(
            self,
            "ServiceNowNotificationsHandler",
            entry=path.join(
                path.dirname(__file__), "..", "assets/service_now_notifications_handler"
            ),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            layers=[domain_layer, mappers_layer, wrappers_layer],
            environment={
                "EVENT_BUS_NAME": event_bus.event_bus_name,
                "SERVICE_NOW_INSTANCE_ID": service_now_instance_id_ssm.parameter_name,
                "SERVICE_NOW_CLIENT_ID": service_now_client_id_ssm.parameter_name,
                "SERVICE_NOW_USER_ID": service_now_user_id_ssm.parameter_name,
                "PRIVATE_KEY_ASSET_BUCKET": private_key_asset_bucket_ssm.parameter_name,
                "PRIVATE_KEY_ASSET_KEY": private_key_asset_key_ssm.parameter_name,
                "SERVICE_NOW_CLIENT_SECRET_PARAM": service_now_client_secret_ssm_param.parameter_name,
                "INCIDENTS_TABLE_NAME": table.table_name,
                "EVENT_SOURCE": SERVICE_NOW_EVENT_SOURCE,
                "INTEGRATION_MODULE": self.integration_module_param.value_as_string,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=service_now_notifications_handler_role,
        )

        # Add a specific rule for ServiceNow notification events
        service_now_notifications_rule = aws_events.Rule(
            self,
            "ServiceNowNotificationsRule",
            description="Rule to capture events from ServiceNow notifications handler",
            event_pattern=aws_events.EventPattern(source=[SERVICE_NOW_EVENT_SOURCE]),
            event_bus=event_bus,
        )

        # Use the same log group as the event bus logger
        service_now_notifications_target = aws_events_targets.CloudWatchLogGroup(
            log_group=event_bus_logger.log_group
        )
        service_now_notifications_rule.add_target(service_now_notifications_target)

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(service_now_notifications_handler_role)

        """
        cdk for Service Now API Gateway Authorizer
        """
        # Create Lambda authorizer for service_now_api_gateway
        service_now_api_gateway_authorizer_role = aws_iam.Role(
            self,
            "ServiceNowApiGatewayAuthorizerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for ServiceNow API Gateway authorizer Lambda function",
        )

        service_now_api_gateway_authorizer_role.add_to_policy(
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

        service_now_api_gateway_authorizer_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["secretsmanager:GetSecretValue"],
                resources=[api_auth_secret.secret_arn],
            )
        )

        service_now_api_gateway_authorizer_lambda = py_lambda.PythonFunction(
            self,
            "ServiceNowApiGatewayAuthorizer",
            entry=path.join(
                path.dirname(__file__),
                "..",
                "assets/service_now_api_gateway_authorizer",
            ),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(30),
            environment={
                "API_AUTH_SECRET": api_auth_secret.secret_arn,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=service_now_api_gateway_authorizer_role,
        )

        # Create API Gateway authorizer
        service_now_api_gateway_token_authorizer = aws_apigateway.TokenAuthorizer(
            self,
            "ServiceNowTokenAuthorizer",
            handler=service_now_api_gateway_authorizer_lambda,
            identity_source="method.request.header.Authorization",
        )

        # Create webhook resource and methods
        webhook_resource = service_now_api_gateway.root.add_resource("webhook")
        webhook_integration = aws_apigateway.LambdaIntegration(
            service_now_notifications_handler
        )

        webhook_resource.add_method(
            "POST",
            webhook_integration,
            authorizer=service_now_api_gateway_token_authorizer,
        )
        # OPTIONS method is automatically added by CORS configuration, no need to add it manually

        # Grant API Gateway permission to invoke the Lambda function
        service_now_notifications_handler.grant_invoke(
            aws_iam.ServicePrincipal("apigateway.amazonaws.com")
        )

        # Add suppression for authorizer role
        NagSuppressions.add_resource_suppressions(
            service_now_api_gateway_authorizer_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for CloudWatch Logs permissions",
                    "applies_to": ["Resource::arn:*:logs:*:*:*"],
                }
            ],
            True,
        )

        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            service_now_notifications_handler,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir, events, lambda, and SSM actions",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

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
        Custom Lambda resource for creating ServiceNow resources (Business Rule and Outbound REST API). These Service Now resources will automate the event processing for Incident related updates in AWS Security IR
        """
        # Create role for ServiceNow API setup Lambda
        service_now_resource_setup_role = aws_iam.Role(
            self,
            "ServiceNowResourceSetupRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for ServiceNow Resource setup Lambda",
        )

        # Add CloudWatch Logs permissions
        service_now_resource_setup_role.add_to_policy(
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

        # Add SSM permissions with full access to resolve permission issues
        service_now_resource_setup_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                    "ssm:DescribeParameters",
                ],
                resources=["*"],
            )
        )

        # Add Secrets Manager permissions for rotation and secret access
        service_now_resource_setup_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "secretsmanager:RotateSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:UpdateSecretVersionStage",
                ],
                resources=[api_auth_secret.secret_arn],
            )
        )

        # Add suppression for wildcard resource in SSM and Secrets Manager policies
        NagSuppressions.add_resource_suppressions(
            service_now_resource_setup_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resource is required for SSM parameter access and Secrets Manager rotation",
                    "applies_to": ["Resource::*"],
                }
            ],
            True,
        )

        # Use the API Gateway's physical ID as the resource prefix
        # This will be available after deployment and used for naming ServiceNow resources

        # Create Lambda function for ServiceNow API setup
        service_now_resource_setup_handler = py_lambda.PythonFunction(
            self,
            "ServiceNowResourceSetupLambda",
            entry=path.join(
                path.dirname(__file__),
                "..",
                "assets/service_now_resource_setup_handler",
            ),
            layers=[domain_layer, mappers_layer, wrappers_layer],
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(5),
            environment={
                "SERVICE_NOW_INSTANCE_ID": service_now_instance_id_ssm.parameter_name,
                "SERVICE_NOW_CLIENT_ID": service_now_client_id_ssm.parameter_name,
                "SERVICE_NOW_USER_ID": service_now_user_id_ssm.parameter_name,
                "PRIVATE_KEY_ASSET_BUCKET": private_key_asset_bucket_ssm.parameter_name,
                "PRIVATE_KEY_ASSET_KEY": private_key_asset_key_ssm.parameter_name,
                "SERVICE_NOW_CLIENT_SECRET_PARAM": service_now_client_secret_ssm_param.parameter_name,
                "SERVICE_NOW_RESOURCE_PREFIX": service_now_api_gateway.rest_api_id,
                "WEBHOOK_URL": f"{service_now_api_gateway.url.rstrip('/')}/webhook",
                "API_AUTH_SECRET": api_auth_secret.secret_arn,
                "INTEGRATION_MODULE": self.integration_module_param.value_as_string,
                "LOG_LEVEL": log_level_param.value_as_string,
            },
            role=service_now_resource_setup_role,
        )

        # Create custom resource provider
        service_now_cr_provider = cr.Provider(
            self,
            "ServiceNowResourceSetupProvider",
            on_event_handler=service_now_resource_setup_handler,
        )

        # Create custom resource
        CustomResource(
            self,
            "ServiceNowResourceSetupCr",
            service_token=service_now_cr_provider.service_token,
            properties={
                "WebhookUrl": f"{service_now_api_gateway.url.rstrip('/')}/webhook",
                "IntegrationModule": self.integration_module_param.value_as_string,
            },
        )

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
            ],
        )

        """
        cdk to output the generated name of CFN resources 
        """
        # Output ServiceNow client ARN
        CfnOutput(
            self,
            "ServiceNowClientLambdaArn",
            value=service_now_client.function_arn,
            description="ServiceNow Client Lambda Function ARN",
        )

        # Output API Gateway URL
        CfnOutput(
            self,
            "ServiceNowWebhookUrl",
            value=f"{service_now_api_gateway.url.rstrip('/')}/webhook",
            description="ServiceNow Webhook API Gateway URL",
        )

from os import path
from aws_cdk import (
    Aspects,
    CfnCondition,
    CfnOutput,
    CfnParameter,
    CfnResource,
    Duration,
    Fn,
    IAspect,
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
    aws_s3 as s3,
    aws_secretsmanager,
    aws_ssm,
    aws_s3_assets,
    CustomResource,
    custom_resources as cr,
)
import jsii
from cdk_nag import NagSuppressions
from constructs import Construct
from .constants import (
    SECURITY_IR_EVENT_SOURCE,
    SERVICE_NOW_EVENT_SOURCE,
    PYTHON_LAMBDA_RUNTIME, SECRET_ROTATION_LAMBDA_TIMEOUT, API_GATEWAY_AUTHORIZOR_TIMEOUT,
    API_GATEWAY_LAMBDA_HANDLER_TIMEOUT, DEFAULT_LAMBDA_TIMEOUT
)
from .aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)


@jsii.implements(IAspect)
class ApplyCondition:
    """Aspect that applies a CfnCondition to all CfnResources in a construct tree."""

    def __init__(self, condition: CfnCondition):
        self.condition = condition

    def visit(self, node):
        if isinstance(node, CfnResource):
            node.cfn_options.condition = self.condition


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
        self.__table = common_stack.table
        self.__event_bus = common_stack.event_bus
        self.__event_bus_logger = common_stack.event_bus_logger
        self.__domain_layer = common_stack.domain_layer
        self.__mappers_layer = common_stack.mappers_layer
        self.__wrappers_layer = common_stack.wrappers_layer
        self.__log_level_param = common_stack.log_level_param

        self.__setup_cfn_parameters()
        self.__setup_ssm_parameters()

        self.__private_key_bucket = s3.Bucket.from_bucket_name(
            self,
            "ServiceNowPrivateKeyBucket",
            bucket_name=self.__private_key_bucket_param.value_as_string
        )

        # Create CfnCondition for deploy-time evaluation of OAuth setting
        # Note: OAuth is not yet implemented - this condition is for future use
        self.use_oauth_condition = CfnCondition(
            self,
            "UseOAuthCondition",
            expression=Fn.condition_equals(self.__use_oauth_param.value_as_string, "true"),
        )

        # Condition for token-based auth (when OAuth is NOT enabled)
        # This is the default authentication method
        self.use_token_auth_condition = CfnCondition(
            self,
            "UseTokenAuthCondition",
            expression=Fn.condition_equals(self.__use_oauth_param.value_as_string, "false"),
        )

        combined_condition = CfnCondition(self, 'TemporaryOrCondition',
                                          expression=Fn.condition_or(
                                            self.use_oauth_condition,
                                            self.use_token_auth_condition
            )
        )

        # Create System -> ServiceNow Connectivity
        self.service_now_client = self._create_service_now_client()
        self.enable_polling(self.service_now_client, common_stack.poller_rule)
        ## Create Event Bridge rule for ServiceNow Client Lambda function
        service_now_client_rule = aws_events.Rule(
            self,
            "service-now-client-rule",
            description="Rule to send all events to Service Now Lambda function",
            event_pattern=aws_events.EventPattern(source=[SECURITY_IR_EVENT_SOURCE]),
            event_bus=self.__event_bus,
        )
        service_now_client_rule.add_target(aws_events_targets.LambdaFunction(
            self.service_now_client
        ))

        # Create ServiceNow -> System Connectivity
        self.service_now_notification_handler = self._create_service_now_notifications_handler()
        ## Add a specific rule for ServiceNow notification events
        service_now_notifications_rule = aws_events.Rule(
            self,
            "ServiceNowNotificationsRule",
            description="Rule to capture events from ServiceNow notifications handler",
            event_pattern=aws_events.EventPattern(source=[SERVICE_NOW_EVENT_SOURCE]),
            event_bus=self.__event_bus,
        )
        ## Use the same log group as the event bus logger
        service_now_notifications_rule.add_target(aws_events_targets.CloudWatchLogGroup(
            log_group=self.__event_bus_logger.log_group
        ))

        # Create Api Gateway
        self.__api_gateway = self.__create_api_gateway()
        webhook_resource = self.__api_gateway.root.add_resource("webhook")
        self.__create_token_based_authn_authz_endpoint(
            api_gateway=self.__api_gateway,
            api_gateway_resource=webhook_resource,
            handler=self.service_now_notification_handler,
            http_method='POST', # OPTIONS method is automatically added by CORS configuration, no need to add it manually
            apply_condition=combined_condition # TODO: Swap for self.__use_token_auth_condition
        )

        # Output API Gateway URL
        CfnOutput(
            self,
            "ServiceNowWebhookUrl",
            value=f"{self.__api_gateway.url.rstrip('/')}/webhook",
            description="ServiceNow Webhook API Gateway URL",
        )

    def __setup_ssm_parameters(self):
        """Creates SSM Parameters, these store static secrets that we wouldn't the values exposed as environment variables in Lambda Functions"""
        self.__service_now_client_secret_ssm_param = aws_ssm.StringParameter(
            self,
            "serviceNowClientSecretSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowClientSecret",
            string_value=self.__service_now_client_secret_param.value_as_string,
            description="Service Now OAuth client secret",
        )
        self.__service_now_client_secret_ssm_param.apply_removal_policy(RemovalPolicy.DESTROY)

        self.__service_now_client_id_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowClientIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowClientId",
            string_value=self.__service_now_client_id_param.value_as_string,
            description="Service Now OAuth client ID",
        )
        self.__service_now_client_id_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        self.__service_now_user_id_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowUserIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowUserId",
            string_value=self.__service_now_user_id_param.value_as_string,
            description="Service Now user ID",
        )
        self.__service_now_user_id_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        # Use existing S3 bucket from deploy script

        # Create SSM parameters for S3 bucket location
        self.__private_key_asset_bucket_ssm = aws_ssm.StringParameter(
            self,
            "PrivateKeyAssetBucketSSM",
            parameter_name="/SecurityIncidentResponse/privateKeyAssetBucket",
            string_value=self.__private_key_bucket_param.value_as_string,
            description="S3 bucket for private key asset",
        )
        self.__private_key_asset_bucket_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        self.__private_key_asset_key_ssm = aws_ssm.StringParameter(
            self,
            "PrivateKeyAssetKeySSM",
            parameter_name="/SecurityIncidentResponse/privateKeyAssetKey",
            string_value="private.key",
            description="S3 object key for private key asset",
        )
        self.__private_key_asset_key_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

        self.__service_now_instance_id_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowInstanceIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowInstanceId",
            string_value=self.__service_now_instance_id_param.value_as_string,
            description="Service Now instance id",
        )
        self.__service_now_instance_id_ssm.apply_removal_policy(RemovalPolicy.DESTROY)

    def __setup_cfn_parameters(self):
        """"Creates CfnParameters. We use CfnParameters to get data about ServiceNow from engineer deploying the system"""
        self.__service_now_instance_id_param = CfnParameter(
            self,
            "serviceNowInstanceId",
            type="String",
            description="The instance id that will be used with the Service Now API.",
            no_echo=True,
        )

        # Store Service Now Client ID parameter
        self.__service_now_client_id_param = CfnParameter(
            self,
            "serviceNowClientId",
            type="String",
            description="The OAuth client ID for the ServiceNow API.",
        )

        # Store Service Now Client Secret parameter
        self.__service_now_client_secret_param = CfnParameter(
            self,
            "serviceNowClientSecret",
            type="String",
            description="The OAuth client secret that will be used with the Service Now API.",
            no_echo=True,
        )

        # Store Service Now User ID parameter
        self.__service_now_user_id_param = CfnParameter(
            self,
            "serviceNowUserId",
            type="String",
            description="The ServiceNow user ID for JWT authentication.",
        )

        # Private key bucket parameter (from deploy script)
        self.__private_key_bucket_param = CfnParameter(
            self,
            "privateKeyBucket",
            type="String",
            description="S3 bucket name containing the private key file.",
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

        # API Gateway authentication type parameter
        self.__use_oauth_param = CfnParameter(
            self,
            "useOAuth",
            type="String",
            description="Use OAuth for API Gateway authentication instead of token-based auth. Set to 'true' to enable OAuth (not yet implemented).",
            allowed_values=["true", "false"],
            default="false",
        )

    def enable_polling(self, py_function: py_lambda.PythonFunction, rule: aws_events.Rule) -> None:
        """Allows a function to be trigged by an EventBridge Scheduled Task"""
        # Enable the poller rule after ServiceNow client is ready
        enable_poller_cr = cr.AwsCustomResource(
            self,
            "EnablePollerRule",
            on_create=cr.AwsSdkCall(
                service="EventBridge",
                action="enableRule",
                parameters={
                    "Name":rule.rule_name,
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    f"enable-poller-{rule.rule_name}"
                ),
            ),
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=[rule.rule_arn]
            ),
        )
        enable_poller_cr.node.add_dependency(py_function)

    def _create_service_now_client(self) -> py_lambda.PythonFunction:
        """The purpose of the ServiceNow Client is to issue commands to ServiceNow from the System"""
        # Create a custom role for the ServiceNow Client Lambda function
        service_now_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseServiceNowClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Service Now Client Lambda function",
        )

        # Grant permissions to security-ir
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

        # Create Lambda function
        service_now_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseServiceNowClient",
            entry=path.join(path.dirname(__file__), "..", "assets/service_now_client"),
            runtime=PYTHON_LAMBDA_RUNTIME,
            timeout=API_GATEWAY_LAMBDA_HANDLER_TIMEOUT,
            layers=[self.__domain_layer, self.__mappers_layer, self.__wrappers_layer],
            environment={
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "INTEGRATION_MODULE": self.integration_module_param.value_as_string,
                "LOG_LEVEL": self.__log_level_param.value_as_string,
            },
            role=service_now_client_role,
        )
        self.__add_service_now_to_environment(service_now_client)
        self.__add_private_key_to_environment(service_now_client)
        self.__add_incident_table_to_environment(service_now_client)
        return service_now_client

    def _create_service_now_notifications_handler(self) -> py_lambda.PythonFunction:
        """The purpose of the ServiceNow Notification Handler is to process events coming from ServiceNow"""
        # Create Service Now notifications handler and related resources
        service_now_notifications_handler_role = aws_iam.Role(
            self,
            "ServiceNowNotificationsHandlerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Service Now Notifications Handler Lambda function",
        )

        # Grant permission to publish events to EventBridge
        # TODO: Swap with grant
        service_now_notifications_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["events:PutEvents"],
                resources=[self.__event_bus.event_bus_arn],
            )
        )
        # Create Lambda function for Service Now Notifications handler with custom role
        service_now_notifications_handler = py_lambda.PythonFunction(
            self,
            "ServiceNowNotificationsHandler",
            entry=path.join(
                path.dirname(__file__), "..", "assets/service_now_notifications_handler"
            ),
            runtime=PYTHON_LAMBDA_RUNTIME,
            timeout=API_GATEWAY_LAMBDA_HANDLER_TIMEOUT,
            layers=[self.__domain_layer, self.__mappers_layer, self.__wrappers_layer],
            environment={
                "EVENT_BUS_NAME": self.__event_bus.event_bus_name,
                "EVENT_SOURCE": SERVICE_NOW_EVENT_SOURCE,
                "INTEGRATION_MODULE": self.integration_module_param.value_as_string,
                "LOG_LEVEL": self.__log_level_param.value_as_string,
            },
            role=service_now_notifications_handler_role,
        )
        self.__add_service_now_to_environment(service_now_notifications_handler)
        self.__add_private_key_to_environment(service_now_notifications_handler)
        self.__add_incident_table_to_environment(service_now_notifications_handler)
        return service_now_notifications_handler

    def __create_service_now_setup_custom_resource(self, api_gateway: aws_apigateway.RestApi, secret: aws_secretsmanager.Secret) -> CustomResource:
        """Creates Business Rule and Outbound REST API. These ServiceNow resources automate the pushing of events from ServiceNow to API Gateway"""
        service_now_resource_setup_role = aws_iam.Role(
            self,
            "ServiceNowResourceSetupRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for ServiceNow Resource setup Lambda",
        )
        secret.grant_read(service_now_resource_setup_role)
        secret.grant_write(service_now_resource_setup_role)

        service_now_resource_setup_handler = py_lambda.PythonFunction(
                self,
                "ServiceNowResourceSetupLambda",
                entry=path.join(
                    path.dirname(__file__),
                    "..",
                    "assets/service_now_resource_setup_handler",
                ),
                layers=[self.__domain_layer, self.__mappers_layer, self.__wrappers_layer],
                runtime=PYTHON_LAMBDA_RUNTIME,
                timeout=DEFAULT_LAMBDA_TIMEOUT,
                environment={
                    "SERVICE_NOW_RESOURCE_PREFIX": api_gateway.rest_api_id,
                    "WEBHOOK_URL": f"{api_gateway.url.rstrip('/')}/webhook",
                    "API_AUTH_SECRET": secret.secret_arn,
                    "INTEGRATION_MODULE": self.integration_module_param.value_as_string,
                    "LOG_LEVEL": self.__log_level_param.value_as_string,
                },
                role=service_now_resource_setup_role,
            )
        self.__add_service_now_to_environment(service_now_resource_setup_handler)
        self.__add_private_key_to_environment(service_now_resource_setup_handler)

        service_now_cr_provider = cr.Provider(
            self,
            "ServiceNowResourceSetupProvider",
            on_event_handler=service_now_resource_setup_handler,
        )

        # Create custom resource
        return CustomResource(
            self,
            "ServiceNowResourceSetupCr",
            service_token=service_now_cr_provider.service_token,
            properties={
                "WebhookUrl": f"{api_gateway.url.rstrip('/')}/webhook",
                "IntegrationModule": self.integration_module_param.value_as_string,
            },
        )

    def __add_service_now_to_environment(self, py_function: py_lambda.PythonFunction) -> None:
        """Adds ServiceNow specific environment variables and grants permissions"""
        py_function.add_environment('SERVICE_NOW_INSTANCE_ID', self.__service_now_instance_id_ssm.parameter_name)
        py_function.add_environment('SERVICE_NOW_CLIENT_ID', self.__service_now_client_id_ssm.parameter_name)
        py_function.add_environment('SERVICE_NOW_USER_ID', self.__service_now_user_id_ssm.parameter_name)
        py_function.add_environment('SERVICE_NOW_CLIENT_SECRET_PARAM', self.__service_now_client_secret_ssm_param.parameter_name)

        # SSM Grants
        for ssm_param in [self.__service_now_instance_id_ssm, self.__service_now_client_id_ssm,
                          self.__service_now_user_id_ssm, self.__service_now_client_secret_ssm_param]:
            ssm_param.grant_read(py_function.role)
            ssm_param.grant_write(py_function.role)

    def __add_private_key_to_environment(self, py_function: py_lambda.PythonFunction) -> None:
        """Adds private key environment and grants permissions"""
        py_function.add_environment('PRIVATE_KEY_ASSET_BUCKET', self.__private_key_asset_bucket_ssm.parameter_name)
        py_function.add_environment('PRIVATE_KEY_ASSET_KEY', self.__private_key_asset_key_ssm.parameter_name)
        ## SSM Grants
        for ssm_param in [self.__private_key_asset_bucket_ssm, self.__private_key_asset_key_ssm]:
            ssm_param.grant_read(py_function.role)
            ssm_param.grant_write(py_function.role)

        self.__private_key_bucket.grant_read(py_function.role)

    def __add_incident_table_to_environment(self, py_function: py_lambda.PythonFunction) -> None:
        py_function.add_environment('INCIDENTS_TABLE_NAME', self.__table.table_name)
        self.__table.grant_read_write_data(py_function.role)

    def __create_api_gateway(self) -> aws_apigateway.RestApi:
        """Create API Gateway"""
        api_gateway_logging_role = aws_iam.Role(
            self,
            "ApiGatewayLoggingRole",
            assumed_by=aws_iam.ServicePrincipal("apigateway.amazonaws.com"),
            description="Role for API Gateway to write logs to CloudWatch",
            managed_policies=[
                aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonAPIGatewayPushToCloudWatchLogs" # This includes Read / Write permission to CW Logs. So we don't need to explicitly grant
                )
            ],
        )

        api_gateway_logs = aws_logs.LogGroup(
                        self,
                        "ServiceNowApiGatewayLogs",
                        log_group_name=f"/aws/apigateway/ServiceNowWebhookApi-{self.node.addr}",
                        retention=aws_logs.RetentionDays.ONE_WEEK,
                        removal_policy=RemovalPolicy.DESTROY,
        )
        api_gateway = aws_apigateway.RestApi(
            self,
            "ServiceNowWebhookApiToken",
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
                access_log_format=aws_apigateway.AccessLogFormat.clf(),
                access_log_destination=aws_apigateway.LogGroupLogDestination(api_gateway_logs)
            )
        )
        api_gateway_account = aws_apigateway.CfnAccount(
            self,
            "ApiGatewayAccount",
            cloud_watch_role_arn=api_gateway_logging_role.role_arn,
        )
        api_gateway_account.node.add_dependency(api_gateway_logging_role)

        return api_gateway

    def __create_token_based_authn_authz_endpoint(self,
                                                  api_gateway: aws_apigateway.RestApi,
                                                  api_gateway_resource: aws_apigateway.Resource,
                                                  handler: py_lambda.PythonFunction,
                                                  http_method: str,
                                                  apply_condition: CfnCondition) -> aws_apigateway.Method:
        # Create Lambda Function to rotate token
        service_now_secret_rotation_handler_role = aws_iam.Role(
            self,
            "ServiceNowSecretRotationHandlerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for ServiceNow secret rotation Lambda function",
        )

        service_now_secret_rotation_handler = py_lambda.PythonFunction(
            self,
            "SecretRotationLambda",
            entry=path.join(
                path.dirname(__file__),
                "..",
                "assets/service_now_secret_rotation_handler",
            ),
            runtime=PYTHON_LAMBDA_RUNTIME,
            timeout=SECRET_ROTATION_LAMBDA_TIMEOUT,
            role=service_now_secret_rotation_handler_role,
        )
        # Create the secret with rotation
        secret_template = '{"token": ""}'  # nosec B105
        token_secret = aws_secretsmanager.Secret(
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
        token_secret.grant_read(service_now_secret_rotation_handler_role)
        token_secret.grant_write(service_now_secret_rotation_handler_role)
        token_secret.add_rotation_schedule(
            "RotationSchedule",
            rotation_lambda=service_now_secret_rotation_handler,
            automatically_after=Duration.days(30),
        )

        # Create Lambda authorizer to enforce Token based AuthN/AuthZ
        service_now_api_gateway_authorizer_role = aws_iam.Role(
            self,
            "ServiceNowApiGatewayAuthorizerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for ServiceNow API Gateway authorizer Lambda function",
        )
        token_secret.grant_read(service_now_api_gateway_authorizer_role)

        service_now_api_gateway_authorizer_lambda = py_lambda.PythonFunction(
            self,
            "ServiceNowApiGatewayAuthorizer",
            entry=path.join(
                path.dirname(__file__),
                "..",
                "assets/service_now_api_gateway_authorizer",
            ),
            runtime=PYTHON_LAMBDA_RUNTIME,
            timeout=API_GATEWAY_AUTHORIZOR_TIMEOUT,
            environment={
                "API_AUTH_SECRET": token_secret.secret_arn,
                "LOG_LEVEL": self.__log_level_param.value_as_string,
            },
            role=service_now_api_gateway_authorizer_role,
        )
        service_now_api_gateway_token_authorizer = aws_apigateway.TokenAuthorizer(
            self,
            "ServiceNowTokenAuthorizer",
            handler=service_now_api_gateway_authorizer_lambda,
            identity_source="method.request.header.Authorization",
        )

        token_based_method = api_gateway_resource.add_method(
            http_method,
            aws_apigateway.LambdaIntegration(handler), # As a side effect, API Gateway is automatically granted invoke permissions
            authorizer=service_now_api_gateway_token_authorizer,
        )

        # Setup ServiceNow Business Rule and REST API
        service_now_setup_cr = self.__create_service_now_setup_custom_resource(
            api_gateway=api_gateway,
            secret=token_secret
        )

        for resource in [service_now_secret_rotation_handler_role, service_now_secret_rotation_handler, token_secret,
                         service_now_api_gateway_authorizer_role, service_now_api_gateway_authorizer_lambda,
                         service_now_api_gateway_token_authorizer, token_based_method, service_now_setup_cr]:
            Aspects.of(resource).add(ApplyCondition(apply_condition))

        return token_based_method
from os import path
from aws_cdk import (
    CfnOutput,
    CfnParameter,
    Duration,
    Stack,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_lambda,
    aws_lambda_python_alpha as py_lambda,
    aws_ssm,
)
from cdk_nag import NagSuppressions
from constructs import Construct
from .constants import SECURITY_IR_EVENT_SOURCE

class AwsSecurityIncidentResponseServiceNowIntegrationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, common_stack=None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Reference common resources
        table = common_stack.table
        event_bus = common_stack.event_bus
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

        # Store Service Now User parameter
        service_now_user_param = CfnParameter(
            self,
            "serviceNowUser",
            type="String",
            description="The user for the ServiceNow API.",
        )

        # Store Service Now User Password parameter
        service_now_password_param = CfnParameter(
            self,
            "serviceNowPassword",
            type="String",
            description="The user password that will be used with the Service Now API.",
            no_echo=True,
        )
        
        # Create SSM parameters
        service_now_password_ssm_param = aws_ssm.StringParameter(
            self,
            "serviceNowPasswordSSM",
            string_value=service_now_password_param.value_as_string,
            description="Service Now password",
        )

        service_now_user_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowUserSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowUser",
            string_value=service_now_user_param.value_as_string,
            description="Service Now user",
        )

        service_now_instance_id_ssm = aws_ssm.StringParameter(
            self,
            "serviceNowInstanceIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowInstanceId",
            string_value=service_now_instance_id_param.value_as_string,
            description="Service Now instance id",
        )
        
        """
        cdk for assets/service_now_client
        """
        # Create a custom role for the ServiceNow Client Lambda function
        service_now_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseServiceNowClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Service Now Client Lambda function"
        )
        
        # Add custom policy for CloudWatch Logs permissions
        service_now_client_role.add_to_policy(
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
        
        # create Lambda function for Service Now with custom role
        service_now_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseServiceNowClient",
            entry=path.join(path.dirname(__file__), "..", "assets/service_now_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(15),
            layers=[domain_layer, mappers_layer, wrappers_layer],
            environment={
                "SERVICE_NOW_INSTANCE_ID": "/SecurityIncidentResponse/serviceNowInstanceId",
                "SERVICE_NOW_USER": "/SecurityIncidentResponse/serviceNowUser",
                "INCIDENTS_TABLE_NAME": table.table_name,
                "SERVICE_NOW_PASSWORD_PARAM": service_now_password_ssm_param.parameter_name,
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "LOG_LEVEL": log_level_param.value_as_string
            },
            role=service_now_client_role
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
        service_now_client_target = aws_events_targets.LambdaFunction(service_now_client)
        service_now_client_rule.add_target(service_now_client_target)
        
        # grant permissions to DynamoDB table and security-ir
        service_now_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:GetCaseAttachmentDownloadUrl",
                    "security-ir:ListComments"
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
        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            service_now_client_role,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir and SSM actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )
        
        # Add stack-level suppression
        NagSuppressions.add_stack_suppressions(
            self, [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Built-in LogRetention Lambda role requires AWSLambdaBasicExecutionRole managed policy"
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Built-in LogRetention Lambda needs these permissions to manage log retention"
                },
                {
                    "id": "AwsSolutions-SQS3",
                    "reason": "SQS is used as DLQ"
                },
                {
                    "id": "AwsSolutions-L1",
                    "reason": "CDK-generated Lambda functions may use older runtimes which we cannot directly control"
                }
            ]
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
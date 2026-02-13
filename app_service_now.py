#!/usr/bin/env python3
"""ServiceNow Integration CDK Application.

This module defines the CDK application for deploying AWS Security Incident Response
ServiceNow integration infrastructure. It creates the common stack with ServiceNow
parameters and the ServiceNow-specific stack.
"""
import aws_cdk as cdk
from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)
from aws_security_incident_response_sample_integrations.aws_security_incident_response_service_now_integration_stack import (
    AwsSecurityIncidentResponseServiceNowIntegrationStack,
)

app = cdk.App()

# ServiceNow parameters for common stack
# Note: client_secret_arn will be dynamically set by the ServiceNow integration stack
# after it creates the Secrets Manager secret from the user-provided client secret value
service_now_params = {
    "instance_id_param_name": "/SecurityIncidentResponse/serviceNowInstanceId",
    "client_id_param_name": "/SecurityIncidentResponse/serviceNowClientId",
    "user_sys_id_param_name": "/SecurityIncidentResponse/serviceNowUserId",
    "private_key_asset_bucket_param_name": "/SecurityIncidentResponse/privateKeyAssetBucket",
    "private_key_asset_key_param_name": "/SecurityIncidentResponse/privateKeyAssetKey",
}

# Create common stack without ServiceNow secret ARN (will be handled in ServiceNow stack)
common_stack = AwsSecurityIncidentResponseSampleIntegrationsCommonStack(
    app,
    "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
    service_now_params=service_now_params,
)

# Create ServiceNow integration stack
service_now_stack = AwsSecurityIncidentResponseServiceNowIntegrationStack(
    app,
    "AwsSecurityIncidentResponseServiceNowIntegrationStack",
    common_stack=common_stack,
)

app.synth()

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
service_now_params = {
    "instance_id_param_name": "/SecurityIncidentResponse/serviceNowInstanceId",
    "username_param_name": "/SecurityIncidentResponse/serviceNowUser",
    "password_param_name": "/SecurityIncidentResponse/serviceNowPassword",
}

# Create common stack with ServiceNow parameters
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

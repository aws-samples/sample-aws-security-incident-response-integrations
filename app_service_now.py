#!/usr/bin/env python3
import os
import aws_cdk as cdk
from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)
from aws_security_incident_response_sample_integrations.aws_security_incident_response_service_now_integration_stack import (
    AwsSecurityIncidentResponseServiceNowIntegrationStack,
)

app = cdk.App()

# Create common stack
common_stack = AwsSecurityIncidentResponseSampleIntegrationsCommonStack(
    app, "AwsSecurityIncidentResponseSampleIntegrationsCommonStack"
)

# Create ServiceNow integration stack
service_now_stack = AwsSecurityIncidentResponseServiceNowIntegrationStack(
    app,
    "AwsSecurityIncidentResponseServiceNowIntegrationStack",
    common_stack=common_stack,
)

app.synth()

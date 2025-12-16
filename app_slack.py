#!/usr/bin/env python3
import os
import aws_cdk as cdk
from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)
from aws_security_incident_response_sample_integrations.aws_security_incident_response_slack_integration_stack import (
    AwsSecurityIncidentResponseSlackIntegrationStack,
)

app = cdk.App()

# Create common stack
common_stack = AwsSecurityIncidentResponseSampleIntegrationsCommonStack(
    app, "AwsSecurityIncidentResponseSampleIntegrationsCommonStack"
)

# Create Slack integration stack
slack_stack = AwsSecurityIncidentResponseSlackIntegrationStack(
    app, "AwsSecurityIncidentResponseSlackIntegrationStack", common_stack=common_stack
)

app.synth()

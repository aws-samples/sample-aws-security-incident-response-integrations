#!/usr/bin/env python3
# TODO: rename this file to app_jira.py once the Service Now integration implementation is complete
# TODO: see https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210524326651427?focus=true
import os
import aws_cdk as cdk
from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)
from aws_security_incident_response_sample_integrations.aws_security_incident_response_jira_integration_stack import (
    AwsSecurityIncidentResponseJiraIntegrationStack,
)

app = cdk.App()

# Create common stack
common_stack = AwsSecurityIncidentResponseSampleIntegrationsCommonStack(
    app, "AwsSecurityIncidentResponseSampleIntegrationsCommonStack"
)

# Create Jira integration stack
jira_stack = AwsSecurityIncidentResponseJiraIntegrationStack(
    app, "AwsSecurityIncidentResponseJiraIntegrationStack", common_stack=common_stack
)

app.synth()

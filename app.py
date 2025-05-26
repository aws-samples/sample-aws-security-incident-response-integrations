#!/usr/bin/env python3
import os

from aws_cdk import App, Environment, Aspects
import cdk_nag

from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsStack,
)

app = App()
AwsSecurityIncidentResponseSampleIntegrationsStack(
    app,
    "AwsSecurityIncidentResponseSampleIntegrationsStack",
    # If you don't specify 'env', this stack will be environment-agnostic.
    # Account/Region-dependent features and context lookups will not work,
    # but a single synthesized template can be deployed anywhere.
    # Uncomment the next line to specialize this stack for the AWS Account
    # and Region that are implied by the current CLI configuration.
    # env=cdk.Environment(account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION')),
    # Uncomment the next line if you know exactly what Account and Region you
    # want to deploy the stack to. */
    # env=cdk.Environment(account='123456789012', region='us-east-1'),
    # For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html
)

# Add the cdk-nag AwsSolutions Pack
cdk_nag.AwsSolutionsChecks.VERBOSE = True
# Add IAM5 suppressions for wildcard resources
cdk_nag.NagSuppressions.add_stack_suppressions(
    app.node.find_child("AwsSecurityIncidentResponseSampleIntegrationsStack"),
    [
        {
            "id": "AwsSolutions-IAM5",
            "reason": "Wildcard resources are required for certain actions in this sample integration",
            "applies_to": ["Resource::*"]
        },
    ],
)
Aspects.of(app).add(cdk_nag.AwsSolutionsChecks())

app.synth()

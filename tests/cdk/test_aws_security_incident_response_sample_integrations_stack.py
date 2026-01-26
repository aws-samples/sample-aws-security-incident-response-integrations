"""Tests for the common integrations CDK stack."""

import aws_cdk as core
import cdk_nag
import pytest
from aws_cdk.assertions import Template
from cdk_nag import AwsSolutionsChecks

from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)

from .cdk_test_utils import FindingAggregatorLogger


@pytest.fixture(autouse=True)
def app():
    return core.App()


@pytest.fixture(autouse=True)
def stack(app):
    return AwsSecurityIncidentResponseSampleIntegrationsCommonStack(
        app, "security-test-stack"
    )


def test_security_compliance(app, stack):
    """
    Test to see if CDK Nag found a problem.
    :return:
    """
    spy = FindingAggregatorLogger()

    checks = AwsSolutionsChecks(additional_loggers=[spy], verbose=True)

    # Add comprehensive stack-level suppressions
    cdk_nag.NagSuppressions.add_stack_suppressions(
        stack,
        [
            {
                "id": "AwsSolutions-L1",
                "reason": "Using the latest available runtime for Python (3.13)",
            },
            {
                "id": "AwsSolutions-SQS3",
                "reason": "DLQs are used appropriately in the architecture and don't need their own DLQs",
            },
            {
                "id": "AwsSolutions-IAM4",
                "reason": "AWS CDK custom resource provider requires AWSLambdaBasicExecutionRole managed policy",
            },
            {
                "id": "AwsSolutions-IAM5",
                "reason": "EventBridge custom resource requires wildcard permissions to manage log group policies",
            },
        ],
    )

    core.Aspects.of(stack).add(checks)

    # Prepare the stack for testing
    app.synth()

    if spy.non_compliant_findings and len(spy.non_compliant_findings) > 0:
        print("\n")
        for finding in spy.non_compliant_findings:
            print(f"Non-compliant finding: {finding}")
        assert False


def test_lambda_function_exist(stack):
    template = Template.from_stack(stack)
    template.has_resource(
        "AWS::Lambda::Function", {"Properties": {"Handler": "index.handler"}}
    )

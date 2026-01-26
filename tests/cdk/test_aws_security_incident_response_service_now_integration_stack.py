"""Tests for the ServiceNow integration CDK stack."""

import aws_cdk as core
import pytest
from aws_cdk.assertions import Template
from cdk_nag import AwsSolutionsChecks, NagSuppressions

from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)
from aws_security_incident_response_sample_integrations.aws_security_incident_response_service_now_integration_stack import (
    AwsSecurityIncidentResponseServiceNowIntegrationStack,
)

from .cdk_test_utils import FindingAggregatorLogger


@pytest.fixture(scope="module")
def app():
    """Create a CDK app for testing (module-scoped for performance)."""
    return core.App()


@pytest.fixture(scope="module")
def common_stack(app):
    """Create the common stack required by ServiceNow integration (module-scoped)."""
    return AwsSecurityIncidentResponseSampleIntegrationsCommonStack(
        app, "service-now-test-common-stack"
    )


@pytest.fixture(scope="module")
def service_now_stack(app, common_stack):
    """Create the ServiceNow integration stack for testing (module-scoped)."""
    return AwsSecurityIncidentResponseServiceNowIntegrationStack(
        app, "service-now-test-stack", common_stack=common_stack
    )


@pytest.fixture(scope="module")
def template(service_now_stack):
    """Create template once for all tests (module-scoped)."""
    return Template.from_stack(service_now_stack)


def test_service_now_stack_synthesizes(template):
    """Test that the ServiceNow stack synthesizes without errors."""
    assert template is not None

def test_lambda_authorizer_exists(template):
    """Test that the API Gateway Lambda authorizer is created."""
    template.has_resource(
        "AWS::ApiGateway::Authorizer",
        {"Properties": {"Type": "TOKEN"}},
    )


def test_security_compliance(app, common_stack, service_now_stack):
    """Test CDK Nag security compliance for the ServiceNow stack."""
    spy = FindingAggregatorLogger()
    checks = AwsSolutionsChecks(additional_loggers=[spy], verbose=True)

    # Add stack-level suppressions for common patterns
    NagSuppressions.add_stack_suppressions(
        common_stack,
        [
            {
                "id": "AwsSolutions-L1",
                "reason": "Using the latest available runtime for Python (3.13)",
            },
            {
                "id": "AwsSolutions-SQS3",
                "reason": "DLQs are used appropriately in the architecture",
            },
            {
                "id": "AwsSolutions-IAM4",
                "reason": "AWS CDK custom resource provider requires managed policies",
            }
        ],
    )

    NagSuppressions.add_stack_suppressions(
        service_now_stack,
        [
            {
                "id": "AwsSolutions-L1",
                "reason": "Using the latest available runtime for Python (3.13)",
            },
            {
                "id": "AwsSolutions-SQS3",
                "reason": "DLQs are used appropriately in the architecture",
            },
            {
                "id": "AwsSolutions-IAM4",
                "reason": "AWS CDK custom resource provider requires managed policies",
            },
            {
                "id": "AwsSolutions-APIG2",
                "reason": "Request validation is handled by Lambda authorizer and handler", # FIXME: In the next round of changes, we will add the option for OAuth 2.0
            },
            {
                "id": "AwsSolutions-APIG4",
                "reason": "Authorization is implemented via Lambda authorizer", # FIXME: In the next round of changes, we will add the option for OAuth 2.0
            },
            {
                "id": "AwsSolutions-COG4",
                "reason": "Using Lambda authorizer instead of Cognito", # FIXME: In the next round of changes, we will add the option for OAuth 2.0
            },
            {
                "id": "AwsSolutions-APIG1",
                "reason": "Access logging is enabled via deploy options", #
            },
            {
                "id": "AwsSolutions-APIG3",
                "reason": "WAF not required for this internal integration", # TODO: Add WAF integration to ApiGateways
            },
            {
                "id": "AwsSolutions-APIG6",
                "reason": "CloudWatch logging is configured at stage level",
            },
            {
                "id": "AwsSolutions-SMG4",
                "reason": "Secret rotation is configured with 30-day schedule",
            },
        ],
    )

    core.Aspects.of(app).add(checks)
    app.synth()

    if spy.non_compliant_findings:
        print("\n")
        for finding in spy.non_compliant_findings:
            print(f"Non-compliant finding: {finding}")
        assert False, f"Found {len(spy.non_compliant_findings)} non-compliant findings"

class TestConditionalResources:
    """Tests for CfnCondition-based conditional resource creation."""

    def test_use_oauth_condition_exists(self, template):
        """Test that the UseOAuthCondition is defined in the template."""
        conditions = template.find_conditions("*")
        
        condition_keys = list(conditions.keys())
        assert any("UseOAuthCondition" in key for key in condition_keys)

    def test_use_token_auth_condition_exists(self, template):
        """Test that the UseTokenAuthCondition is defined in the template."""
        conditions = template.find_conditions("*")
        
        condition_keys = list(conditions.keys())
        assert any("UseTokenAuthCondition" in key for key in condition_keys)

    def test_combined_condition_exists(self, template):
        """Test that the TemporaryOrCondition combining OAuth and token auth exists."""
        conditions = template.find_conditions("*")
        
        condition_keys = list(conditions.keys())
        assert any("TemporaryOrCondition" in key for key in condition_keys)

    def test_api_gateway_has_condition_applied(self, template):
        """Test that API Gateway resources have the combined condition applied."""
        api_gateways = template.find_resources("AWS::ApiGateway::Authorizer")

        # At least one API Gateway should have a condition
        has_condition = False
        for resource in api_gateways.values():
            if "Condition" in resource:
                has_condition = True
                break
        assert has_condition, "Authorizers should have a condition applied"

    def test_use_oauth_parameter_allowed_values(self, template):
        """Test that useOAuth parameter only allows 'true' or 'false'."""
        parameters = template.find_parameters("*")
        
        oauth_param = None
        for key, value in parameters.items():
            if "useoauth" in key.lower():
                oauth_param = value
                break
        
        assert oauth_param is not None, "useOAuth parameter should exist"
        assert oauth_param.get("AllowedValues") == ["true", "false"]
        assert oauth_param.get("Default") == "false"

    def test_integration_module_parameter_allowed_values(self, template):
        """Test that integrationModule parameter only allows 'itsm' or 'ir'."""
        parameters = template.find_parameters("*")
        
        module_param = None
        for key, value in parameters.items():
            if "integrationmodule" in key.lower():
                module_param = value
                break
        
        assert module_param is not None, "integrationModule parameter should exist"
        assert module_param.get("AllowedValues") == ["itsm", "ir"]
        assert module_param.get("Default") == "itsm"

    def test_condition_evaluates_oauth_parameter(self, template):
        """Test that UseOAuthCondition evaluates the useOAuth parameter."""
        conditions = template.find_conditions("*")
        
        # Find the UseOAuthCondition
        oauth_condition = None
        for key, value in conditions.items():
            if "UseOAuthCondition" in key:
                oauth_condition = value
                break
        
        assert oauth_condition is not None
        # The condition should use Fn::Equals to compare parameter value to "true"
        assert "Fn::Equals" in oauth_condition

    def test_condition_evaluates_token_auth_parameter(self, template):
        """Test that UseTokenAuthCondition evaluates the useOAuth parameter for 'false'."""
        conditions = template.find_conditions("*")
        
        # Find the UseTokenAuthCondition
        token_condition = None
        for key, value in conditions.items():
            if "UseTokenAuthCondition" in key:
                token_condition = value
                break
        
        assert token_condition is not None
        # The condition should use Fn::Equals to compare parameter value to "false"
        assert "Fn::Equals" in token_condition

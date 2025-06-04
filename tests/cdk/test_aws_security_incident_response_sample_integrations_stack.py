import sys

import aws_cdk as core
import cdk_nag
import pytest
from aws_cdk.assertions import Template
from cdk_nag import AwsSolutionsChecks

from aws_security_incident_response_sample_integrations.aws_security_incident_response_sample_integrations_common_stack import (
    AwsSecurityIncidentResponseSampleIntegrationsCommonStack,
)


class Finding:
    def __init__(self, rule_id: str, rule_explanation: str, resource: core.CfnResource):
        self.rule_id = rule_id
        self.rule_explanation = rule_explanation
        self.resource = resource
        self.stack_name = (
            core.Names.unique_id(self.resource.stack)
            if self.resource.stack.nested_stack_parent
            else self.resource.stack.stack_name
        )
        self.resource_id = self.resource.node.path

    def __str__(self):
        return f"{self.resource_id}: {self.rule_id} -- {self.rule_explanation}"


class FindingAggregatorLogger(cdk_nag.AnnotationLogger):
    def __init__(self):
        super().__init__()
        self.non_compliant_findings: list[Finding] = []
        self.suppressed_findings: list[Finding] = []

    def on_non_compliance(
        self,
        *,
        finding_id: str,
        nag_pack_name: str,
        resource: core.CfnResource,
        rule_explanation: str,
        rule_id: str,
        rule_info: str,
        rule_level: cdk_nag.NagMessageLevel,
        rule_original_name: str,
    ) -> None:
        self.non_compliant_findings.append(Finding(rule_id, rule_explanation, resource))

    def on_error(
        self,
        *,
        error_message: str,
        nag_pack_name: str,
        resource: core.CfnResource,
        rule_explanation: str,
        rule_id: str,
        rule_info: str,
        rule_level: cdk_nag.NagMessageLevel,
        rule_original_name: str,
    ) -> None:
        print(f"Error found: {rule_id} - {rule_explanation}")
        sys.exit(1)

    def on_compliance(
        self,
        *,
        nag_pack_name: str,
        resource: core.CfnResource,
        rule_explanation: str,
        rule_id: str,
        rule_info: str,
        rule_level: cdk_nag.NagMessageLevel,
        rule_original_name: str,
    ) -> None:
        pass

    def on_suppressed(
        self,
        *,
        suppression_reason: str,
        finding_id: str,
        nag_pack_name: str,
        resource: core.CfnResource,
        rule_explanation: str,
        rule_id: str,
        rule_info: str,
        rule_level: cdk_nag.NagMessageLevel,
        rule_original_name: str,
    ) -> None:
        self.suppressed_findings.append(Finding(rule_id, rule_explanation, resource))

    def on_not_applicable(
        self,
        *,
        nag_pack_name: str,
        resource: core.CfnResource,
        rule_explanation: str,
        rule_id: str,
        rule_info: str,
        rule_level: cdk_nag.NagMessageLevel,
        rule_original_name: str,
    ) -> None:
        pass

    def on_suppressed_error(
        self,
        *,
        error_suppression_reason: str,
        error_message: str,
        nag_pack_name: str,
        resource: core.CfnResource,
        rule_explanation: str,
        rule_id: str,
        rule_info: str,
        rule_level: cdk_nag.NagMessageLevel,
        rule_original_name: str,
    ) -> None:
        print(f"Suppressed error finding: {rule_id} - {rule_explanation}")


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

    # Add stack-level suppression for L1 rule
    cdk_nag.NagSuppressions.add_stack_suppressions(
        stack,
        [
            {
                "id": "AwsSolutions-L1",
                "reason": "Using the latest available runtime for Python (3.13)",
            }
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
    template.has_resource("AWS::Lambda::Function", {
        "Properties": {
            "Handler": "index.handler"
        }
    })

"""Shared utilities for CDK stack tests.

This module provides common classes and functions used across CDK test files,
including CDK Nag finding aggregation and compliance checking utilities.
"""

import sys

import aws_cdk as core
import cdk_nag


class Finding:
    """Represents a CDK Nag finding.
    
    Attributes:
        rule_id: The CDK Nag rule identifier
        rule_explanation: Description of the rule violation
        resource: The CDK resource that triggered the finding
        stack_name: Name of the stack containing the resource
        resource_id: Path identifier of the resource
    """

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
    """Aggregates CDK Nag findings for test assertions.
    
    This logger collects non-compliant and suppressed findings during CDK Nag
    analysis, allowing tests to assert on compliance results.
    
    Attributes:
        non_compliant_findings: List of findings that violate CDK Nag rules
        suppressed_findings: List of findings that were suppressed
    """

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

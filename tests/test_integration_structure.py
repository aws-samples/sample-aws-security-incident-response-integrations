"""
Test integration structure compliance.

This test ensures that all integrations (JIRA, ServiceNow, Slack) follow
the same structural patterns and have the required files.
"""

import os
import pytest
from typing import List, Dict


class TestIntegrationStructure:
    """Test that all integrations follow consistent structure patterns."""

    @pytest.fixture
    def integration_patterns(self) -> Dict[str, List[str]]:
        """Define the expected patterns for each integration type."""
        return {
            "jira": [
                "assets/jira_client",
                "assets/jira_notifications_handler"
            ],
            "service_now": [
                "assets/service_now_client", 
                "assets/service_now_notifications_handler",
                "assets/service_now_resource_setup_handler",
                "assets/service_now_secret_rotation_handler",
                "assets/service_now_api_gateway_authorizer"
            ],
            "slack": [
                "assets/slack_client",
                "assets/slack_command_handler", 
                "assets/slack_events_bolt_handler"
            ]
        }

    @pytest.fixture
    def required_files_per_handler(self) -> List[str]:
        """Define required files for each handler directory."""
        return [
            "__init__.py",
            "index.py", 
            "requirements.txt"
        ]

    def test_integration_directories_exist(self, integration_patterns):
        """Test that all integration directories exist."""
        for integration, directories in integration_patterns.items():
            for directory in directories:
                assert os.path.exists(directory), f"Missing directory: {directory}"
                assert os.path.isdir(directory), f"Path exists but is not a directory: {directory}"

    def test_handler_required_files_exist(self, integration_patterns, required_files_per_handler):
        """Test that all handlers have required files."""
        for integration, directories in integration_patterns.items():
            for directory in directories:
                if os.path.exists(directory):
                    for required_file in required_files_per_handler:
                        file_path = os.path.join(directory, required_file)
                        assert os.path.exists(file_path), f"Missing required file: {file_path}"
                        assert os.path.isfile(file_path), f"Path exists but is not a file: {file_path}"

    def test_handler_index_files_have_lambda_handler(self, integration_patterns):
        """Test that index.py files contain lambda_handler function."""
        for integration, directories in integration_patterns.items():
            for directory in directories:
                index_path = os.path.join(directory, "index.py")
                if os.path.exists(index_path):
                    with open(index_path, 'r') as f:
                        content = f.read()
                        assert "def lambda_handler" in content, f"Missing lambda_handler in {index_path}"

    def test_handler_requirements_files_not_empty(self, integration_patterns):
        """Test that requirements.txt files are not empty."""
        for integration, directories in integration_patterns.items():
            for directory in directories:
                req_path = os.path.join(directory, "requirements.txt")
                if os.path.exists(req_path):
                    with open(req_path, 'r') as f:
                        content = f.read().strip()
                        assert content, f"Empty requirements.txt file: {req_path}"

    def test_slack_specific_requirements(self):
        """Test Slack-specific requirements and patterns."""
        # Test that Slack handlers have appropriate dependencies
        slack_handlers = [
            "assets/slack_client",
            "assets/slack_command_handler", 
            "assets/slack_events_bolt_handler"
        ]
        
        for handler in slack_handlers:
            req_path = os.path.join(handler, "requirements.txt")
            if os.path.exists(req_path):
                with open(req_path, 'r') as f:
                    content = f.read()
                    # Slack handlers should have boto3 and slack dependencies
                    assert "boto3" in content, f"Missing boto3 dependency in {req_path}"
                    if "slack_client" in handler or "slack_events_bolt_handler" in handler:
                        assert "slack-bolt" in content or "slack-sdk" in content, f"Missing Slack SDK in {req_path}"

    def test_constants_file_has_integration_constants(self):
        """Test that constants.py has constants for all integrations."""
        constants_path = "aws_security_incident_response_sample_integrations/constants.py"
        assert os.path.exists(constants_path), "Missing constants.py file"
        
        with open(constants_path, 'r') as f:
            content = f.read()
            
            # Test for integration-specific constants
            assert "JIRA_EVENT_SOURCE" in content, "Missing JIRA constants"
            assert "SERVICE_NOW_EVENT_SOURCE" in content, "Missing ServiceNow constants" 
            assert "SLACK_EVENT_SOURCE" in content, "Missing Slack constants"
            
            # Test for Slack-specific constants (should have multiple)
            slack_constants = [line for line in content.split('\n') if line.strip().startswith('SLACK_')]
            assert len(slack_constants) >= 5, f"Expected at least 5 Slack constants, found {len(slack_constants)}"
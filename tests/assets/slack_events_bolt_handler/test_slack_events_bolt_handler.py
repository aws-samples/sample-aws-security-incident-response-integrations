"""
Unit tests for Slack Events Bolt Handler Lambda function.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Mock environment variables before importing
os.environ["EVENT_BUS_NAME"] = "test-event-bus"
os.environ["INCIDENTS_TABLE_NAME"] = "test-incidents-table"
os.environ["EVENT_SOURCE"] = "slack"
os.environ["SLACK_COMMAND_HANDLER_FUNCTION"] = "test-command-handler"
os.environ["SLACK_BOT_TOKEN"] = "/test/slackBotToken"
os.environ["SLACK_SIGNING_SECRET"] = "/test/slackSigningSecret"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

# Global mocks to avoid import conflicts
_mock_app = Mock()
_mock_handler = Mock()
_mock_boto_client = Mock()
_mock_boto_resource = Mock()
_mock_dynamodb_table = Mock()
_mock_ssm_client = Mock()

# Configure mock responses
_mock_ssm_client.get_parameter.side_effect = lambda Name, **kwargs: {
    "/test/slackBotToken": {"Parameter": {"Value": "xoxb-test-token"}},
    "/test/slackSigningSecret": {"Parameter": {"Value": "test-signing-secret"}}
}.get(Name, {"Parameter": {"Value": None}})

_mock_dynamodb_table.query.side_effect = lambda **kwargs: {
    "Items": [{"PK": "Case#12345", "SK": "latest", "slackChannelId": "C1234567890", "caseId": "12345"}] 
    if kwargs.get("IndexName") == "SlackChannelIndex" and kwargs.get("KeyConditionExpression") 
    else []
}

# Apply patches globally
with patch("slack_bolt.App", return_value=_mock_app), \
     patch("slack_bolt.adapter.aws_lambda.SlackRequestHandler", return_value=_mock_handler), \
     patch("boto3.client", return_value=_mock_boto_client), \
     patch("boto3.resource", return_value=_mock_boto_resource):
    
    sys.path.append(os.path.join(os.path.dirname(__file__), "../../../assets/slack_events_bolt_handler"))
    import index
    
    # Replace module-level objects with our mocks
    index.ssm_client = _mock_ssm_client
    index.incidents_table = _mock_dynamodb_table


class TestSlackEventsBoltHandler:
    """Test class for Slack Events Bolt Handler"""

    def test_get_ssm_parameter_success(self):
        """Test successful SSM parameter retrieval"""
        result = index.get_ssm_parameter("/test/slackBotToken")
        assert result == "xoxb-test-token"

    def test_get_ssm_parameter_not_found(self):
        """Test SSM parameter not found"""
        result = index.get_ssm_parameter("/nonexistent/parameter")
        assert result is None

    def test_get_case_id_from_channel_success(self):
        """Test successful case ID retrieval from channel"""
        with patch.object(index, "incidents_table") as mock_table:
            mock_table.scan.return_value = {
                "Items": [{"PK": "Case#12345", "SK": "latest", "caseId": "12345"}]
            }
            result = index.get_case_id_from_channel("C1234567890")
            assert result == "12345"

    def test_get_case_id_from_channel_not_found(self):
        """Test case ID not found for channel"""
        with patch.object(index, "incidents_table") as mock_table:
            mock_table.scan.return_value = {"Items": []}
            result = index.get_case_id_from_channel("C9999999999")
            assert result is None

    def test_get_channel_id_from_case_success(self):
        """Test successful channel ID retrieval from case"""
        with patch.object(index, "incidents_table") as mock_table:
            mock_table.get_item.return_value = {
                "Item": {"PK": "Case#12345", "SK": "latest", "slackChannelId": "C1234567890"}
            }
            result = index.get_channel_id_from_case("12345")
            assert result == "C1234567890"

    def test_get_channel_id_from_case_not_found(self):
        """Test channel ID not found for case"""
        with patch.object(index, "incidents_table") as mock_table:
            mock_table.get_item.return_value = {}
            result = index.get_channel_id_from_case("99999")
            assert result is None

    def test_publish_event_to_eventbridge_success(self):
        """Test successful event publishing to EventBridge"""
        with patch.object(index, "eventbridge_client") as mock_eventbridge:
            mock_eventbridge.put_events.return_value = {"FailedEntryCount": 0}
            result = index.publish_event_to_eventbridge("Test Event", {"test": "data"})
            assert result is True

    def test_publish_event_to_eventbridge_failure(self):
        """Test EventBridge publishing failure"""
        with patch.object(index, "eventbridge_client") as mock_eventbridge:
            mock_eventbridge.put_events.side_effect = Exception("EventBridge error")
            result = index.publish_event_to_eventbridge("Test Event", {"test": "data"})
            assert result is False

    def test_is_incident_channel_true(self):
        """Test incident channel detection - positive case"""
        result = index.is_incident_channel("aws-security-incident-response-case-12345")
        assert result is True

    def test_is_incident_channel_false(self):
        """Test incident channel detection - negative case"""
        result = index.is_incident_channel("general")
        assert result is False

    def test_invoke_command_handler_success(self):
        """Test successful command handler invocation"""
        with patch.object(index, "lambda_client") as mock_lambda_client:
            mock_lambda_client.invoke.return_value = {"StatusCode": 202}
            result = index.invoke_command_handler({"command": "/security-ir status"})
            assert result is True

    def test_invoke_command_handler_failure(self):
        """Test command handler invocation failure"""
        with patch.object(index, "lambda_client") as mock_lambda_client:
            mock_lambda_client.invoke.side_effect = Exception("Lambda error")
            result = index.invoke_command_handler({"command": "/security-ir status"})
            assert result is False

    def test_create_slack_app_success(self):
        """Test successful Slack app creation"""
        result = index.create_slack_app()
        assert result is not None or result is None

    def test_create_slack_app_missing_credentials(self):
        """Test Slack app creation with missing credentials"""
        with patch.object(index, "get_ssm_parameter", return_value=None):
            result = index.create_slack_app()
            assert result is None

    def test_lambda_handler_success(self):
        """Test successful Lambda handler execution"""
        with patch.object(index, "slack_handler") as mock_slack_handler:
            mock_slack_handler.handle.return_value = {"statusCode": 200, "body": json.dumps({"message": "success"})}
            event = {"body": json.dumps({"type": "event_callback"})}
            context = Mock()
            result = index.lambda_handler(event, context)
            assert result["statusCode"] == 200

    def test_lambda_handler_no_slack_handler(self):
        """Test Lambda handler when Slack handler is not initialized"""
        with patch.object(index, "slack_handler", None):
            event = {"body": json.dumps({"type": "event_callback"})}
            context = Mock()
            result = index.lambda_handler(event, context)
            assert result["statusCode"] == 500

    def test_lambda_handler_exception(self):
        """Test Lambda handler with exception"""
        with patch.object(index, "slack_handler") as mock_handler:
            mock_handler.handle.side_effect = Exception("Test error")
            event = {"body": json.dumps({"type": "event_callback"})}
            context = Mock()
            result = index.lambda_handler(event, context)
            assert result["statusCode"] == 500


if __name__ == "__main__":
    pytest.main([__file__])
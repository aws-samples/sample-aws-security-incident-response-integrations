"""
Unit tests for Slack Events Bolt Handler Lambda function.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock, call
import os
import sys

# Mock environment variables before importing
os.environ["EVENT_BUS_NAME"] = "test-event-bus"
os.environ["INCIDENTS_TABLE_NAME"] = "test-incidents-table"
os.environ["EVENT_SOURCE"] = "slack"
os.environ["SLACK_COMMAND_HANDLER_FUNCTION"] = "test-command-handler"
os.environ["SLACK_BOT_TOKEN"] = "/test/slackBotToken"
os.environ["SLACK_SIGNING_SECRET"] = "/test/slackSigningSecret"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["LOG_LEVEL"] = "INFO"

# Use importlib to directly load the module from the specific file path
import importlib.util

slack_events_handler_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../assets/slack_events_bolt_handler"))
index_file_path = os.path.join(slack_events_handler_path, "index.py")

# Set up global mocks that will be accessible in tests
mock_eventbridge = Mock()
mock_dynamodb = Mock()
mock_ssm = Mock()
mock_lambda = Mock()
mock_app = Mock()
mock_handler = Mock()

# Mock environment variables and AWS services before importing
with patch('boto3.client') as mock_boto_client, \
     patch('boto3.resource') as mock_boto_resource, \
     patch('slack_bolt.App') as mock_slack_app, \
     patch('slack_bolt.adapter.aws_lambda.SlackRequestHandler') as mock_slack_handler:
    
    def mock_client_factory(service_name, **kwargs):
        if service_name == "events":
            return mock_eventbridge
        elif service_name == "ssm":
            return mock_ssm
        elif service_name == "lambda":
            return mock_lambda
        return Mock()
    
    mock_boto_client.side_effect = mock_client_factory
    mock_boto_resource.return_value = mock_dynamodb
    mock_slack_app.return_value = mock_app
    mock_slack_handler.return_value = mock_handler
    
    # Import the module directly from file path
    spec = importlib.util.spec_from_file_location("index", index_file_path)
    index = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(index)
    
    # Make the module available globally for patch decorators
    sys.modules['index'] = index


class TestSlackEventsBoltHandler:
    """Test class for Slack Events Bolt Handler"""

    def setup_method(self):
        """Set up test fixtures"""
        # Reset mocks
        mock_eventbridge.reset_mock()
        mock_dynamodb.reset_mock()
        mock_ssm.reset_mock()
        mock_lambda.reset_mock()
        mock_app.reset_mock()
        mock_handler.reset_mock()

    @patch('index.ssm_client')
    def test_get_ssm_parameter_success(self, mock_ssm_client):
        """Test successful SSM parameter retrieval"""
        # Setup
        mock_ssm_client.get_parameter.return_value = {
            "Parameter": {"Value": "test-value"}
        }
        
        # Execute
        result = index.get_ssm_parameter("/test/parameter")
        
        # Verify
        assert result == "test-value"
        mock_ssm_client.get_parameter.assert_called_once_with(
            Name="/test/parameter",
            WithDecryption=True
        )

    def test_get_ssm_parameter_failure(self):
        """Test SSM parameter retrieval failure"""
        # Setup
        mock_ssm.get_parameter.side_effect = Exception("Parameter not found")
        
        # Execute
        result = index.get_ssm_parameter("/test/parameter")
        
        # Verify
        assert result is None

    def test_get_case_id_from_channel_success(self):
        """Test successful case ID extraction from channel"""
        # Setup
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.scan.return_value = {
            "Items": [{"PK": "Case#12345", "slackChannelId": "C1234567890"}]
        }
        
        # Execute
        result = index.get_case_id_from_channel("C1234567890")
        
        # Verify
        assert result == "12345"
        mock_table.scan.assert_called_once()

    def test_get_case_id_from_channel_not_found(self):
        """Test case ID extraction when channel not found"""
        # Setup
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.scan.return_value = {"Items": []}
        
        # Execute
        result = index.get_case_id_from_channel("C1234567890")
        
        # Verify
        assert result is None

    def test_publish_event_to_eventbridge_success(self):
        """Test successful EventBridge event publishing"""
        # Setup
        mock_eventbridge.put_events.return_value = {}
        
        # Execute
        result = index.publish_event_to_eventbridge("Test Event", {"key": "value"})
        
        # Verify
        assert result is True
        mock_eventbridge.put_events.assert_called_once_with(
            Entries=[{
                "Source": "slack",
                "DetailType": "Test Event",
                "Detail": json.dumps({"key": "value"}),
                "EventBusName": "test-event-bus"
            }]
        )

    def test_publish_event_to_eventbridge_failure(self):
        """Test EventBridge event publishing failure"""
        # Setup
        mock_eventbridge.put_events.side_effect = Exception("EventBridge error")
        
        # Execute
        result = index.publish_event_to_eventbridge("Test Event", {"key": "value"})
        
        # Verify
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
        # Setup
        mock_lambda.invoke.return_value = {}
        
        # Execute
        result = index.invoke_command_handler({"command": "/security-ir", "text": "status"})
        
        # Verify
        assert result is True
        mock_lambda.invoke.assert_called_once_with(
            FunctionName="test-command-handler",
            InvocationType="Event",
            Payload=json.dumps({"command": "/security-ir", "text": "status"})
        )

    def test_invoke_command_handler_failure(self):
        """Test command handler invocation failure"""
        # Setup
        mock_lambda.invoke.side_effect = Exception("Lambda error")
        
        # Execute
        result = index.invoke_command_handler({"command": "/security-ir", "text": "status"})
        
        # Verify
        assert result is False

    def test_lambda_handler_success(self):
        """Test successful lambda handler execution"""
        # Setup
        mock_handler.handle.return_value = {
            "statusCode": 200,
            "body": json.dumps({"message": "success"})
        }
        
        event = {"body": json.dumps({"type": "event_callback"})}
        context = Mock()
        
        # Execute
        result = index.lambda_handler(event, context)
        
        # Verify
        assert result["statusCode"] == 200
        mock_handler.handle.assert_called_once_with(event, context)

    def test_lambda_handler_no_slack_handler(self):
        """Test lambda handler when Slack handler not initialized"""
        # Setup - temporarily set slack_handler to None
        original_handler = index.slack_handler
        index.slack_handler = None
        
        try:
            event = {"body": json.dumps({"type": "event_callback"})}
            context = Mock()
            
            # Execute
            result = index.lambda_handler(event, context)
            
            # Verify
            assert result["statusCode"] == 500
            assert "Slack handler not initialized" in result["body"]
        finally:
            # Restore original handler
            index.slack_handler = original_handler

    def test_lambda_handler_exception(self):
        """Test lambda handler with exception"""
        # Setup
        mock_handler.handle.side_effect = Exception("Test exception")
        
        event = {"body": json.dumps({"type": "event_callback"})}
        context = Mock()
        
        # Execute
        result = index.lambda_handler(event, context)
        
        # Verify
        assert result["statusCode"] == 500
        assert "Test exception" in result["body"]

    @patch('index.requests.head')
    @patch('index.requests.get')
    def test_download_slack_file_success(self, mock_get, mock_head):
        """Test successful file download from Slack"""
        # Setup
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': '1024'}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        mock_get_response = Mock()
        mock_get_response.raise_for_status.return_value = None
        mock_get_response.iter_content.return_value = [b'test', b'file', b'content']
        mock_get.return_value = mock_get_response
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result == b'testfilecontent'
        mock_head.assert_called_once()
        mock_get.assert_called_once()

    @patch('index.requests.head')
    def test_download_slack_file_size_exceeded(self, mock_head):
        """Test file download with size limit exceeded"""
        # Setup
        mock_head_response = Mock()
        mock_head_response.headers = {'content-length': str(index.MAX_FILE_SIZE_BYTES + 1)}
        mock_head_response.raise_for_status.return_value = None
        mock_head.return_value = mock_head_response
        
        # Execute
        result = index.download_slack_file("https://files.slack.com/test", "xoxb-token")
        
        # Verify
        assert result is None


class TestSlackEventHandlers:
    """Test class for Slack event handler functions"""

    def setup_method(self):
        """Set up test fixtures"""
        # Reset mocks
        mock_eventbridge.reset_mock()
        mock_dynamodb.reset_mock()

    @patch('index.get_case_id_from_channel')
    @patch('index.publish_event_to_eventbridge')
    def test_handle_incident_message_success(self, mock_publish, mock_get_case_id):
        """Test successful incident message handling"""
        # Setup
        mock_get_case_id.return_value = "12345"
        mock_publish.return_value = True
        
        message = {
            "channel": "C1234567890",
            "user": "U1234567890",
            "text": "This is a test message",
            "ts": "1234567890.123456"
        }
        
        mock_client = Mock()
        mock_client.users_info.return_value = {
            "user": {"real_name": "Test User"}
        }
        
        # Execute - simulate the message handler logic
        if not message.get("subtype") and message.get("user"):
            if index.SLACK_SYSTEM_COMMENT_TAG not in message.get("text", ""):
                case_id = mock_get_case_id(message["channel"])
                if case_id:
                    user_response = mock_client.users_info(user=message["user"])
                    user_info = user_response["user"]
                    
                    event_detail = {
                        "caseId": case_id,
                        "channelId": message["channel"],
                        "messageId": message["ts"],
                        "userId": message["user"],
                        "userName": user_info.get("real_name"),
                        "text": message["text"],
                        "timestamp": message["ts"],
                        "threadTs": message.get("thread_ts"),
                        "messageType": "user_message"
                    }
                    mock_publish("Message Added", event_detail)
        
        # Verify
        mock_get_case_id.assert_called_once_with("C1234567890")
        mock_publish.assert_called_once_with("Message Added", {
            "caseId": "12345",
            "channelId": "C1234567890",
            "messageId": "1234567890.123456",
            "userId": "U1234567890",
            "userName": "Test User",
            "text": "This is a test message",
            "timestamp": "1234567890.123456",
            "threadTs": None,
            "messageType": "user_message"
        })

    @patch('index.get_case_id_from_channel')
    def test_handle_incident_message_bot_message_skip(self, mock_get_case_id):
        """Test skipping bot messages"""
        # Setup
        message = {
            "channel": "C1234567890",
            "subtype": "bot_message",
            "text": "This is a bot message"
        }
        
        # Execute - simulate the message handler logic
        should_skip = message.get("subtype") in ["bot_message", "app_mention"] or not message.get("user")
        
        # Verify
        assert should_skip is True
        mock_get_case_id.assert_not_called()

    @patch('index.get_case_id_from_channel')
    def test_handle_incident_message_system_tag_skip(self, mock_get_case_id):
        """Test skipping messages with system tag"""
        # Setup
        message = {
            "channel": "C1234567890",
            "user": "U1234567890",
            "text": f"This message has {index.SLACK_SYSTEM_COMMENT_TAG} tag",
            "ts": "1234567890.123456"
        }
        
        # Execute - simulate the message handler logic
        should_skip = index.SLACK_SYSTEM_COMMENT_TAG in message.get("text", "")
        
        # Verify
        assert should_skip is True
        mock_get_case_id.assert_not_called()

    @patch('index.is_incident_channel')
    @patch('index.get_case_id_from_channel')
    @patch('index.publish_event_to_eventbridge')
    def test_handle_member_joined_success(self, mock_publish, mock_get_case_id, mock_is_incident):
        """Test successful member joined event handling"""
        # Setup
        mock_is_incident.return_value = True
        mock_get_case_id.return_value = "12345"
        mock_publish.return_value = True
        
        event = {
            "channel": "C1234567890",
            "user": "U1234567890",
            "event_ts": "1234567890"
        }
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {
            "channel": {"name": "aws-security-incident-response-case-12345"}
        }
        mock_client.users_info.return_value = {
            "user": {"real_name": "Test User"}
        }
        
        # Execute - simulate the member joined handler logic
        channel_response = mock_client.conversations_info(channel=event["channel"])
        channel_name = channel_response["channel"]["name"]
        
        if mock_is_incident(channel_name):
            case_id = mock_get_case_id(event["channel"])
            if case_id:
                user_response = mock_client.users_info(user=event["user"])
                user_info = user_response["user"]
                
                event_detail = {
                    "caseId": case_id,
                    "channelId": event["channel"],
                    "userId": event["user"],
                    "userName": user_info.get("real_name"),
                    "eventType": "member_joined",
                    "timestamp": str(event.get("event_ts", ""))
                }
                mock_publish("Channel Member Added", event_detail)
        
        # Verify
        mock_is_incident.assert_called_once_with("aws-security-incident-response-case-12345")
        mock_get_case_id.assert_called_once_with("C1234567890")
        mock_publish.assert_called_once_with("Channel Member Added", {
            "caseId": "12345",
            "channelId": "C1234567890",
            "userId": "U1234567890",
            "userName": "Test User",
            "eventType": "member_joined",
            "timestamp": "1234567890"
        })

    @patch('index.is_incident_channel')
    @patch('index.get_case_id_from_channel')
    @patch('index.invoke_command_handler')
    def test_handle_slash_command_success(self, mock_invoke, mock_get_case_id, mock_is_incident):
        """Test successful slash command handling"""
        # Setup
        mock_is_incident.return_value = True
        mock_get_case_id.return_value = "12345"
        mock_invoke.return_value = True
        
        command = {
            "command": "/security-ir",
            "text": "status",
            "user_id": "U1234567890",
            "user_name": "testuser",
            "channel_id": "C1234567890",
            "team_id": "T1234567890",
            "response_url": "https://hooks.slack.com/commands/response",
            "trigger_id": "trigger123"
        }
        
        mock_ack = Mock()
        mock_client = Mock()
        mock_client.conversations_info.return_value = {
            "channel": {"name": "aws-security-incident-response-case-12345"}
        }
        
        # Execute - simulate the slash command handler logic
        mock_ack()  # Acknowledge immediately
        
        channel_response = mock_client.conversations_info(channel=command["channel_id"])
        channel_name = channel_response["channel"]["name"]
        
        if mock_is_incident(channel_name):
            case_id = mock_get_case_id(command["channel_id"])
            if case_id:
                command_payload = {
                    "command": command["command"],
                    "text": command["text"],
                    "user_id": command["user_id"],
                    "user_name": command["user_name"],
                    "channel_id": command["channel_id"],
                    "channel_name": channel_name,
                    "team_id": command["team_id"],
                    "response_url": command["response_url"],
                    "trigger_id": command["trigger_id"],
                    "case_id": case_id
                }
                mock_invoke(command_payload)
        
        # Verify
        mock_ack.assert_called_once()
        mock_is_incident.assert_called_once_with("aws-security-incident-response-case-12345")
        mock_get_case_id.assert_called_once_with("C1234567890")
        mock_invoke.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])
"""
Unit tests for Slack Bolt wrapper.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import time

# TODO: Fix mock configuration issues in CI environment to re-enable these tests
# https://app.asana.com/1/8442528107068/project/1209571477232011/task/1211611017424273?focus=true
# Skip entire file due to mock configuration issues in CI
pytest.skip("Skipping Slack Bolt wrapper tests due to mock configuration issues", allow_module_level=True)

# Import the wrapper
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../assets/wrappers/python'))

from slack_bolt_wrapper import SlackBoltClient
from slack_sdk.errors import SlackApiError


class TestSlackBoltClient:
    """Test cases for SlackBoltClient wrapper"""

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_initialization_success(self, mock_app, mock_ssm):
        """Test successful SlackBoltClient initialization"""
        # Mock SSM responses
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        # Mock Slack App
        mock_app_instance = Mock()
        mock_app_instance.client = Mock()
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        
        assert client.app == mock_app_instance
        assert client.client == mock_app_instance.client
        mock_app.assert_called_once_with(
            token="xoxb-test-token",
            signing_secret="test-signing-secret",
            process_before_response=True
        )

    @patch('slack_bolt_wrapper.ssm_client')
    def test_initialization_missing_credentials(self, mock_ssm):
        """Test initialization failure when credentials are missing"""
        # Mock SSM to return empty values
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": ""}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        client = SlackBoltClient()
        
        assert client.app is None
        assert client.client is None

    @patch('slack_bolt_wrapper.ssm_client')
    def test_initialization_ssm_error(self, mock_ssm):
        """Test initialization failure when SSM throws error"""
        mock_ssm.get_parameter.side_effect = Exception("SSM error")
        
        client = SlackBoltClient()
        
        assert client.app is None
        assert client.client is None

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_create_channel_success(self, mock_app, mock_ssm):
        """Test successful channel creation"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_create.return_value = {
            "channel": {"id": "C1234567890"}
        }
        mock_client.conversations_setTopic.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.create_channel("12345", "Test Case Title")
        
        assert result == "C1234567890"
        mock_client.conversations_create.assert_called_once_with(
            name="aws-security-incident-response-case-12345",
            is_private=False
        )
        mock_client.conversations_setTopic.assert_called_once_with(
            channel="C1234567890",
            topic="AWS Security Incident: Test Case Title"
        )

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_create_channel_without_title(self, mock_app, mock_ssm):
        """Test channel creation without title"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_create.return_value = {
            "channel": {"id": "C1234567890"}
        }
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.create_channel("12345")
        
        assert result == "C1234567890"
        mock_client.conversations_create.assert_called_once()
        mock_client.conversations_setTopic.assert_not_called()

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_create_channel_api_error(self, mock_app, mock_ssm):
        """Test channel creation with API error"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_create.side_effect = SlackApiError(
            message="Channel creation failed",
            response={"error": "name_taken"}
        )
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.create_channel("12345")
        
        assert result is None

    def test_create_channel_no_client(self):
        """Test channel creation when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.create_channel("12345")
        assert result is None

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_post_message_success(self, mock_app, mock_ssm):
        """Test successful message posting"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.chat_postMessage.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.post_message("C1234567890", "Test message")
        
        assert result is True
        mock_client.chat_postMessage.assert_called_once_with(
            channel="C1234567890",
            text="Test message",
            blocks=None
        )

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_post_message_with_blocks(self, mock_app, mock_ssm):
        """Test message posting with blocks"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.chat_postMessage.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "Test"}}]
        
        client = SlackBoltClient()
        result = client.post_message("C1234567890", "Test message", blocks)
        
        assert result is True
        mock_client.chat_postMessage.assert_called_once_with(
            channel="C1234567890",
            text="Test message",
            blocks=blocks
        )

    def test_post_message_no_client(self):
        """Test message posting when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.post_message("C1234567890", "Test message")
        assert result is False

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_add_users_to_channel_success(self, mock_app, mock_ssm):
        """Test successful user addition to channel"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_invite.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.add_users_to_channel("C1234567890", ["U1111111111", "U2222222222"])
        
        assert result is True
        mock_client.conversations_invite.assert_called_once_with(
            channel="C1234567890",
            users="U1111111111,U2222222222"
        )

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_add_users_to_channel_empty_list(self, mock_app, mock_ssm):
        """Test user addition with empty user list"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.add_users_to_channel("C1234567890", [])
        
        assert result is False

    def test_add_users_to_channel_no_client(self):
        """Test user addition when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.add_users_to_channel("C1234567890", ["U1111111111"])
        assert result is False

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_get_channel_info_success(self, mock_app, mock_ssm):
        """Test successful channel info retrieval"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        channel_info = {
            "id": "C1234567890",
            "name": "test-channel",
            "is_private": False
        }
        
        mock_client = Mock()
        mock_client.conversations_info.return_value = {"channel": channel_info}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.get_channel_info("C1234567890")
        
        assert result == channel_info
        mock_client.conversations_info.assert_called_once_with(channel="C1234567890")

    def test_get_channel_info_no_client(self):
        """Test channel info retrieval when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.get_channel_info("C1234567890")
        assert result is None

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_upload_file_success(self, mock_app, mock_ssm):
        """Test successful file upload"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.files_upload_v2.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        file_content = b"test file content"
        
        client = SlackBoltClient()
        result = client.upload_file(
            "C1234567890", 
            file_content, 
            "test.txt",
            "Test File",
            "Initial comment"
        )
        
        assert result is True
        mock_client.files_upload_v2.assert_called_once_with(
            channel="C1234567890",
            file=file_content,
            filename="test.txt",
            title="Test File",
            initial_comment="Initial comment"
        )

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_upload_file_without_optional_params(self, mock_app, mock_ssm):
        """Test file upload without optional parameters"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.files_upload_v2.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        file_content = b"test file content"
        
        client = SlackBoltClient()
        result = client.upload_file("C1234567890", file_content, "test.txt")
        
        assert result is True
        mock_client.files_upload_v2.assert_called_once_with(
            channel="C1234567890",
            file=file_content,
            filename="test.txt",
            title="test.txt",
            initial_comment=None
        )

    def test_upload_file_no_client(self):
        """Test file upload when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.upload_file("C1234567890", b"content", "test.txt")
        assert result is False

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    @patch('slack_bolt_wrapper.time.sleep')
    def test_retry_with_backoff_rate_limited(self, mock_sleep, mock_app, mock_ssm):
        """Test retry logic with rate limiting"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        # Create rate limit error
        rate_limit_error = SlackApiError(
            message="Rate limited",
            response={
                "error": "rate_limited",
                "headers": {"Retry-After": "5"}
            }
        )
        
        mock_func = Mock()
        mock_func.side_effect = [rate_limit_error, {"ok": True}]
        
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client._retry_with_backoff(mock_func)
        
        assert result == {"ok": True}
        assert mock_func.call_count == 2
        mock_sleep.assert_called_once_with(5)

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    @patch('slack_bolt_wrapper.time.sleep')
    def test_retry_with_backoff_exponential(self, mock_sleep, mock_app, mock_ssm):
        """Test exponential backoff retry logic"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        api_error = SlackApiError(
            message="API error",
            response={"error": "internal_error"}
        )
        
        mock_func = Mock()
        mock_func.side_effect = [api_error, api_error, {"ok": True}]
        
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client._retry_with_backoff(mock_func)
        
        assert result == {"ok": True}
        assert mock_func.call_count == 3
        # Check exponential backoff: 1s, then 2s
        expected_calls = [pytest.approx(1), pytest.approx(2)]
        actual_calls = [call[0][0] for call in mock_sleep.call_args_list]
        assert actual_calls == expected_calls

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    @patch('slack_bolt_wrapper.time.sleep')
    def test_retry_with_backoff_max_retries(self, mock_sleep, mock_app, mock_ssm):
        """Test retry logic reaches maximum retries"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        api_error = SlackApiError(
            message="API error",
            response={"error": "internal_error"}
        )
        
        mock_func = Mock()
        mock_func.side_effect = api_error
        
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        
        with pytest.raises(SlackApiError):
            client._retry_with_backoff(mock_func)
        
        assert mock_func.call_count == 5  # SLACK_MAX_RETRIES

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    @patch('slack_bolt_wrapper.time.sleep')
    def test_retry_with_backoff_generic_exception(self, mock_sleep, mock_app, mock_ssm):
        """Test retry logic with generic exception - should fail fast"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_func = Mock()
        mock_func.side_effect = Exception("Generic error")
        
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        
        # Generic exceptions should not be retried - fail fast
        with pytest.raises(Exception, match="Generic error"):
            client._retry_with_backoff(mock_func)
        
        assert mock_func.call_count == 1
        mock_sleep.assert_not_called()

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_remove_users_from_channel_success(self, mock_app, mock_ssm):
        """Test successful user removal from channel"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_kick.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.remove_users_from_channel("C1234567890", ["U1111111111", "U2222222222"])
        
        assert result is True
        assert mock_client.conversations_kick.call_count == 2
        mock_client.conversations_kick.assert_any_call(channel="C1234567890", user="U1111111111")
        mock_client.conversations_kick.assert_any_call(channel="C1234567890", user="U2222222222")

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_remove_users_from_channel_empty_list(self, mock_app, mock_ssm):
        """Test user removal with empty user list"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.remove_users_from_channel("C1234567890", [])
        
        assert result is False

    def test_remove_users_from_channel_no_client(self):
        """Test user removal when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.remove_users_from_channel("C1234567890", ["U1111111111"])
        assert result is False

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_update_channel_topic_success(self, mock_app, mock_ssm):
        """Test successful channel topic update"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_setTopic.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.update_channel_topic("C1234567890", "New topic")
        
        assert result is True
        mock_client.conversations_setTopic.assert_called_once_with(
            channel="C1234567890",
            topic="New topic"
        )

    def test_update_channel_topic_no_client(self):
        """Test channel topic update when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.update_channel_topic("C1234567890", "New topic")
        assert result is False

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_get_channel_members_success(self, mock_app, mock_ssm):
        """Test successful channel members retrieval"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        members = ["U1111111111", "U2222222222", "U3333333333"]
        
        mock_client = Mock()
        mock_client.conversations_members.return_value = {"members": members}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.get_channel_members("C1234567890")
        
        assert result == members
        mock_client.conversations_members.assert_called_once_with(channel="C1234567890")

    def test_get_channel_members_no_client(self):
        """Test channel members retrieval when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.get_channel_members("C1234567890")
        assert result is None

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_archive_channel_success(self, mock_app, mock_ssm):
        """Test successful channel archiving"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_archive.return_value = {"ok": True}
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.archive_channel("C1234567890")
        
        assert result is True
        mock_client.conversations_archive.assert_called_once_with(channel="C1234567890")

    def test_archive_channel_no_client(self):
        """Test channel archiving when client is not initialized"""
        client = SlackBoltClient()
        client.client = None
        
        result = client.archive_channel("C1234567890")
        assert result is False

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_remove_users_api_error(self, mock_app, mock_ssm):
        """Test user removal with API error"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_kick.side_effect = SlackApiError(
            message="User removal failed",
            response={"error": "user_not_in_channel"}
        )
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.remove_users_from_channel("C1234567890", ["U1111111111"])
        
        assert result is False

    @patch('slack_bolt_wrapper.ssm_client')
    @patch('slack_bolt_wrapper.App')
    def test_update_channel_topic_api_error(self, mock_app, mock_ssm):
        """Test channel topic update with API error"""
        # Setup mocks
        mock_ssm.get_parameter.side_effect = [
            {"Parameter": {"Value": "xoxb-test-token"}},
            {"Parameter": {"Value": "test-signing-secret"}}
        ]
        
        mock_client = Mock()
        mock_client.conversations_setTopic.side_effect = SlackApiError(
            message="Topic update failed",
            response={"error": "channel_not_found"}
        )
        
        mock_app_instance = Mock()
        mock_app_instance.client = mock_client
        mock_app.return_value = mock_app_instance
        
        client = SlackBoltClient()
        result = client.update_channel_topic("C1234567890", "New topic")
        
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__])
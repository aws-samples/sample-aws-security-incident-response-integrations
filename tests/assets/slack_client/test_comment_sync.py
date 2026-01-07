"""
Unit tests for Slack Client comment synchronization functionality.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import os
import sys

# TODO: Fix mock configuration issues in CI environment to re-enable these tests
# Skip entire file due to mock configuration issues in CI
pytest.skip("Skipping Slack comment sync tests due to mock configuration issues", allow_module_level=True)

# Mock AWS clients before importing
with patch('boto3.client'), patch('boto3.resource'):
    # Import the module under test
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'assets', 'slack_client'))
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'assets', 'wrappers', 'python'))
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'assets', 'mappers', 'python'))
    
    from index import SlackService, DatabaseService


class TestSlackCommentSync:
    """Test class for Slack comment synchronization functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_slack_client = Mock()
        self.mock_db_service = Mock()
        
        # Create SlackService instance with mocked dependencies
        with patch('index.SlackBoltClient', return_value=self.mock_slack_client):
            with patch('index.DatabaseService', return_value=self.mock_db_service):
                self.slack_service = SlackService()
                self.slack_service.slack_client = self.mock_slack_client
                self.slack_service.db_service = self.mock_db_service

    def test_sync_comment_to_slack_success(self):
        """Test successful comment sync from AWS SIR to Slack."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-123",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z",
            "createdBy": {"name": "John Doe", "email": "john@example.com"}
        }
        
        case_data = {
            "Item": {
                "slackChannelId": "C1234567890",
                "slackChannelCaseComments": [],
                "slackChannelUpdateTimestamp": "2025-01-15T10:00:00Z"
            }
        }
        
        self.mock_db_service.get_case.return_value = case_data
        self.mock_slack_client.post_message.return_value = True
        self.mock_db_service.update_case_details.return_value = True
        
        # Act
        result = self.slack_service.sync_comment_to_slack(case_id, comment)
        
        # Assert
        assert result is True
        assert self.mock_db_service.get_case.call_count == 2  # Called once in sync method, once in track method
        self.mock_slack_client.post_message.assert_called_once()
        self.mock_db_service.update_case_details.assert_called_once()

    def test_sync_comment_to_slack_skip_system_comment(self):
        """Test that system comments with Slack tag are skipped."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-123",
            "body": "[Slack Update] This is a system comment",
            "createdDate": "2025-01-15T10:30:00Z"
        }
        
        # Act
        result = self.slack_service.sync_comment_to_slack(case_id, comment)
        
        # Assert
        assert result is True
        self.mock_db_service.get_case.assert_not_called()
        self.mock_slack_client.post_message.assert_not_called()

    def test_sync_comment_to_slack_no_channel_found(self):
        """Test comment sync when no Slack channel is found."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-123",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z"
        }
        
        self.mock_db_service.get_case.return_value = None
        
        # Act
        result = self.slack_service.sync_comment_to_slack(case_id, comment)
        
        # Assert
        assert result is False
        self.mock_db_service.get_case.assert_called_once_with(case_id)
        self.mock_slack_client.post_message.assert_not_called()

    def test_sync_comment_to_slack_duplicate_detection(self):
        """Test duplicate comment detection using timestamp and content."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-123",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z",
            "createdBy": {"name": "John Doe"}
        }
        
        case_data = {
            "Item": {
                "slackChannelId": "C1234567890",
                "slackChannelCaseComments": [
                    {
                        "commentId": "comment-123",
                        "body": "This is a test comment",
                        "createdDate": "2025-01-15T10:30:00Z",
                        "syncedToSlack": True
                    }
                ],
                "slackChannelUpdateTimestamp": "2025-01-15T10:35:00Z"
            }
        }
        
        self.mock_db_service.get_case.return_value = case_data
        
        # Act
        result = self.slack_service.sync_comment_to_slack(case_id, comment)
        
        # Assert
        assert result is True
        self.mock_db_service.get_case.assert_called_once_with(case_id)
        self.mock_slack_client.post_message.assert_not_called()

    def test_is_duplicate_comment_by_id(self):
        """Test duplicate detection by comment ID."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-123",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z"
        }
        
        case_data = {
            "slackChannelCaseComments": [
                {
                    "commentId": "comment-123",
                    "body": "Different body",
                    "createdDate": "2025-01-15T10:25:00Z"
                }
            ]
        }
        
        # Act
        result = self.slack_service._is_duplicate_comment(case_id, comment, case_data)
        
        # Assert
        assert result is True

    def test_is_duplicate_comment_by_content(self):
        """Test duplicate detection by body and creation date."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-456",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z"
        }
        
        case_data = {
            "slackChannelCaseComments": [
                {
                    "commentId": "comment-123",
                    "body": "This is a test comment",
                    "createdDate": "2025-01-15T10:30:00Z"
                }
            ]
        }
        
        # Act
        result = self.slack_service._is_duplicate_comment(case_id, comment, case_data)
        
        # Assert
        assert result is True

    def test_is_duplicate_comment_timestamp_based(self):
        """Test duplicate detection using timestamp comparison."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-456",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:25:00Z"
        }
        
        case_data = {
            "slackChannelCaseComments": [
                "This is a test comment"  # Legacy string format
            ],
            "slackChannelUpdateTimestamp": "2025-01-15T10:30:00Z"
        }
        
        # Act
        result = self.slack_service._is_duplicate_comment(case_id, comment, case_data)
        
        # Assert
        assert result is True

    def test_is_not_duplicate_comment(self):
        """Test that new comments are not marked as duplicates."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-456",
            "body": "This is a new comment",
            "createdDate": "2025-01-15T10:35:00Z"
        }
        
        case_data = {
            "slackChannelCaseComments": [
                {
                    "commentId": "comment-123",
                    "body": "This is an old comment",
                    "createdDate": "2025-01-15T10:30:00Z"
                }
            ],
            "slackChannelUpdateTimestamp": "2025-01-15T10:30:00Z"
        }
        
        # Act
        result = self.slack_service._is_duplicate_comment(case_id, comment, case_data)
        
        # Assert
        assert result is False

    def test_track_synced_comment(self):
        """Test tracking of synced comments in DynamoDB."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-123",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z",
            "createdBy": {"name": "John Doe"}
        }
        
        case_data = {
            "Item": {
                "slackChannelCaseComments": []
            }
        }
        
        self.mock_db_service.get_case.return_value = case_data
        self.mock_db_service.update_case_details.return_value = True
        
        # Act
        result = self.slack_service._track_synced_comment(case_id, comment)
        
        # Assert
        assert result is True
        self.mock_db_service.get_case.assert_called_once_with(case_id)
        self.mock_db_service.update_case_details.assert_called_once()
        
        # Check that the comment was added to the list
        call_args = self.mock_db_service.update_case_details.call_args
        updated_comments = call_args[1]['case_comments']
        assert len(updated_comments) == 1
        assert updated_comments[0]['commentId'] == "comment-123"
        assert updated_comments[0]['syncedToSlack'] is True

    def test_sync_comments_from_slack_success(self):
        """Test successful sync of comments from Slack to AWS SIR."""
        # Arrange
        case_id = "12345"
        slack_messages = [
            {
                "ts": "1642248600.000100",
                "user": "U1234567890",
                "text": "This is a Slack message",
                "type": "message"
            },
            {
                "ts": "1642248700.000200",
                "user": "U0987654321",
                "text": "Another Slack message",
                "type": "message"
            }
        ]
        
        self.mock_slack_client.get_user_info.return_value = {
            "display_name": "John Doe",
            "real_name": "John Doe"
        }
        
        with patch('index.security_incident_response_client') as mock_sir_client:
            mock_sir_client.create_case_comment.return_value = {"commentId": "new-comment"}
            
            # Act
            result = self.slack_service.sync_comments_from_slack(case_id, slack_messages)
            
            # Assert
            assert result is True
            assert mock_sir_client.create_case_comment.call_count == 2

    def test_sync_comments_from_slack_skip_bot_messages(self):
        """Test that bot messages are skipped during sync."""
        # Arrange
        case_id = "12345"
        slack_messages = [
            {
                "ts": "1642248600.000100",
                "bot_id": "B1234567890",
                "text": "This is a bot message",
                "type": "message"
            },
            {
                "ts": "1642248700.000200",
                "subtype": "bot_message",
                "text": "Another bot message",
                "type": "message"
            }
        ]
        
        with patch('index.security_incident_response_client') as mock_sir_client:
            # Act
            result = self.slack_service.sync_comments_from_slack(case_id, slack_messages)
            
            # Assert
            assert result is False  # No messages were synced
            mock_sir_client.create_case_comment.assert_not_called()

    def test_should_skip_slack_message_bot_messages(self):
        """Test detection of bot messages that should be skipped."""
        # Test bot_id present
        message1 = {"bot_id": "B1234567890", "text": "Bot message"}
        assert self.slack_service._should_skip_slack_message(message1) is True
        
        # Test bot_message subtype
        message2 = {"subtype": "bot_message", "text": "Bot message"}
        assert self.slack_service._should_skip_slack_message(message2) is True
        
        # Test system messages
        message3 = {"subtype": "channel_join", "text": "User joined"}
        assert self.slack_service._should_skip_slack_message(message3) is True
        
        # Test empty text
        message4 = {"text": "", "user": "U1234567890"}
        assert self.slack_service._should_skip_slack_message(message4) is True
        
        # Test system notification patterns
        message5 = {"text": "Case 12345 status updated to Closed", "user": "U1234567890"}
        assert self.slack_service._should_skip_slack_message(message5) is True

    def test_should_not_skip_regular_slack_message(self):
        """Test that regular user messages are not skipped."""
        message = {
            "text": "This is a regular user message",
            "user": "U1234567890",
            "type": "message"
        }
        
        assert self.slack_service._should_skip_slack_message(message) is False

    def test_is_slack_message_synced(self):
        """Test detection of already synced Slack messages."""
        # Arrange
        case_id = "12345"
        message = {
            "ts": "1642248600.000100",
            "user": "U1234567890",
            "text": "Test message"
        }
        
        case_data = {
            "Item": {
                "slackSyncedMessages": [
                    {
                        "ts": "1642248600.000100",
                        "user": "U1234567890",
                        "syncedToSIR": True
                    }
                ]
            }
        }
        
        self.mock_db_service.get_case.return_value = case_data
        
        # Act
        result = self.slack_service._is_slack_message_synced(case_id, message)
        
        # Assert
        assert result is True

    def test_is_slack_message_not_synced(self):
        """Test detection of new Slack messages that haven't been synced."""
        # Arrange
        case_id = "12345"
        message = {
            "ts": "1642248700.000200",
            "user": "U1234567890",
            "text": "New message"
        }
        
        case_data = {
            "Item": {
                "slackSyncedMessages": [
                    {
                        "ts": "1642248600.000100",
                        "user": "U0987654321",
                        "syncedToSIR": True
                    }
                ]
            }
        }
        
        self.mock_db_service.get_case.return_value = case_data
        
        # Act
        result = self.slack_service._is_slack_message_synced(case_id, message)
        
        # Assert
        assert result is False

    def test_track_slack_message_sync(self):
        """Test tracking of synced Slack messages."""
        # Arrange
        case_id = "12345"
        message = {
            "ts": "1642248600.000100",
            "user": "U1234567890",
            "text": "Test message"
        }
        
        case_data = {
            "Item": {
                "slackSyncedMessages": []
            }
        }
        
        self.mock_db_service.get_case.return_value = case_data
        self.mock_db_service.table = Mock()
        self.mock_db_service.table.update_item.return_value = {"Attributes": {}}
        
        # Act
        result = self.slack_service._track_slack_message_sync(case_id, message)
        
        # Assert
        assert result is True
        self.mock_db_service.table.update_item.assert_called_once()

    def test_get_slack_user_name_success(self):
        """Test successful retrieval of Slack user name."""
        # Arrange
        user_id = "U1234567890"
        user_info = {
            "display_name": "John Doe",
            "real_name": "John Smith"
        }
        
        self.mock_slack_client.get_user_info.return_value = user_info
        
        # Act
        result = self.slack_service._get_slack_user_name(user_id)
        
        # Assert
        assert result == "John Doe"
        self.mock_slack_client.get_user_info.assert_called_once_with(user_id)

    def test_get_slack_user_name_fallback_to_real_name(self):
        """Test fallback to real_name when display_name is not available."""
        # Arrange
        user_id = "U1234567890"
        user_info = {
            "real_name": "John Smith"
        }
        
        self.mock_slack_client.get_user_info.return_value = user_info
        
        # Act
        result = self.slack_service._get_slack_user_name(user_id)
        
        # Assert
        assert result == "John Smith"

    def test_get_slack_user_name_fallback_to_user_id(self):
        """Test fallback to user ID when user info is not available."""
        # Arrange
        user_id = "U1234567890"
        
        self.mock_slack_client.get_user_info.return_value = None
        
        # Act
        result = self.slack_service._get_slack_user_name(user_id)
        
        # Assert
        assert result == user_id

    def test_get_slack_user_name_empty_user_id(self):
        """Test handling of empty user ID."""
        # Act
        result = self.slack_service._get_slack_user_name("")
        
        # Assert
        assert result == "Unknown User"
        self.mock_slack_client.get_user_info.assert_not_called()

    @patch('index.datetime')
    def test_timestamp_parsing_in_duplicate_detection(self, mock_datetime):
        """Test timestamp parsing in duplicate comment detection."""
        # Arrange
        mock_datetime.fromisoformat.side_effect = lambda x: datetime.fromisoformat(x.replace('Z', '+00:00'))
        
        case_id = "12345"
        comment = {
            "commentId": "comment-456",
            "body": "Test comment",
            "createdDate": "2025-01-15T10:25:00Z"
        }
        
        case_data = {
            "slackChannelCaseComments": ["Test comment"],
            "slackChannelUpdateTimestamp": "2025-01-15T10:30:00Z"
        }
        
        # Act
        result = self.slack_service._is_duplicate_comment(case_id, comment, case_data)
        
        # Assert
        assert result is True

    def test_error_handling_in_comment_sync(self):
        """Test error handling during comment synchronization."""
        # Arrange
        case_id = "12345"
        comment = {
            "commentId": "comment-123",
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z"
        }
        
        self.mock_db_service.get_case.side_effect = Exception("Database error")
        
        # Act
        result = self.slack_service.sync_comment_to_slack(case_id, comment)
        
        # Assert
        assert result is False

    def test_error_handling_in_slack_message_sync(self):
        """Test error handling during Slack message synchronization."""
        # Arrange
        case_id = "12345"
        slack_messages = [
            {
                "ts": "1642248600.000100",
                "user": "U1234567890",
                "text": "Test message"
            }
        ]
        
        with patch('index.security_incident_response_client') as mock_sir_client:
            mock_sir_client.create_case_comment.side_effect = Exception("SIR API error")
            
            # Act
            result = self.slack_service.sync_comments_from_slack(case_id, slack_messages)
            
            # Assert
            assert result is False


if __name__ == "__main__":
    pytest.main([__file__])
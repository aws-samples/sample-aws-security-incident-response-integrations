"""
Unit tests for Slack Client attachment synchronization functionality.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the slack_client directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'assets', 'slack_client'))

# Mock all the dependencies before importing
sys.modules['slack_bolt_wrapper'] = Mock()
sys.modules['slack_sir_mapper'] = Mock()
sys.modules['requests'] = Mock()

# Mock AWS clients and other dependencies
with patch('boto3.client'), patch('boto3.resource'):
    # Import the module under test
    import index
    
    # Get the classes we need to test
    SlackService = index.SlackService


class TestAttachmentSync:
    """Test cases for attachment synchronization functionality"""

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.create_system_comment')
    def test_sync_attachment_size_limit_exceeded(self, mock_create_comment, mock_db_service, mock_slack_client):
        """Test attachment sync failure due to size limit"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        mock_db_instance.get_case.return_value = {
            "Item": {
                "slackChannelId": "C1234567890"
            }
        }
        
        mock_create_comment.return_value = "System comment about size limit"
        
        # Large attachment that exceeds size limit
        attachment = {
            "attachmentId": "att-12345",
            "filename": "large_file.pdf",
            "size": 200 * 1024 * 1024  # 200MB, exceeds 100MB limit
        }
        
        with patch('index.security_incident_response_client') as mock_sir_client:
            mock_sir_client.create_case_comment.return_value = {}
            
            slack_service = SlackService()
            result = slack_service.sync_attachment_to_slack("12345", attachment)
        
        # Assertions
        assert result is False
        mock_slack_instance.upload_file.assert_not_called()
        mock_sir_client.create_case_comment.assert_called_once()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    def test_sync_attachment_no_channel(self, mock_db_service, mock_slack_client):
        """Test attachment sync failure when no Slack channel exists"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        mock_db_instance.get_case.return_value = {
            "Item": {
                # No slackChannelId
            }
        }
        
        attachment = {
            "attachmentId": "att-12345",
            "filename": "test_file.pdf",
            "size": 1024
        }
        
        slack_service = SlackService()
        result = slack_service.sync_attachment_to_slack("12345", attachment)
        
        # Assertions
        assert result is False
        mock_slack_instance.upload_file.assert_not_called()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    def test_sync_attachments_empty_list(self, mock_db_service, mock_slack_client):
        """Test sync with empty attachments list"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        
        slack_service = SlackService()
        result = slack_service.sync_attachments_from_sir_to_slack("12345", [])
        
        # Assertions
        assert result is True

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    def test_download_sir_attachment_no_id(self, mock_db_service, mock_slack_client):
        """Test download failure when attachment has no ID"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        
        attachment = {
            "filename": "test_file.pdf",
            "size": 1024
            # No attachmentId
        }
        
        slack_service = SlackService()
        result = slack_service._download_sir_attachment("12345", attachment)
        
        # Assertions
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__])
"""
Unit tests for Slack Client Lambda function.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import sys
import os

# Add the slack_client directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'assets', 'slack_client'))

# Mock all the dependencies before importing
mock_slack_bolt_client = Mock()
mock_slack_sir_mapper = Mock()

# Mock the imports
sys.modules['slack_bolt_wrapper'] = Mock()
sys.modules['slack_sir_mapper'] = Mock()

# Mock AWS clients and other dependencies
with patch('boto3.client'), patch('boto3.resource'):
    # Import the module under test
    import index
    
    # Get the classes we need to test
    DatabaseService = index.DatabaseService
    SlackService = index.SlackService
    IncidentService = index.IncidentService
    lambda_handler = index.lambda_handler


class TestDatabaseService:
    """Test cases for DatabaseService class"""

    @patch('index.dynamodb')
    def test_get_case_success(self, mock_dynamodb):
        """Test successful case retrieval from database"""
        # Setup
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.get_item.return_value = {
            "Item": {
                "PK": "Case#12345",
                "SK": "latest",
                "slackChannelId": "C1234567890"
            }
        }
        
        # Set environment variable
        with patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "test-table"}):
            db_service = DatabaseService()
            result = db_service.get_case("12345")
        
        # Assertions
        assert result is not None
        assert "Item" in result
        assert result["Item"]["slackChannelId"] == "C1234567890"
        mock_table.get_item.assert_called_once_with(
            Key={"PK": "Case#12345", "SK": "latest"}
        )

    @patch('index.dynamodb')
    def test_get_case_not_found(self, mock_dynamodb):
        """Test case not found in database"""
        # Setup
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.get_item.return_value = {}
        
        with patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "test-table"}):
            db_service = DatabaseService()
            result = db_service.get_case("12345")
        
        # Assertions
        assert result == {}

    @patch('index.dynamodb')
    def test_update_slack_mapping_success(self, mock_dynamodb):
        """Test successful Slack channel mapping update"""
        # Setup
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.update_item.return_value = {"Attributes": {}}
        
        with patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "test-table"}):
            db_service = DatabaseService()
            result = db_service.update_slack_mapping("12345", "C1234567890")
        
        # Assertions
        assert result is True
        mock_table.update_item.assert_called_once()

    @patch('index.dynamodb')
    def test_update_case_details_success(self, mock_dynamodb):
        """Test successful case details update"""
        # Setup
        mock_table = Mock()
        mock_dynamodb.Table.return_value = mock_table
        mock_table.update_item.return_value = {"Attributes": {}}
        
        with patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "test-table"}):
            db_service = DatabaseService()
            result = db_service.update_case_details(
                "12345", 
                case_title="Test Title",
                case_description="Test Description"
            )
        
        # Assertions
        assert result is True
        mock_table.update_item.assert_called_once()


class TestSlackService:
    """Test cases for SlackService class"""

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.map_case_to_slack_channel_name')
    @patch('index.map_case_to_slack_channel_topic')
    @patch('index.map_case_to_slack_notification')
    @patch('index.map_watchers_to_slack_users')
    @patch('index.create_system_comment')
    def test_create_channel_for_case_success(self, mock_create_comment, mock_map_watchers, 
                                           mock_map_notification, mock_map_topic, mock_map_name,
                                           mock_db_service, mock_slack_client):
        """Test successful channel creation for a case"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        mock_slack_instance.create_channel.return_value = "C1234567890"
        mock_slack_instance.update_channel_topic.return_value = True
        mock_slack_instance.add_users_to_channel.return_value = True
        mock_slack_instance.post_message.return_value = True
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        mock_db_instance.update_slack_mapping.return_value = True
        
        # Mock mapper functions
        mock_map_name.return_value = "aws-security-incident-response-case-12345"
        mock_map_topic.return_value = "Test Topic"
        mock_map_notification.return_value = {"text": "Test notification", "blocks": []}
        mock_map_watchers.return_value = ["U1234567890"]
        mock_create_comment.return_value = "System comment"
        
        case_data = {
            "caseId": "12345",
            "title": "Test Security Incident",
            "description": "Test description",
            "severity": "High",
            "caseStatus": "Acknowledged",
            "watchers": ["user@example.com"]
        }
        
        with patch('index.security_incident_response_client') as mock_sir_client:
            mock_sir_client.create_case_comment.return_value = {}
            
            slack_service = SlackService()
            result = slack_service.create_channel_for_case("12345", case_data)
        
        # Assertions
        assert result == "C1234567890"
        mock_slack_instance.create_channel.assert_called_once_with("12345", "Test Security Incident")
        mock_slack_instance.update_channel_topic.assert_called_once()
        mock_slack_instance.post_message.assert_called_once()
        mock_db_instance.update_slack_mapping.assert_called_once_with("12345", "C1234567890")

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    def test_create_channel_for_case_failure(self, mock_db_service, mock_slack_client):
        """Test channel creation failure"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        mock_slack_instance.create_channel.return_value = None  # Simulate failure
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        
        case_data = {
            "caseId": "12345",
            "title": "Test Security Incident"
        }
        
        with patch('index.security_incident_response_client') as mock_sir_client:
            mock_sir_client.create_case_comment.return_value = {}
            
            slack_service = SlackService()
            result = slack_service.create_channel_for_case("12345", case_data)
        
        # Assertions
        assert result is None
        mock_slack_instance.create_channel.assert_called_once()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.map_case_to_slack_channel_topic')
    @patch('index.map_case_update_to_slack_message')
    def test_update_channel_for_case_success(self, mock_map_update, mock_map_topic, 
                                           mock_db_service, mock_slack_client):
        """Test successful channel update for a case"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        mock_slack_instance.update_channel_topic.return_value = True
        mock_slack_instance.post_message.return_value = True
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        mock_db_instance.get_case.return_value = {
            "Item": {
                "slackChannelId": "C1234567890"
            }
        }
        mock_db_instance.update_case_details.return_value = True
        
        # Mock mapper functions
        mock_map_topic.return_value = "Updated Topic"
        mock_map_update.return_value = {"text": "Update message", "blocks": []}
        
        case_data = {
            "caseId": "12345",
            "title": "Updated Title",
            "caseStatus": "Detection and Analysis"
        }
        
        slack_service = SlackService()
        result = slack_service.update_channel_for_case("12345", case_data, "status")
        
        # Assertions
        assert result is True
        mock_slack_instance.update_channel_topic.assert_called_once()
        mock_slack_instance.post_message.assert_called_once()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.should_skip_comment')
    @patch('index.map_comment_to_slack_message')
    def test_sync_comment_to_slack_success(self, mock_map_comment, mock_should_skip,
                                         mock_db_service, mock_slack_client):
        """Test successful comment sync to Slack"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        mock_slack_instance.post_message.return_value = True
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        mock_db_instance.get_case.return_value = {
            "Item": {
                "slackChannelId": "C1234567890"
            }
        }
        
        # Mock mapper functions
        mock_should_skip.return_value = False
        mock_map_comment.return_value = {"text": "Comment message", "blocks": []}
        
        comment = {
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z",
            "createdBy": {"name": "Test User"}
        }
        
        slack_service = SlackService()
        result = slack_service.sync_comment_to_slack("12345", comment)
        
        # Assertions
        assert result is True
        mock_slack_instance.post_message.assert_called_once()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.should_skip_comment')
    def test_sync_comment_skip_system_comment(self, mock_should_skip, mock_db_service, mock_slack_client):
        """Test skipping system comments to prevent loops"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        
        # Mock should_skip_comment to return True for system comments
        mock_should_skip.return_value = True
        
        comment = {
            "body": "[Slack Update] This is a system comment",
            "createdDate": "2025-01-15T10:30:00Z"
        }
        
        slack_service = SlackService()
        result = slack_service.sync_comment_to_slack("12345", comment)
        
        # Assertions
        assert result is True
        mock_slack_instance.post_message.assert_not_called()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.create_system_comment')
    @patch('requests.get')
    def test_sync_attachment_to_slack_success(self, mock_requests_get, mock_create_comment, 
                                            mock_db_service, mock_slack_client):
        """Test successful attachment sync to Slack"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        mock_slack_instance.upload_file.return_value = True
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        mock_db_instance.get_case.return_value = {
            "Item": {
                "slackChannelId": "C1234567890"
            }
        }
        
        # Mock download response
        mock_response = Mock()
        mock_response.content = b"test file content"
        mock_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_response
        
        attachment = {
            "attachmentId": "att-12345",
            "filename": "test_file.pdf",
            "size": 1024
        }
        
        with patch('index.security_incident_response_client') as mock_sir_client, \
             patch('index.map_attachment_to_slack_file') as mock_map_attachment:
            
            mock_sir_client.get_case_attachment_download_url.return_value = {
                "attachmentDownloadUrl": "https://example.com/download/test_file.pdf"
            }
            
            # Mock attachment mapping
            mock_map_attachment.return_value = {
                "filename": "test_file.pdf",
                "title": "Test File",
                "initial_comment": "Attachment from AWS Security Incident Response: test_file.pdf"
            }
            
            slack_service = SlackService()
            result = slack_service.sync_attachment_to_slack("12345", attachment)
        
        # Assertions
        assert result is True
        mock_slack_instance.upload_file.assert_called_once()
        mock_sir_client.get_case_attachment_download_url.assert_called_once_with(
            caseId="12345",
            attachmentId="att-12345"
        )

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.create_system_comment')
    def test_sync_attachment_to_slack_size_limit_exceeded(self, mock_create_comment, 
                                                        mock_db_service, mock_slack_client):
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
    def test_sync_attachment_to_slack_no_channel(self, mock_db_service, mock_slack_client):
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
    @patch('index.create_system_comment')
    @patch('requests.get')
    def test_sync_attachment_to_slack_download_failure(self, mock_requests_get, mock_create_comment,
                                                     mock_db_service, mock_slack_client):
        """Test attachment sync failure during download"""
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
        
        # Mock download failure
        mock_requests_get.side_effect = Exception("Download failed")
        mock_create_comment.return_value = "System comment about download failure"
        
        attachment = {
            "attachmentId": "att-12345",
            "filename": "test_file.pdf",
            "size": 1024
        }
        
        with patch('index.security_incident_response_client') as mock_sir_client:
            mock_sir_client.get_case_attachment_download_url.return_value = {
                "attachmentDownloadUrl": "https://example.com/download/test_file.pdf"
            }
            mock_sir_client.create_case_comment.return_value = {}
            
            slack_service = SlackService()
            result = slack_service.sync_attachment_to_slack("12345", attachment)
        
        # Assertions
        assert result is False
        mock_slack_instance.upload_file.assert_not_called()
        mock_sir_client.create_case_comment.assert_called_once()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    @patch('index.create_system_comment')
    @patch('requests.get')
    def test_sync_attachment_to_slack_upload_failure(self, mock_requests_get, mock_create_comment,
                                                   mock_db_service, mock_slack_client):
        """Test attachment sync failure during Slack upload"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        mock_slack_instance.upload_file.return_value = False  # Upload fails
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        mock_db_instance.get_case.return_value = {
            "Item": {
                "slackChannelId": "C1234567890"
            }
        }
        
        # Mock successful download
        mock_response = Mock()
        mock_response.content = b"test file content"
        mock_response.raise_for_status.return_value = None
        mock_requests_get.return_value = mock_response
        
        mock_create_comment.return_value = "System comment about upload failure"
        
        attachment = {
            "attachmentId": "att-12345",
            "filename": "test_file.pdf",
            "size": 1024
        }
        
        with patch('index.security_incident_response_client') as mock_sir_client, \
             patch('index.map_attachment_to_slack_file') as mock_map_attachment:
            
            mock_sir_client.get_case_attachment_download_url.return_value = {
                "attachmentDownloadUrl": "https://example.com/download/test_file.pdf"
            }
            mock_sir_client.create_case_comment.return_value = {}
            
            # Mock attachment mapping
            mock_map_attachment.return_value = {
                "filename": "test_file.pdf",
                "title": "Test File",
                "initial_comment": "Attachment from AWS Security Incident Response: test_file.pdf"
            }
            
            slack_service = SlackService()
            result = slack_service.sync_attachment_to_slack("12345", attachment)
        
        # Assertions
        assert result is False
        mock_slack_instance.upload_file.assert_called_once()
        mock_sir_client.create_case_comment.assert_called_once()

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    def test_sync_attachments_from_sir_to_slack_success(self, mock_db_service, mock_slack_client):
        """Test successful sync of multiple attachments"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        
        attachments = [
            {"attachmentId": "att-1", "filename": "file1.pdf"},
            {"attachmentId": "att-2", "filename": "file2.jpg"},
            {"attachmentId": "att-3", "filename": "file3.txt"}
        ]
        
        with patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "test-table"}), \
             patch.object(SlackService, 'sync_attachment_to_slack', side_effect=[True, True, True]) as mock_sync:
            
            slack_service = SlackService()
            result = slack_service.sync_attachments_from_sir_to_slack("12345", attachments)
        
        # Assertions
        assert result is True
        assert mock_sync.call_count == 3

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    def test_sync_attachments_from_sir_to_slack_partial_failure(self, mock_db_service, mock_slack_client):
        """Test partial failure when syncing multiple attachments"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        
        attachments = [
            {"attachmentId": "att-1", "filename": "file1.pdf"},
            {"attachmentId": "att-2", "filename": "file2.jpg"},
            {"attachmentId": "att-3", "filename": "file3.txt"}
        ]
        
        with patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "test-table"}), \
             patch.object(SlackService, 'sync_attachment_to_slack', side_effect=[True, False, True]) as mock_sync:
            
            slack_service = SlackService()
            result = slack_service.sync_attachments_from_sir_to_slack("12345", attachments)
        
        # Assertions
        assert result is False  # Not all succeeded
        assert mock_sync.call_count == 3

    @patch('index.SlackBoltClient')
    @patch('index.DatabaseService')
    def test_sync_attachments_from_sir_to_slack_empty_list(self, mock_db_service, mock_slack_client):
        """Test sync with empty attachments list"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_client.return_value = mock_slack_instance
        
        mock_db_instance = Mock()
        mock_db_service.return_value = mock_db_instance
        
        with patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "test-table"}):
            slack_service = SlackService()
            result = slack_service.sync_attachments_from_sir_to_slack("12345", [])
        
        # Assertions
        assert result is True


class TestIncidentService:
    """Test cases for IncidentService class"""

    @patch('index.SlackService')
    def test_extract_case_details_success(self, mock_slack_service):
        """Test successful case details extraction"""
        # Setup
        ir_case = {
            "detail": {
                "eventType": "CaseCreated",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345",
                "title": "Test Case"
            }
        }
        
        incident_service = IncidentService()
        ir_case_detail, ir_event_type, ir_case_id = incident_service.extract_case_details(ir_case)
        
        # Assertions
        assert ir_event_type == "CaseCreated"
        assert ir_case_id == "12345"
        assert ir_case_detail["title"] == "Test Case"

    @patch('index.SlackService')
    def test_extract_case_details_invalid_arn(self, mock_slack_service):
        """Test case details extraction with invalid ARN"""
        # Setup
        ir_case = {
            "detail": {
                "eventType": "CaseCreated",
                "caseArn": "invalid-arn-format",
                "title": "Test Case"
            }
        }
        
        incident_service = IncidentService()
        
        # Assertions
        with pytest.raises(ValueError, match="Invalid case ARN format"):
            incident_service.extract_case_details(ir_case)

    @patch('index.SlackService')
    def test_process_case_event_case_created(self, mock_slack_service):
        """Test processing CaseCreated event"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_service.return_value = mock_slack_instance
        mock_slack_instance.create_channel_for_case.return_value = "C1234567890"
        
        ir_case = {
            "detail": {
                "eventType": "CaseCreated",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345",
                "title": "Test Case",
                "severity": "High"
            }
        }
        
        incident_service = IncidentService()
        result = incident_service.process_case_event(ir_case)
        
        # Assertions
        assert result == "C1234567890"
        mock_slack_instance.create_channel_for_case.assert_called_once_with(
            "12345", ir_case["detail"]
        )

    @patch('index.SlackService')
    def test_process_case_event_case_updated(self, mock_slack_service):
        """Test processing CaseUpdated event"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_service.return_value = mock_slack_instance
        mock_slack_instance.update_channel_for_case.return_value = True
        
        ir_case = {
            "detail": {
                "eventType": "CaseUpdated",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345",
                "title": "Updated Test Case",
                "caseStatus": "Detection and Analysis"
            }
        }
        
        incident_service = IncidentService()
        result = incident_service.process_case_event(ir_case)
        
        # Assertions
        assert result is True
        mock_slack_instance.update_channel_for_case.assert_called_once_with(
            "12345", ir_case["detail"], "status"
        )

    @patch('index.SlackService')
    def test_process_case_event_comment_added(self, mock_slack_service):
        """Test processing CommentAdded event"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_service.return_value = mock_slack_instance
        mock_slack_instance.sync_comment_to_slack.return_value = True
        
        ir_case = {
            "detail": {
                "eventType": "CommentAdded",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345",
                "caseComments": [
                    {
                        "body": "This is a new comment",
                        "createdDate": "2025-01-15T10:30:00Z"
                    }
                ]
            }
        }
        
        incident_service = IncidentService()
        result = incident_service.process_case_event(ir_case)
        
        # Assertions
        assert result is True
        mock_slack_instance.sync_comment_to_slack.assert_called_once()

    @patch('index.SlackService')
    def test_process_case_event_attachment_added(self, mock_slack_service):
        """Test processing AttachmentAdded event"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_service.return_value = mock_slack_instance
        mock_slack_instance.sync_attachment_to_slack.return_value = True
        
        ir_case = {
            "detail": {
                "eventType": "AttachmentAdded",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345",
                "attachments": [
                    {
                        "attachmentId": "att-12345",
                        "filename": "evidence.pdf",
                        "size": 1024
                    }
                ]
            }
        }
        
        incident_service = IncidentService()
        result = incident_service.process_case_event(ir_case)
        
        # Assertions
        assert result is True
        mock_slack_instance.sync_attachment_to_slack.assert_called_once_with(
            "12345", 
            {
                "attachmentId": "att-12345",
                "filename": "evidence.pdf",
                "size": 1024
            }
        )

    @patch('index.SlackService')
    def test_process_case_event_attachment_added_no_attachments(self, mock_slack_service):
        """Test processing AttachmentAdded event with no attachments"""
        # Setup
        mock_slack_instance = Mock()
        mock_slack_service.return_value = mock_slack_instance
        
        ir_case = {
            "detail": {
                "eventType": "AttachmentAdded",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345",
                "attachments": []  # Empty attachments list
            }
        }
        
        incident_service = IncidentService()
        result = incident_service.process_case_event(ir_case)
        
        # Assertions
        assert result is True
        mock_slack_instance.sync_attachment_to_slack.assert_not_called()


class TestLambdaHandler:
    """Test cases for lambda_handler function"""

    @patch('index.IncidentService')
    def test_lambda_handler_success(self, mock_incident_service):
        """Test successful lambda handler execution"""
        # Setup
        mock_incident_instance = Mock()
        mock_incident_service.return_value = mock_incident_instance
        mock_incident_instance.process_case_event.return_value = True
        
        event = {
            "source": "security-ir",
            "detail": {
                "eventType": "CaseCreated",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345"
            }
        }
        context = Mock()
        
        with patch.dict(os.environ, {"EVENT_SOURCE": "security-ir"}):
            result = lambda_handler(event, context)
        
        # Assertions
        assert result["statusCode"] == 200
        response_body = json.loads(result["body"])
        assert response_body["message"] == "Event processed successfully"

    @patch('index.IncidentService')
    def test_lambda_handler_wrong_source(self, mock_incident_service):
        """Test lambda handler with wrong event source"""
        # Setup
        event = {
            "source": "jira",
            "detail": {}
        }
        context = Mock()
        
        with patch.dict(os.environ, {"EVENT_SOURCE": "security-ir"}):
            result = lambda_handler(event, context)
        
        # Assertions
        assert result["statusCode"] == 200
        response_body = json.loads(result["body"])
        assert "Event skipped" in response_body
        mock_incident_service.assert_not_called()

    @patch('index.IncidentService')
    def test_lambda_handler_processing_failure(self, mock_incident_service):
        """Test lambda handler with processing failure"""
        # Setup
        mock_incident_instance = Mock()
        mock_incident_service.return_value = mock_incident_instance
        mock_incident_instance.process_case_event.return_value = False
        
        event = {
            "source": "security-ir",
            "detail": {
                "eventType": "CaseCreated",
                "caseArn": "arn:aws:security-ir:us-east-1:123456789012:case/12345"
            }
        }
        context = Mock()
        
        with patch.dict(os.environ, {"EVENT_SOURCE": "security-ir"}):
            result = lambda_handler(event, context)
        
        # Assertions
        assert result["statusCode"] == 500
        response_body = json.loads(result["body"])
        assert "Failed to process event" in response_body["error"]

    @patch('index.IncidentService')
    def test_lambda_handler_exception(self, mock_incident_service):
        """Test lambda handler with exception"""
        # Setup
        mock_incident_service.side_effect = Exception("Test exception")
        
        event = {
            "source": "security-ir",
            "detail": {}
        }
        context = Mock()
        
        with patch.dict(os.environ, {"EVENT_SOURCE": "security-ir"}):
            result = lambda_handler(event, context)
        
        # Assertions
        assert result["statusCode"] == 500
        response_body = json.loads(result["body"])
        assert "Test exception" in response_body["error"]


if __name__ == "__main__":
    pytest.main([__file__])
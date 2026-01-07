"""
Unit tests for enhanced DynamoDB schema operations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from botocore.exceptions import ClientError

# Import the enhanced DynamoDB service
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../assets/domain/python'))

from enhanced_dynamodb_schema import EnhancedDynamoDBService


class TestEnhancedDynamoDBService:
    """Test cases for EnhancedDynamoDBService"""

    def setup_method(self):
        """Set up test fixtures"""
        self.table_name = "test-incidents-table"
        
        # Create service instance and mock its dependencies
        with patch('enhanced_dynamodb_schema.boto3'):
            self.service = EnhancedDynamoDBService(self.table_name)
        
        # Mock the DynamoDB resources after initialization
        self.mock_table = Mock()
        self.mock_dynamodb = Mock()
        self.mock_dynamodb_client = Mock()
        
        # Replace the service's dependencies with mocks
        self.service.table = self.mock_table
        self.service.dynamodb = self.mock_dynamodb
        self.service.dynamodb_client = self.mock_dynamodb_client

    def test_initialization(self):
        """Test EnhancedDynamoDBService initialization"""
        with patch('enhanced_dynamodb_schema.boto3'):
            service = EnhancedDynamoDBService("test-table")
            assert service.table_name == "test-table"

    def test_get_case_success(self):
        """Test successful case retrieval"""
        case_id = "12345"
        expected_item = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelId": "C1234567890",
            "slackChannelCaseTitle": "Test Case"
        }
        
        self.mock_table.get_item.return_value = {"Item": expected_item}
        
        result = self.service.get_case(case_id)
        
        assert result == expected_item
        self.mock_table.get_item.assert_called_once_with(
            Key={"PK": "Case#12345", "SK": "latest"}
        )

    def test_get_case_not_found(self):
        """Test case retrieval when case not found"""
        case_id = "12345"
        self.mock_table.get_item.return_value = {}
        
        result = self.service.get_case(case_id)
        
        assert result is None

    def test_get_case_client_error(self):
        """Test case retrieval with ClientError"""
        case_id = "12345"
        error_response = {"Error": {"Code": "ResourceNotFoundException"}}
        self.mock_table.get_item.side_effect = ClientError(error_response, "GetItem")
        
        result = self.service.get_case(case_id)
        
        assert result is None

    @patch('enhanced_dynamodb_schema.datetime')
    def test_update_slack_mapping_success(self, mock_datetime):
        """Test successful Slack mapping update"""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2025-01-15T10:30:00"
        
        case_id = "12345"
        slack_channel_id = "C1234567890"
        case_description = "Test description"
        case_title = "Test title"
        case_comments = ["comment1", "comment2"]
        
        result = self.service.update_slack_mapping(
            case_id=case_id,
            slack_channel_id=slack_channel_id,
            case_description=case_description,
            case_title=case_title,
            case_comments=case_comments
        )
        
        assert result is True
        self.mock_table.update_item.assert_called_once()
        
        # Verify the call arguments
        call_args = self.mock_table.update_item.call_args
        assert call_args[1]["Key"] == {"PK": "Case#12345", "SK": "latest"}
        assert "slackChannelId = :channel_id" in call_args[1]["UpdateExpression"]
        assert "slackChannelUpdateTimestamp = :timestamp" in call_args[1]["UpdateExpression"]
        assert call_args[1]["ExpressionAttributeValues"][":channel_id"] == slack_channel_id

    @patch('enhanced_dynamodb_schema.datetime')
    def test_update_slack_mapping_minimal(self, mock_datetime):
        """Test Slack mapping update with minimal parameters"""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2025-01-15T10:30:00"
        
        case_id = "12345"
        slack_channel_id = "C1234567890"
        
        result = self.service.update_slack_mapping(
            case_id=case_id,
            slack_channel_id=slack_channel_id
        )
        
        assert result is True
        self.mock_table.update_item.assert_called_once()

    def test_update_slack_mapping_client_error(self):
        """Test Slack mapping update with ClientError"""
        error_response = {"Error": {"Code": "ValidationException"}}
        self.mock_table.update_item.side_effect = ClientError(error_response, "UpdateItem")
        
        result = self.service.update_slack_mapping("12345", "C1234567890")
        
        assert result is False

    def test_get_slack_channel_id_success(self):
        """Test successful Slack channel ID retrieval"""
        case_id = "12345"
        case_data = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelId": "C1234567890"
        }
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        result = self.service.get_slack_channel_id(case_id)
        
        assert result == "C1234567890"

    def test_get_slack_channel_id_not_found(self):
        """Test Slack channel ID retrieval when case not found"""
        case_id = "12345"
        self.mock_table.get_item.return_value = {}
        
        result = self.service.get_slack_channel_id(case_id)
        
        assert result is None

    def test_get_slack_channel_id_no_channel(self):
        """Test Slack channel ID retrieval when channel ID not set"""
        case_id = "12345"
        case_data = {"PK": "Case#12345", "SK": "latest"}
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        result = self.service.get_slack_channel_id(case_id)
        
        assert result is None

    @patch('enhanced_dynamodb_schema.datetime')
    def test_update_slack_case_details_success(self, mock_datetime):
        """Test successful Slack case details update"""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2025-01-15T10:30:00"
        
        case_id = "12345"
        case_description = "Updated description"
        case_title = "Updated title"
        case_comments = ["comment1", "comment2", "comment3"]
        
        result = self.service.update_slack_case_details(
            case_id=case_id,
            case_description=case_description,
            case_title=case_title,
            case_comments=case_comments
        )
        
        assert result is True
        self.mock_table.update_item.assert_called_once()

    @patch('enhanced_dynamodb_schema.datetime')
    def test_update_slack_case_details_timestamp_only(self, mock_datetime):
        """Test Slack case details update with timestamp only"""
        mock_datetime.utcnow.return_value.isoformat.return_value = "2025-01-15T10:30:00"
        
        case_id = "12345"
        
        result = self.service.update_slack_case_details(case_id=case_id)
        
        assert result is True
        # Should not call update_item when only timestamp would be updated
        self.mock_table.update_item.assert_not_called()

    def test_add_slack_comment_success(self):
        """Test successful Slack comment addition"""
        case_id = "12345"
        new_comment = "New comment"
        existing_comments = ["comment1", "comment2"]
        
        case_data = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelCaseComments": existing_comments
        }
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        with patch.object(self.service, 'update_slack_case_details', return_value=True) as mock_update:
            result = self.service.add_slack_comment(case_id, new_comment)
            
            assert result is True
            mock_update.assert_called_once_with(
                case_id=case_id,
                case_comments=["comment1", "comment2", "New comment"]
            )

    def test_add_slack_comment_duplicate(self):
        """Test Slack comment addition with duplicate comment"""
        case_id = "12345"
        duplicate_comment = "comment1"
        existing_comments = ["comment1", "comment2"]
        
        case_data = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelCaseComments": existing_comments
        }
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        result = self.service.add_slack_comment(case_id, duplicate_comment)
        
        assert result is True
        # Should not call update_item for duplicate comment
        self.mock_table.update_item.assert_not_called()

    def test_add_slack_comment_case_not_found(self):
        """Test Slack comment addition when case not found"""
        case_id = "12345"
        comment = "New comment"
        
        self.mock_table.get_item.return_value = {}
        
        result = self.service.add_slack_comment(case_id, comment)
        
        assert result is False

    def test_get_slack_case_details_success(self):
        """Test successful Slack case details retrieval"""
        case_id = "12345"
        case_data = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelId": "C1234567890",
            "slackChannelCaseDescription": "Test description",
            "slackChannelCaseTitle": "Test title",
            "slackChannelCaseComments": ["comment1", "comment2"],
            "slackChannelUpdateTimestamp": "2025-01-15T10:30:00"
        }
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        result = self.service.get_slack_case_details(case_id)
        
        expected_result = {
            "slackChannelId": "C1234567890",
            "slackChannelCaseDescription": "Test description",
            "slackChannelCaseTitle": "Test title",
            "slackChannelCaseComments": ["comment1", "comment2"],
            "slackChannelUpdateTimestamp": "2025-01-15T10:30:00"
        }
        
        assert result == expected_result

    def test_get_slack_case_details_case_not_found(self):
        """Test Slack case details retrieval when case not found"""
        case_id = "12345"
        self.mock_table.get_item.return_value = {}
        
        result = self.service.get_slack_case_details(case_id)
        
        assert result == {}

    def test_find_case_by_slack_channel_success(self):
        """Test successful case finding by Slack channel"""
        slack_channel_id = "C1234567890"
        items = [{"PK": "Case#12345", "SK": "latest", "slackChannelId": slack_channel_id}]
        
        self.mock_table.scan.return_value = {"Items": items}
        
        result = self.service.find_case_by_slack_channel(slack_channel_id)
        
        assert result == "12345"
        self.mock_table.scan.assert_called_once_with(
            FilterExpression="slackChannelId = :channel_id",
            ExpressionAttributeValues={":channel_id": slack_channel_id}
        )

    def test_find_case_by_slack_channel_not_found(self):
        """Test case finding by Slack channel when not found"""
        slack_channel_id = "C1234567890"
        
        self.mock_table.scan.return_value = {"Items": []}
        
        result = self.service.find_case_by_slack_channel(slack_channel_id)
        
        assert result is None

    def test_find_case_by_slack_channel_with_pagination(self):
        """Test case finding by Slack channel with pagination"""
        slack_channel_id = "C1234567890"
        items = [{"PK": "Case#12345", "SK": "latest", "slackChannelId": slack_channel_id}]
        
        # First call returns with LastEvaluatedKey
        self.mock_table.scan.side_effect = [
            {"Items": [], "LastEvaluatedKey": {"PK": "Case#12345"}},
            {"Items": items}
        ]
        
        result = self.service.find_case_by_slack_channel(slack_channel_id)
        
        assert result == "12345"
        assert self.mock_table.scan.call_count == 2

    def test_find_case_by_slack_channel_client_error(self):
        """Test case finding by Slack channel with ClientError"""
        slack_channel_id = "C1234567890"
        error_response = {"Error": {"Code": "ValidationException"}}
        self.mock_table.scan.side_effect = ClientError(error_response, "Scan")
        
        result = self.service.find_case_by_slack_channel(slack_channel_id)
        
        assert result is None

    def test_check_comment_exists_true(self):
        """Test comment existence check when comment exists"""
        case_id = "12345"
        comment = "existing comment"
        case_data = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelCaseComments": ["existing comment", "another comment"]
        }
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        result = self.service.check_comment_exists(case_id, comment)
        
        assert result is True

    def test_check_comment_exists_false(self):
        """Test comment existence check when comment doesn't exist"""
        case_id = "12345"
        comment = "non-existing comment"
        case_data = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelCaseComments": ["existing comment", "another comment"]
        }
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        result = self.service.check_comment_exists(case_id, comment)
        
        assert result is False

    def test_check_comment_exists_case_not_found(self):
        """Test comment existence check when case not found"""
        case_id = "12345"
        comment = "any comment"
        
        self.mock_table.get_item.return_value = {}
        
        result = self.service.check_comment_exists(case_id, comment)
        
        assert result is False

    def test_get_last_update_timestamp_success(self):
        """Test successful last update timestamp retrieval"""
        case_id = "12345"
        timestamp = "2025-01-15T10:30:00"
        case_data = {
            "PK": "Case#12345",
            "SK": "latest",
            "slackChannelUpdateTimestamp": timestamp
        }
        
        self.mock_table.get_item.return_value = {"Item": case_data}
        
        result = self.service.get_last_update_timestamp(case_id)
        
        assert result == timestamp

    def test_get_last_update_timestamp_not_found(self):
        """Test last update timestamp retrieval when case not found"""
        case_id = "12345"
        self.mock_table.get_item.return_value = {}
        
        result = self.service.get_last_update_timestamp(case_id)
        
        assert result is None

    def test_validate_schema_compatibility_success(self):
        """Test successful schema compatibility validation"""
        items = [{"PK": "Case#12345", "SK": "latest", "incidentDetails": "{}"}]
        self.mock_table.scan.return_value = {"Items": items}
        
        result = self.service.validate_schema_compatibility()
        
        assert result is True
        self.mock_table.scan.assert_called_once_with(Limit=1)

    def test_validate_schema_compatibility_no_items(self):
        """Test schema compatibility validation with no items"""
        self.mock_table.scan.return_value = {"Items": []}
        
        result = self.service.validate_schema_compatibility()
        
        assert result is True

    def test_validate_schema_compatibility_missing_keys(self):
        """Test schema compatibility validation with missing required keys"""
        items = [{"SK": "latest"}]  # Missing PK
        self.mock_table.scan.return_value = {"Items": items}
        
        result = self.service.validate_schema_compatibility()
        
        assert result is False

    def test_validate_schema_compatibility_exception(self):
        """Test schema compatibility validation with exception"""
        self.mock_table.scan.side_effect = Exception("Test exception")
        
        result = self.service.validate_schema_compatibility()
        
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__])
"""
Unit tests for Slack SIR mapper.
"""

import pytest
from datetime import datetime
from unittest.mock import patch

# Import the mapper
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../assets/mappers/python'))

from slack_sir_mapper import (
    map_case_to_slack_channel_name,
    map_case_to_slack_channel_topic,
    map_case_to_slack_notification,
    map_case_update_to_slack_message,
    map_comment_to_slack_message,
    map_slack_message_to_sir_comment,
    map_watchers_to_slack_users,
    map_slack_users_to_watchers,
    map_attachment_to_slack_file,
    map_slack_file_to_attachment,
    should_skip_comment,
    create_system_comment,
    map_case_summary_to_slack_message,
    validate_slack_channel_mapping,
    extract_case_id_from_channel_name,
    format_slack_error_message
)


class TestSlackSirMapper:
    """Test cases for Slack SIR mapper functions"""

    def test_map_case_to_slack_channel_name(self):
        """Test mapping case ID to Slack channel name"""
        case_id = "12345"
        expected = "aws-security-incident-response-case-12345"
        
        result = map_case_to_slack_channel_name(case_id)
        assert result == expected

    def test_map_case_to_slack_channel_topic(self):
        """Test mapping case to Slack channel topic"""
        sir_case = {
            "title": "Security Breach Investigation",
            "caseStatus": "Detection and Analysis",
            "severity": "High"
        }
        
        result = map_case_to_slack_channel_topic(sir_case)
        
        assert "🟠" in result  # High severity emoji
        assert "🔍 Under Investigation" in result  # Status mapping
        assert "Security Breach Investigation" in result

    def test_map_case_to_slack_channel_topic_with_defaults(self):
        """Test mapping case to Slack channel topic with default values"""
        sir_case = {}
        
        result = map_case_to_slack_channel_topic(sir_case)
        
        assert "⚪" in result  # Default severity emoji
        assert "🔍 Under Investigation" in result  # Default status
        assert "Security Incident" in result  # Default title

    def test_map_case_to_slack_notification(self):
        """Test mapping case to Slack notification message"""
        sir_case = {
            "caseId": "12345",
            "title": "Security Breach",
            "description": "Suspicious activity detected",
            "caseStatus": "Detection and Analysis",
            "severity": "High",
            "createdDate": "2025-01-15T10:30:00Z",
            "impactedAccounts": ["123456789012"],
            "impactedRegions": ["us-east-1", "us-west-2"]
        }
        
        result = map_case_to_slack_notification(sir_case)
        
        assert result["text"] == "New Security Incident: 12345"
        assert "blocks" in result
        assert len(result["blocks"]) > 0
        
        # Check header block
        header_block = result["blocks"][0]
        assert header_block["type"] == "header"
        assert "🟠 New Security Incident: 12345" in header_block["text"]["text"]
        
        # Check that impacted accounts and regions are included
        blocks_text = str(result["blocks"])
        assert "123456789012" in blocks_text
        assert "us-east-1" in blocks_text

    def test_map_case_update_to_slack_message_status(self):
        """Test mapping case status update to Slack message"""
        sir_case = {
            "caseId": "12345",
            "caseStatus": "Containment, Eradication and Recovery",
            "severity": "Critical"
        }
        
        result = map_case_update_to_slack_message(sir_case, "status")
        
        assert "Case 12345 status updated" in result["text"]
        assert "🔴" in str(result["blocks"])  # Critical severity emoji
        assert "🚨 Active Response" in str(result["blocks"])  # Status mapping

    def test_map_case_update_to_slack_message_title(self):
        """Test mapping case title update to Slack message"""
        sir_case = {
            "caseId": "12345",
            "title": "Updated Security Incident Title"
        }
        
        result = map_case_update_to_slack_message(sir_case, "title")
        
        assert "Case 12345 title updated" in result["text"]
        assert "Updated Security Incident Title" in str(result["blocks"])

    def test_map_case_update_to_slack_message_description(self):
        """Test mapping case description update to Slack message"""
        sir_case = {
            "caseId": "12345",
            "description": "Updated description with more details"
        }
        
        result = map_case_update_to_slack_message(sir_case, "description")
        
        assert "Case 12345 description updated" in result["text"]
        assert "Updated description with more details" in str(result["blocks"])

    def test_map_case_update_to_slack_message_generic(self):
        """Test mapping generic case update to Slack message"""
        sir_case = {
            "caseId": "12345"
        }
        
        result = map_case_update_to_slack_message(sir_case, "other")
        
        assert "Case 12345 updated" in result["text"]
        assert "🔄" in str(result["blocks"])

    def test_map_comment_to_slack_message(self):
        """Test mapping SIR comment to Slack message"""
        comment = {
            "body": "This is a test comment",
            "createdDate": "2025-01-15T10:30:00Z",
            "createdBy": {
                "name": "John Doe",
                "email": "john.doe@example.com"
            }
        }
        case_id = "12345"
        
        result = map_comment_to_slack_message(comment, case_id)
        
        assert "New comment on case 12345" in result["text"]
        assert "John Doe" in str(result["blocks"])
        assert "This is a test comment" in str(result["blocks"])

    def test_map_comment_to_slack_message_string_created_by(self):
        """Test mapping SIR comment with string createdBy to Slack message"""
        comment = {
            "body": "Test comment",
            "createdDate": "2025-01-15T10:30:00Z",
            "createdBy": "jane.doe@example.com"
        }
        case_id = "12345"
        
        result = map_comment_to_slack_message(comment, case_id)
        
        assert "jane.doe@example.com" in str(result["blocks"])

    def test_map_slack_message_to_sir_comment(self):
        """Test mapping Slack message to SIR comment"""
        message = {
            "text": "This is a Slack message",
            "ts": "1642248600.123456",
            "user": "U1234567890"
        }
        user_name = "John Doe"
        
        result = map_slack_message_to_sir_comment(message, user_name)
        
        assert "[Slack Message from John Doe" in result
        assert "2022-01-15" in result  # Formatted timestamp
        assert "This is a Slack message" in result

    def test_map_slack_message_to_sir_comment_no_user_name(self):
        """Test mapping Slack message to SIR comment without user name"""
        message = {
            "text": "Test message",
            "ts": "1642248600.123456",
            "user": "U1234567890"
        }
        
        result = map_slack_message_to_sir_comment(message)
        
        assert "[Slack Message from U1234567890" in result
        assert "Test message" in result

    def test_map_slack_message_to_sir_comment_invalid_timestamp(self):
        """Test mapping Slack message with invalid timestamp"""
        message = {
            "text": "Test message",
            "ts": "invalid-timestamp",
            "user": "U1234567890"
        }
        
        result = map_slack_message_to_sir_comment(message)
        
        assert "[Slack Message from U1234567890" in result
        assert "invalid-timestamp" in result
        assert "Test message" in result

    def test_map_watchers_to_slack_users(self):
        """Test mapping SIR watchers to Slack user IDs"""
        sir_watchers = [
            {"email": "john.doe@example.com"},
            "jane.doe@example.com",
            {"email": "bob.smith@example.com"}
        ]
        slack_user_mapping = {
            "john.doe@example.com": "U1111111111",
            "jane.doe@example.com": "U2222222222"
        }
        
        result = map_watchers_to_slack_users(sir_watchers, slack_user_mapping)
        
        assert "U1111111111" in result
        assert "U2222222222" in result
        assert len(result) == 2  # bob.smith not mapped

    def test_map_watchers_to_slack_users_no_mapping(self):
        """Test mapping SIR watchers without user mapping"""
        sir_watchers = [
            {"email": "john.doe@example.com"},
            "jane.doe@example.com"
        ]
        
        result = map_watchers_to_slack_users(sir_watchers)
        
        assert result == []

    def test_map_slack_users_to_watchers(self):
        """Test mapping Slack user IDs to email addresses"""
        slack_user_ids = ["U1111111111", "U2222222222", "U3333333333"]
        slack_user_mapping = {
            "john.doe@example.com": "U1111111111",
            "jane.doe@example.com": "U2222222222"
        }
        
        result = map_slack_users_to_watchers(slack_user_ids, slack_user_mapping)
        
        assert "john.doe@example.com" in result
        assert "jane.doe@example.com" in result
        assert len(result) == 2  # U3333333333 not mapped

    def test_map_attachment_to_slack_file(self):
        """Test mapping SIR attachment to Slack file format"""
        attachment = {
            "filename": "evidence.pdf",
            "content": b"file content",
            "title": "Evidence Document"
        }
        
        result = map_attachment_to_slack_file(attachment)
        
        assert result["filename"] == "evidence.pdf"
        assert result["file"] == b"file content"
        assert result["title"] == "Evidence Document"
        assert "AWS Security Incident Response" in result["initial_comment"]

    def test_map_attachment_to_slack_file_minimal(self):
        """Test mapping SIR attachment with minimal data"""
        attachment = {
            "filename": "file.txt",
            "content": b"content"
        }
        
        result = map_attachment_to_slack_file(attachment)
        
        assert result["filename"] == "file.txt"
        assert result["title"] == "file.txt"  # Defaults to filename

    def test_map_slack_file_to_attachment(self):
        """Test mapping Slack file to SIR attachment format"""
        file_data = {
            "name": "screenshot.png",
            "url_private_download": "https://files.slack.com/files-pri/T123-F456/screenshot.png",
            "size": 1024,
            "mimetype": "image/png",
            "title": "Screenshot",
            "user": "U1234567890"
        }
        
        result = map_slack_file_to_attachment(file_data)
        
        assert result["filename"] == "screenshot.png"
        assert result["url"] == "https://files.slack.com/files-pri/T123-F456/screenshot.png"
        assert result["size"] == 1024
        assert result["mimetype"] == "image/png"
        assert result["title"] == "Screenshot"
        assert "U1234567890" in result["description"]

    def test_should_skip_comment_with_tag(self):
        """Test comment skipping with Slack update tag"""
        comment_body = "[Slack Update] This comment should be skipped"
        
        result = should_skip_comment(comment_body)
        
        assert result is True

    def test_should_skip_comment_without_tag(self):
        """Test comment not skipping without Slack update tag"""
        comment_body = "This is a regular comment"
        
        result = should_skip_comment(comment_body)
        
        assert result is False

    @patch('slack_sir_mapper.datetime')
    def test_create_system_comment(self, mock_datetime):
        """Test creating system comment"""
        mock_datetime.utcnow.return_value.strftime.return_value = "2025-01-15 10:30:00 UTC"
        
        result = create_system_comment("Channel created successfully")
        
        assert "[Slack Update]" in result
        assert "Channel created successfully" in result
        assert "2025-01-15 10:30:00 UTC" in result

    @patch('slack_sir_mapper.datetime')
    def test_create_system_comment_with_error(self, mock_datetime):
        """Test creating system comment with error details"""
        mock_datetime.utcnow.return_value.strftime.return_value = "2025-01-15 10:30:00 UTC"
        
        result = create_system_comment("Operation failed", "API timeout")
        
        assert "[Slack Update]" in result
        assert "Operation failed" in result
        assert "Error Details: API timeout" in result

    def test_map_case_summary_to_slack_message(self):
        """Test mapping case summary to Slack message"""
        sir_case = {
            "caseId": "12345",
            "title": "Security Investigation",
            "description": "Detailed investigation of security incident",
            "caseStatus": "Detection and Analysis",
            "severity": "High",
            "createdDate": "2025-01-15T10:30:00Z",
            "lastUpdated": "2025-01-15T12:00:00Z",
            "impactedAccounts": ["123456789012"],
            "impactedRegions": ["us-east-1"]
        }
        comments = [{"body": "Comment 1"}, {"body": "Comment 2"}]
        attachments = [{"filename": "file1.txt"}]
        
        result = map_case_summary_to_slack_message(sir_case, comments, attachments)
        
        assert result["text"] == "Case Summary: 12345"
        assert "blocks" in result
        
        blocks_text = str(result["blocks"])
        assert "Security Investigation" in blocks_text
        assert "🟠" in blocks_text  # High severity
        assert "🔍 Under Investigation" in blocks_text  # Status mapping
        assert "*Comments:* 2" in blocks_text
        assert "*Attachments:* 1" in blocks_text
        assert "123456789012" in blocks_text
        assert "us-east-1" in blocks_text

    def test_map_case_summary_to_slack_message_minimal(self):
        """Test mapping minimal case summary to Slack message"""
        sir_case = {
            "caseId": "12345"
        }
        
        result = map_case_summary_to_slack_message(sir_case)
        
        assert result["text"] == "Case Summary: 12345"
        assert "blocks" in result
        
        blocks_text = str(result["blocks"])
        assert "Security Incident" in blocks_text  # Default title
        assert "⚪" in blocks_text  # Default severity

    def test_validate_slack_channel_mapping_valid(self):
        """Test valid Slack channel mapping"""
        case_id = "12345"
        channel_id = "C1234567890"
        
        result = validate_slack_channel_mapping(case_id, channel_id)
        
        assert result is True

    def test_validate_slack_channel_mapping_invalid_channel_id(self):
        """Test invalid Slack channel ID format"""
        case_id = "12345"
        channel_id = "invalid-channel-id"
        
        result = validate_slack_channel_mapping(case_id, channel_id)
        
        assert result is False

    def test_validate_slack_channel_mapping_missing_data(self):
        """Test validation with missing data"""
        result1 = validate_slack_channel_mapping("", "C1234567890")
        result2 = validate_slack_channel_mapping("12345", "")
        result3 = validate_slack_channel_mapping("", "")
        
        assert result1 is False
        assert result2 is False
        assert result3 is False

    def test_extract_case_id_from_channel_name_valid(self):
        """Test extracting case ID from valid channel name"""
        channel_name = "aws-security-incident-response-case-12345"
        
        result = extract_case_id_from_channel_name(channel_name)
        
        assert result == "12345"

    def test_extract_case_id_from_channel_name_invalid(self):
        """Test extracting case ID from invalid channel name"""
        channel_name = "random-channel-name"
        
        result = extract_case_id_from_channel_name(channel_name)
        
        assert result is None

    def test_extract_case_id_from_channel_name_empty(self):
        """Test extracting case ID from empty channel name"""
        result = extract_case_id_from_channel_name("")
        
        assert result is None

    def test_format_slack_error_message(self):
        """Test formatting error message for Slack"""
        error = "API connection failed"
        
        result = format_slack_error_message(error)
        
        assert "❌ Error: API connection failed" in result["text"]
        assert "blocks" in result
        assert "❌" in str(result["blocks"])

    def test_format_slack_error_message_with_case_id(self):
        """Test formatting error message with case ID"""
        error = "Channel creation failed"
        case_id = "12345"
        
        result = format_slack_error_message(error, case_id)
        
        assert "❌ Error for case 12345: Channel creation failed" in result["text"]
        assert "blocks" in result


if __name__ == "__main__":
    pytest.main([__file__])
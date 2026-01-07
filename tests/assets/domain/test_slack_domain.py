"""
Comprehensive tests for Slack domain models.

This module provides complete test coverage for all Slack domain models including:
- Valid data creation scenarios
- Validation failure scenarios
- Edge cases and boundary conditions
- Serialization/deserialization testing
- Factory method testing
- Utility method testing

Test Coverage:
- SlackChannel: Channel management and validation
- SlackMessage: Message handling and bot detection
- SlackAttachment: File attachment processing
- SlackCommand: Slash command parsing and validation
"""

import datetime
import pytest
from unittest.mock import patch
from assets.domain.python.slack_domain import (
    SlackChannel,
    SlackMessage,
    SlackAttachment,
    SlackCommand
)


class TestSlackChannel:
    """Test cases for SlackChannel domain model."""

    def test_valid_channel_creation(self):
        """Test creating a valid SlackChannel with all required fields."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="security-incident",
            case_id="case-123",
            members=["U1234567890", "U0987654321"],
            topic="Security incident discussion",
            purpose="Handle security incidents"
        )
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "security-incident"
        assert channel.case_id == "case-123"
        assert channel.members == ["U1234567890", "U0987654321"]
        assert channel.topic == "Security incident discussion"
        assert channel.purpose == "Handle security incidents"
        assert isinstance(channel.created_at, datetime.datetime)

    def test_channel_creation_with_minimal_fields(self):
        """Test creating a SlackChannel with only required fields."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id="case-456"
        )
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "test-channel"
        assert channel.case_id == "case-456"
        assert channel.members == []
        assert channel.topic is None
        assert channel.purpose is None
        assert isinstance(channel.created_at, datetime.datetime)

    def test_channel_creation_with_explicit_none_timestamp(self):
        """Test creating a SlackChannel with explicitly None timestamp."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id="case-456",
            created_at=None
        )
        
        assert channel.created_at is None

    def test_channel_validation_success(self):
        """Test successful validation of a valid SlackChannel."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="valid-channel",
            case_id="case-123"
        )
        
        assert channel.validate() is True

    def test_channel_validation_missing_channel_id(self):
        """Test validation failure when channel_id is missing."""
        channel = SlackChannel(
            channel_id="",
            channel_name="test-channel",
            case_id="case-123"
        )
        
        with pytest.raises(ValueError, match="Channel ID is required"):
            channel.validate()

    def test_channel_validation_missing_channel_name(self):
        """Test validation failure when channel_name is missing."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="",
            case_id="case-123"
        )
        
        with pytest.raises(ValueError, match="Channel name is required"):
            channel.validate()

    def test_channel_validation_missing_case_id(self):
        """Test validation failure when case_id is missing."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id=""
        )
        
        with pytest.raises(ValueError, match="Case ID is required"):
            channel.validate()

    def test_channel_validation_invalid_channel_id_format(self):
        """Test validation failure for invalid channel ID format."""
        channel = SlackChannel(
            channel_id="invalid-id",
            channel_name="test-channel",
            case_id="case-123"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack channel ID format"):
            channel.validate()

    def test_channel_validation_invalid_channel_name_format(self):
        """Test validation failure for invalid channel name format."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="Invalid Channel Name!",
            case_id="case-123"
        )
        
        with pytest.raises(ValueError, match="Invalid channel name format"):
            channel.validate()

    def test_channel_to_dict(self):
        """Test converting SlackChannel to dictionary."""
        created_at = datetime.datetime(2023, 1, 15, 10, 30, 0, tzinfo=datetime.timezone.utc)
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id="case-123",
            members=["U1234567890"],
            created_at=created_at,
            topic="Test topic",
            purpose="Test purpose"
        )
        
        result = channel.to_dict()
        expected = {
            "channelId": "C1234567890",
            "channelName": "test-channel",
            "caseId": "case-123",
            "members": ["U1234567890"],
            "createdAt": "2023-01-15T10:30:00+00:00",
            "topic": "Test topic",
            "purpose": "Test purpose"
        }
        
        assert result == expected

    def test_channel_to_dict_with_none_timestamp(self):
        """Test converting SlackChannel to dictionary with None timestamp."""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id="case-123",
            created_at=None
        )
        
        result = channel.to_dict()
        assert result["createdAt"] is None

    def test_channel_from_dict(self):
        """Test creating SlackChannel from dictionary."""
        data = {
            "channelId": "C1234567890",
            "channelName": "test-channel",
            "caseId": "case-123",
            "members": ["U1234567890"],
            "createdAt": "2023-01-15T10:30:00+00:00",
            "topic": "Test topic",
            "purpose": "Test purpose"
        }
        
        channel = SlackChannel.from_dict(data)
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "test-channel"
        assert channel.case_id == "case-123"
        assert channel.members == ["U1234567890"]
        assert channel.created_at == datetime.datetime(2023, 1, 15, 10, 30, 0, tzinfo=datetime.timezone.utc)
        assert channel.topic == "Test topic"
        assert channel.purpose == "Test purpose"

    def test_channel_from_dict_minimal(self):
        """Test creating SlackChannel from dictionary with minimal data."""
        data = {
            "channelId": "C1234567890",
            "channelName": "test-channel",
            "caseId": "case-123"
        }
        
        channel = SlackChannel.from_dict(data)
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "test-channel"
        assert channel.case_id == "case-123"
        assert channel.members == []
        assert channel.created_at is None

    def test_channel_from_slack_response(self):
        """Test creating SlackChannel from Slack API response."""
        response = {
            "id": "C1234567890",
            "name": "test-channel",
            "created": 1673776200,
            "members": ["U1234567890", "U0987654321"],
            "topic": {"value": "Test topic"},
            "purpose": {"value": "Test purpose"}
        }
        
        channel = SlackChannel.from_slack_response(response, "case-123")
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "test-channel"
        assert channel.case_id == "case-123"
        assert channel.members == ["U1234567890", "U0987654321"]
        assert channel.topic == "Test topic"
        assert channel.purpose == "Test purpose"
        assert isinstance(channel.created_at, datetime.datetime)

    def test_channel_from_slack_response_minimal(self):
        """Test creating SlackChannel from minimal Slack API response."""
        response = {
            "id": "C1234567890",
            "name": "test-channel"
        }
        
        channel = SlackChannel.from_slack_response(response, "case-123")
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "test-channel"
        assert channel.case_id == "case-123"
        assert channel.members == []
        assert channel.created_at is None
        assert channel.topic is None
        assert channel.purpose is None

    def test_channel_edge_cases(self):
        """Test edge cases for SlackChannel."""
        # Test with very long channel name (valid format)
        long_name = "a" * 21  # Slack allows up to 21 characters
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name=long_name,
            case_id="case-123"
        )
        assert channel.validate() is True
        
        # Test with special characters in channel name
        special_name = "test-channel_with-underscores123"
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name=special_name,
            case_id="case-123"
        )
        assert channel.validate() is True


class TestSlackMessage:
    """Test cases for SlackMessage domain model."""

    def test_valid_message_creation(self):
        """Test creating a valid SlackMessage with all fields."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello, world!",
            timestamp="1673776200.123456",
            thread_ts="1673776100.123456",
            message_type="message",
            subtype=None,
            user_name="john.doe",
            attachments=[{"id": "F1234567890"}]
        )
        
        assert message.message_id == "1673776200.123456"
        assert message.channel_id == "C1234567890"
        assert message.user_id == "U1234567890"
        assert message.text == "Hello, world!"
        assert message.timestamp == "1673776200.123456"
        assert message.thread_ts == "1673776100.123456"
        assert message.message_type == "message"
        assert message.subtype is None
        assert message.user_name == "john.doe"
        assert message.attachments == [{"id": "F1234567890"}]

    def test_message_creation_minimal(self):
        """Test creating a SlackMessage with minimal required fields."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        assert message.message_id == "1673776200.123456"
        assert message.channel_id == "C1234567890"
        assert message.user_id == "U1234567890"
        assert message.text == "Hello"
        assert message.timestamp == "1673776200.123456"
        assert message.thread_ts is None
        assert message.message_type == "message"
        assert message.subtype is None
        assert message.user_name is None
        assert message.attachments == []

    def test_message_validation_success(self):
        """Test successful validation of a valid SlackMessage."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        assert message.validate() is True

    def test_message_validation_missing_message_id(self):
        """Test validation failure when message_id is missing."""
        message = SlackMessage(
            message_id="",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        with pytest.raises(ValueError, match="Message ID is required"):
            message.validate()

    def test_message_validation_missing_channel_id(self):
        """Test validation failure when channel_id is missing."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        with pytest.raises(ValueError, match="Channel ID is required"):
            message.validate()

    def test_message_validation_missing_user_id(self):
        """Test validation failure when user_id is missing."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="",
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        with pytest.raises(ValueError, match="User ID is required"):
            message.validate()

    def test_message_validation_missing_timestamp(self):
        """Test validation failure when timestamp is missing."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp=""
        )
        
        with pytest.raises(ValueError, match="Timestamp is required"):
            message.validate()

    def test_message_validation_invalid_channel_id(self):
        """Test validation failure for invalid channel ID format."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="invalid-channel",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack channel ID format"):
            message.validate()

    def test_message_validation_invalid_user_id(self):
        """Test validation failure for invalid user ID format."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="invalid-user",
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack user ID format"):
            message.validate()

    def test_message_validation_invalid_timestamp(self):
        """Test validation failure for invalid timestamp format."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="invalid-timestamp"
        )
        
        with pytest.raises(ValueError, match="Invalid timestamp format"):
            message.validate()

    def test_message_validation_bot_user_id(self):
        """Test validation success for bot user ID format."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="B1234567890",  # Bot user ID
            text="Hello",
            timestamp="1673776200.123456"
        )
        
        assert message.validate() is True

    def test_message_to_dict(self):
        """Test converting SlackMessage to dictionary."""
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello, world!",
            timestamp="1673776200.123456",
            thread_ts="1673776100.123456",
            message_type="message",
            subtype="channel_join",
            user_name="john.doe",
            attachments=[{"id": "F1234567890"}]
        )
        
        result = message.to_dict()
        expected = {
            "messageId": "1673776200.123456",
            "channelId": "C1234567890",
            "userId": "U1234567890",
            "text": "Hello, world!",
            "timestamp": "1673776200.123456",
            "threadTs": "1673776100.123456",
            "messageType": "message",
            "subtype": "channel_join",
            "userName": "john.doe",
            "attachments": [{"id": "F1234567890"}]
        }
        
        assert result == expected

    def test_message_from_dict(self):
        """Test creating SlackMessage from dictionary."""
        data = {
            "messageId": "1673776200.123456",
            "channelId": "C1234567890",
            "userId": "U1234567890",
            "text": "Hello, world!",
            "timestamp": "1673776200.123456",
            "threadTs": "1673776100.123456",
            "messageType": "message",
            "subtype": "channel_join",
            "userName": "john.doe",
            "attachments": [{"id": "F1234567890"}]
        }
        
        message = SlackMessage.from_dict(data)
        
        assert message.message_id == "1673776200.123456"
        assert message.channel_id == "C1234567890"
        assert message.user_id == "U1234567890"
        assert message.text == "Hello, world!"
        assert message.timestamp == "1673776200.123456"
        assert message.thread_ts == "1673776100.123456"
        assert message.message_type == "message"
        assert message.subtype == "channel_join"
        assert message.user_name == "john.doe"
        assert message.attachments == [{"id": "F1234567890"}]

    def test_message_from_slack_event(self):
        """Test creating SlackMessage from Slack event."""
        event = {
            "ts": "1673776200.123456",
            "channel": "C1234567890",
            "user": "U1234567890",
            "text": "Hello from Slack!",
            "type": "message",
            "thread_ts": "1673776100.123456",
            "subtype": "channel_join",
            "attachments": [{"id": "F1234567890"}]
        }
        
        message = SlackMessage.from_slack_event(event)
        
        assert message.message_id == "1673776200.123456"
        assert message.channel_id == "C1234567890"
        assert message.user_id == "U1234567890"
        assert message.text == "Hello from Slack!"
        assert message.timestamp == "1673776200.123456"
        assert message.thread_ts == "1673776100.123456"
        assert message.message_type == "message"
        assert message.subtype == "channel_join"
        assert message.attachments == [{"id": "F1234567890"}]

    def test_message_is_bot_message(self):
        """Test bot message detection."""
        # Test bot_message subtype
        bot_message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456",
            subtype="bot_message"
        )
        assert bot_message.is_bot_message() is True
        
        # Test app_mention subtype
        app_message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456",
            subtype="app_mention"
        )
        assert app_message.is_bot_message() is True
        
        # Test bot user ID
        bot_user_message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="B1234567890",  # Bot user ID
            text="Hello",
            timestamp="1673776200.123456"
        )
        assert bot_user_message.is_bot_message() is True
        
        # Test None user ID
        no_user_message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id=None,
            text="Hello",
            timestamp="1673776200.123456"
        )
        assert no_user_message.is_bot_message() is True
        
        # Test regular user message
        user_message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456"
        )
        assert user_message.is_bot_message() is False

    def test_message_edge_cases(self):
        """Test edge cases for SlackMessage."""
        # Test with very long text
        long_text = "a" * 4000  # Slack messages can be quite long
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text=long_text,
            timestamp="1673776200.123456"
        )
        assert message.validate() is True
        
        # Test with special characters in text
        special_text = "Hello! @channel #general :smile: <@U1234567890>"
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text=special_text,
            timestamp="1673776200.123456"
        )
        assert message.validate() is True


class TestSlackAttachment:
    """Test cases for SlackAttachment domain model."""

    def test_valid_attachment_creation(self):
        """Test creating a valid SlackAttachment with all fields."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="document.pdf",
            url="https://files.slack.com/files-pri/T1234567890-F1234567890/document.pdf",
            size=1024000,
            mimetype="application/pdf",
            title="Important Document",
            timestamp="1673776200",
            user_id="U1234567890",
            channel_id="C1234567890",
            initial_comment="Here's the document we discussed"
        )
        
        assert attachment.file_id == "F1234567890"
        assert attachment.filename == "document.pdf"
        assert attachment.url == "https://files.slack.com/files-pri/T1234567890-F1234567890/document.pdf"
        assert attachment.size == 1024000
        assert attachment.mimetype == "application/pdf"
        assert attachment.title == "Important Document"
        assert attachment.timestamp == "1673776200"
        assert attachment.user_id == "U1234567890"
        assert attachment.channel_id == "C1234567890"
        assert attachment.initial_comment == "Here's the document we discussed"

    def test_attachment_creation_minimal(self):
        """Test creating a SlackAttachment with minimal required fields."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url=None,
            size=1024,
            mimetype="text/plain"
        )
        
        assert attachment.file_id == "F1234567890"
        assert attachment.filename == "test.txt"
        assert attachment.url is None
        assert attachment.size == 1024
        assert attachment.mimetype == "text/plain"
        assert attachment.title == "test.txt"  # Defaults to filename
        assert attachment.timestamp is None
        assert attachment.user_id is None
        assert attachment.channel_id is None
        assert attachment.initial_comment is None

    def test_attachment_validation_success(self):
        """Test successful validation of a valid SlackAttachment."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        assert attachment.validate() is True

    def test_attachment_validation_missing_file_id(self):
        """Test validation failure when file_id is missing."""
        attachment = SlackAttachment(
            file_id="",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="File ID is required"):
            attachment.validate()

    def test_attachment_validation_missing_filename(self):
        """Test validation failure when filename is missing."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="Filename is required"):
            attachment.validate()

    def test_attachment_validation_negative_size(self):
        """Test validation failure when size is negative."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=-1,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="File size cannot be negative"):
            attachment.validate()

    def test_attachment_validation_missing_mimetype(self):
        """Test validation failure when mimetype is missing."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype=""
        )
        
        with pytest.raises(ValueError, match="MIME type is required"):
            attachment.validate()

    def test_attachment_validation_invalid_file_id(self):
        """Test validation failure for invalid file ID format."""
        attachment = SlackAttachment(
            file_id="invalid-file-id",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack file ID format"):
            attachment.validate()

    def test_attachment_validation_invalid_url(self):
        """Test validation failure for invalid URL format."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="invalid-url",
            size=1024,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="Invalid URL format"):
            attachment.validate()

    def test_attachment_validation_invalid_user_id(self):
        """Test validation failure for invalid user ID format."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain",
            user_id="invalid-user"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack user ID format"):
            attachment.validate()

    def test_attachment_validation_invalid_channel_id(self):
        """Test validation failure for invalid channel ID format."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain",
            channel_id="invalid-channel"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack channel ID format"):
            attachment.validate()

    def test_attachment_is_downloadable(self):
        """Test downloadable status checking."""
        # Test with valid URL
        downloadable = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        assert downloadable.is_downloadable() is True
        
        # Test with http URL
        http_downloadable = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="http://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        assert http_downloadable.is_downloadable() is True
        
        # Test with None URL
        not_downloadable = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url=None,
            size=1024,
            mimetype="text/plain"
        )
        assert not_downloadable.is_downloadable() is False
        
        # Test with invalid URL
        invalid_url = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="ftp://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        assert invalid_url.is_downloadable() is False

    def test_attachment_to_dict(self):
        """Test converting SlackAttachment to dictionary."""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="document.pdf",
            url="https://files.slack.com/document.pdf",
            size=1024000,
            mimetype="application/pdf",
            title="Important Document",
            timestamp="1673776200",
            user_id="U1234567890",
            channel_id="C1234567890",
            initial_comment="Here's the document"
        )
        
        result = attachment.to_dict()
        expected = {
            "fileId": "F1234567890",
            "filename": "document.pdf",
            "url": "https://files.slack.com/document.pdf",
            "size": 1024000,
            "mimetype": "application/pdf",
            "title": "Important Document",
            "timestamp": "1673776200",
            "userId": "U1234567890",
            "channelId": "C1234567890",
            "initialComment": "Here's the document"
        }
        
        assert result == expected

    def test_attachment_from_dict(self):
        """Test creating SlackAttachment from dictionary."""
        data = {
            "fileId": "F1234567890",
            "filename": "document.pdf",
            "url": "https://files.slack.com/document.pdf",
            "size": 1024000,
            "mimetype": "application/pdf",
            "title": "Important Document",
            "timestamp": "1673776200",
            "userId": "U1234567890",
            "channelId": "C1234567890",
            "initialComment": "Here's the document"
        }
        
        attachment = SlackAttachment.from_dict(data)
        
        assert attachment.file_id == "F1234567890"
        assert attachment.filename == "document.pdf"
        assert attachment.url == "https://files.slack.com/document.pdf"
        assert attachment.size == 1024000
        assert attachment.mimetype == "application/pdf"
        assert attachment.title == "Important Document"
        assert attachment.timestamp == "1673776200"
        assert attachment.user_id == "U1234567890"
        assert attachment.channel_id == "C1234567890"
        assert attachment.initial_comment == "Here's the document"

    def test_attachment_from_slack_file(self):
        """Test creating SlackAttachment from Slack file data."""
        file_data = {
            "id": "F1234567890",
            "name": "document.pdf",
            "url_private_download": "https://files.slack.com/document.pdf",
            "size": 1024000,
            "mimetype": "application/pdf",
            "title": "Important Document",
            "timestamp": 1673776200,
            "user": "U1234567890",
            "initial_comment": {"comment": "Here's the document"}
        }
        
        attachment = SlackAttachment.from_slack_file(file_data, "C1234567890")
        
        assert attachment.file_id == "F1234567890"
        assert attachment.filename == "document.pdf"
        assert attachment.url == "https://files.slack.com/document.pdf"
        assert attachment.size == 1024000
        assert attachment.mimetype == "application/pdf"
        assert attachment.title == "Important Document"
        assert attachment.timestamp == "1673776200"
        assert attachment.user_id == "U1234567890"
        assert attachment.channel_id == "C1234567890"
        assert attachment.initial_comment == "Here's the document"

    def test_attachment_edge_cases(self):
        """Test edge cases for SlackAttachment."""
        # Test with very large file size
        large_attachment = SlackAttachment(
            file_id="F1234567890",
            filename="large_file.zip",
            url="https://files.slack.com/large_file.zip",
            size=1073741824,  # 1GB
            mimetype="application/zip"
        )
        assert large_attachment.validate() is True
        
        # Test with zero size file
        empty_attachment = SlackAttachment(
            file_id="F1234567890",
            filename="empty.txt",
            url="https://files.slack.com/empty.txt",
            size=0,
            mimetype="text/plain"
        )
        assert empty_attachment.validate() is True
        
        # Test with special characters in filename
        special_filename = SlackAttachment(
            file_id="F1234567890",
            filename="file with spaces & symbols!.txt",
            url="https://files.slack.com/file.txt",
            size=1024,
            mimetype="text/plain"
        )
        assert special_filename.validate() is True


class TestSlackCommand:
    """Test cases for SlackCommand domain model."""

    def test_valid_command_creation(self):
        """Test creating a valid SlackCommand with all fields."""
        command = SlackCommand(
            command="/security-ir",
            text="status case-123",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop",
            user_name="john.doe",
            channel_name="security-incidents"
        )
        
        assert command.command == "/security-ir"
        assert command.text == "status case-123"
        assert command.user_id == "U1234567890"
        assert command.channel_id == "C1234567890"
        assert command.team_id == "T1234567890"
        assert command.response_url == "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop"
        assert command.trigger_id == "1234567890.987654321.abcdefghijklmnop"
        assert command.user_name == "john.doe"
        assert command.channel_name == "security-incidents"

    def test_command_creation_minimal(self):
        """Test creating a SlackCommand with minimal required fields."""
        command = SlackCommand(
            command="/test",
            text="",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        assert command.command == "/test"
        assert command.text == ""
        assert command.user_id == "U1234567890"
        assert command.channel_id == "C1234567890"
        assert command.team_id == "T1234567890"
        assert command.response_url == "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop"
        assert command.trigger_id == "1234567890.987654321.abcdefghijklmnop"
        assert command.user_name is None
        assert command.channel_name is None

    def test_command_validation_success(self):
        """Test successful validation of a valid SlackCommand."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        assert command.validate() is True

    def test_command_validation_missing_command(self):
        """Test validation failure when command is missing."""
        command = SlackCommand(
            command="",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Command is required"):
            command.validate()

    def test_command_validation_missing_user_id(self):
        """Test validation failure when user_id is missing."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="User ID is required"):
            command.validate()

    def test_command_validation_missing_channel_id(self):
        """Test validation failure when channel_id is missing."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Channel ID is required"):
            command.validate()

    def test_command_validation_missing_team_id(self):
        """Test validation failure when team_id is missing."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Team ID is required"):
            command.validate()

    def test_command_validation_missing_response_url(self):
        """Test validation failure when response_url is missing."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Response URL is required"):
            command.validate()

    def test_command_validation_missing_trigger_id(self):
        """Test validation failure when trigger_id is missing."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id=""
        )
        
        with pytest.raises(ValueError, match="Trigger ID is required"):
            command.validate()

    def test_command_validation_invalid_command_format(self):
        """Test validation failure for invalid command format."""
        command = SlackCommand(
            command="test",  # Missing leading slash
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Invalid command format"):
            command.validate()

    def test_command_validation_invalid_user_id(self):
        """Test validation failure for invalid user ID format."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="invalid-user",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack user ID format"):
            command.validate()

    def test_command_validation_invalid_channel_id(self):
        """Test validation failure for invalid channel ID format."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="invalid-channel",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack channel ID format"):
            command.validate()

    def test_command_validation_invalid_team_id(self):
        """Test validation failure for invalid team ID format."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="invalid-team",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack team ID format"):
            command.validate()

    def test_command_validation_invalid_response_url(self):
        """Test validation failure for invalid response URL format."""
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://invalid.com/webhook",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Invalid response URL format"):
            command.validate()

    def test_command_to_dict(self):
        """Test converting SlackCommand to dictionary."""
        command = SlackCommand(
            command="/security-ir",
            text="status case-123",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop",
            user_name="john.doe",
            channel_name="security-incidents"
        )
        
        result = command.to_dict()
        expected = {
            "command": "/security-ir",
            "text": "status case-123",
            "userId": "U1234567890",
            "channelId": "C1234567890",
            "teamId": "T1234567890",
            "responseUrl": "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            "triggerId": "1234567890.987654321.abcdefghijklmnop",
            "userName": "john.doe",
            "channelName": "security-incidents"
        }
        
        assert result == expected

    def test_command_from_dict(self):
        """Test creating SlackCommand from dictionary."""
        data = {
            "command": "/security-ir",
            "text": "status case-123",
            "userId": "U1234567890",
            "channelId": "C1234567890",
            "teamId": "T1234567890",
            "responseUrl": "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            "triggerId": "1234567890.987654321.abcdefghijklmnop",
            "userName": "john.doe",
            "channelName": "security-incidents"
        }
        
        command = SlackCommand.from_dict(data)
        
        assert command.command == "/security-ir"
        assert command.text == "status case-123"
        assert command.user_id == "U1234567890"
        assert command.channel_id == "C1234567890"
        assert command.team_id == "T1234567890"
        assert command.response_url == "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop"
        assert command.trigger_id == "1234567890.987654321.abcdefghijklmnop"
        assert command.user_name == "john.doe"
        assert command.channel_name == "security-incidents"

    def test_command_from_slack_payload(self):
        """Test creating SlackCommand from Slack command payload."""
        payload = {
            "command": "/security-ir",
            "text": "status case-123",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "team_id": "T1234567890",
            "response_url": "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            "trigger_id": "1234567890.987654321.abcdefghijklmnop",
            "user_name": "john.doe",
            "channel_name": "security-incidents"
        }
        
        command = SlackCommand.from_slack_payload(payload)
        
        assert command.command == "/security-ir"
        assert command.text == "status case-123"
        assert command.user_id == "U1234567890"
        assert command.channel_id == "C1234567890"
        assert command.team_id == "T1234567890"
        assert command.response_url == "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop"
        assert command.trigger_id == "1234567890.987654321.abcdefghijklmnop"
        assert command.user_name == "john.doe"
        assert command.channel_name == "security-incidents"

    def test_command_parse_subcommand(self):
        """Test parsing subcommand and arguments."""
        # Test with subcommand and arguments
        command = SlackCommand(
            command="/security-ir",
            text="update-description This is a new description",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        
        subcommand, args = command.parse_subcommand()
        assert subcommand == "update-description"
        assert args == "This is a new description"
        
        # Test with subcommand only
        command.text = "status"
        subcommand, args = command.parse_subcommand()
        assert subcommand == "status"
        assert args == ""
        
        # Test with empty text
        command.text = ""
        subcommand, args = command.parse_subcommand()
        assert subcommand == ""
        assert args == ""
        
        # Test with whitespace
        command.text = "   help   "
        subcommand, args = command.parse_subcommand()
        assert subcommand == "help"
        assert args == ""

    def test_command_edge_cases(self):
        """Test edge cases for SlackCommand."""
        # Test with very long command text
        long_text = "subcommand " + "a" * 1000
        command = SlackCommand(
            command="/test",
            text=long_text,
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        assert command.validate() is True
        
        # Test with special characters in command text
        special_text = "status @user #channel :emoji: <@U1234567890>"
        command = SlackCommand(
            command="/test",
            text=special_text,
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        assert command.validate() is True


class TestSlackDomainIntegration:
    """Integration tests for Slack domain models working together."""

    def test_serialization_roundtrip(self):
        """Test that all models can be serialized and deserialized correctly."""
        # Test SlackChannel
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id="case-123"
        )
        channel_dict = channel.to_dict()
        restored_channel = SlackChannel.from_dict(channel_dict)
        assert restored_channel.channel_id == channel.channel_id
        assert restored_channel.channel_name == channel.channel_name
        assert restored_channel.case_id == channel.case_id
        
        # Test SlackMessage
        message = SlackMessage(
            message_id="1673776200.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Hello",
            timestamp="1673776200.123456"
        )
        message_dict = message.to_dict()
        restored_message = SlackMessage.from_dict(message_dict)
        assert restored_message.message_id == message.message_id
        assert restored_message.channel_id == message.channel_id
        assert restored_message.user_id == message.user_id
        
        # Test SlackAttachment
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        attachment_dict = attachment.to_dict()
        restored_attachment = SlackAttachment.from_dict(attachment_dict)
        assert restored_attachment.file_id == attachment.file_id
        assert restored_attachment.filename == attachment.filename
        assert restored_attachment.url == attachment.url
        
        # Test SlackCommand
        command = SlackCommand(
            command="/test",
            text="hello",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.987654321.abcdefghijklmnop"
        )
        command_dict = command.to_dict()
        restored_command = SlackCommand.from_dict(command_dict)
        assert restored_command.command == command.command
        assert restored_command.text == command.text
        assert restored_command.user_id == command.user_id

    def test_factory_methods_with_real_slack_data(self):
        """Test factory methods with realistic Slack API data."""
        # Test SlackChannel from Slack response
        slack_channel_response = {
            "id": "C1234567890",
            "name": "security-incident-123",
            "created": 1673776200,
            "members": ["U1234567890", "U0987654321", "U1111111111"],
            "topic": {
                "value": "Security incident case-123 discussion",
                "creator": "U1234567890",
                "last_set": 1673776300
            },
            "purpose": {
                "value": "Handle security incident case-123",
                "creator": "U1234567890",
                "last_set": 1673776300
            }
        }
        
        channel = SlackChannel.from_slack_response(slack_channel_response, "case-123")
        assert channel.validate() is True
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "security-incident-123"
        assert channel.case_id == "case-123"
        assert len(channel.members) == 3
        assert channel.topic == "Security incident case-123 discussion"
        assert channel.purpose == "Handle security incident case-123"
        
        # Test SlackMessage from Slack event
        slack_message_event = {
            "type": "message",
            "ts": "1673776200.123456",
            "user": "U1234567890",
            "text": "I've identified the root cause of the security incident.",
            "channel": "C1234567890",
            "thread_ts": "1673776100.123456"
        }
        
        message = SlackMessage.from_slack_event(slack_message_event)
        assert message.validate() is True
        assert message.message_id == "1673776200.123456"
        assert message.channel_id == "C1234567890"
        assert message.user_id == "U1234567890"
        assert message.text == "I've identified the root cause of the security incident."
        assert message.thread_ts == "1673776100.123456"
        
        # Test SlackAttachment from Slack file
        slack_file_data = {
            "id": "F1234567890",
            "name": "incident_report.pdf",
            "title": "Security Incident Report - Case 123",
            "mimetype": "application/pdf",
            "size": 2048576,
            "url_private_download": "https://files.slack.com/files-pri/T1234567890-F1234567890/incident_report.pdf",
            "timestamp": 1673776200,
            "user": "U1234567890",
            "initial_comment": {
                "comment": "Here's the detailed incident report with findings and recommendations."
            }
        }
        
        attachment = SlackAttachment.from_slack_file(slack_file_data, "C1234567890")
        assert attachment.validate() is True
        assert attachment.file_id == "F1234567890"
        assert attachment.filename == "incident_report.pdf"
        assert attachment.title == "Security Incident Report - Case 123"
        assert attachment.mimetype == "application/pdf"
        assert attachment.size == 2048576
        assert attachment.is_downloadable() is True
        assert attachment.channel_id == "C1234567890"
        assert attachment.initial_comment == "Here's the detailed incident report with findings and recommendations."
        
        # Test SlackCommand from Slack payload
        slack_command_payload = {
            "token": "verification_token",
            "team_id": "T1234567890",
            "team_domain": "example",
            "channel_id": "C1234567890",
            "channel_name": "security-incidents",
            "user_id": "U1234567890",
            "user_name": "john.doe",
            "command": "/security-ir",
            "text": "status case-123",
            "response_url": "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            "trigger_id": "1234567890.987654321.abcdefghijklmnop"
        }
        
        command = SlackCommand.from_slack_payload(slack_command_payload)
        assert command.validate() is True
        assert command.command == "/security-ir"
        assert command.text == "status case-123"
        assert command.user_id == "U1234567890"
        assert command.channel_id == "C1234567890"
        assert command.team_id == "T1234567890"
        assert command.user_name == "john.doe"
        assert command.channel_name == "security-incidents"
        
        subcommand, args = command.parse_subcommand()
        assert subcommand == "status"
        assert args == "case-123"
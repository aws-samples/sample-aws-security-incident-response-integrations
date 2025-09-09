"""
Slack domain models for AWS Security Incident Response integration.

This module provides domain models for Slack entities used in the AWS Security
Incident Response integration. All models include comprehensive validation,
serialization support, and factory methods for creating instances from Slack API responses.

Key Features:
- Comprehensive validation with Slack-specific format checking
- Full serialization support (to_dict/from_dict)
- Factory methods for Slack API integration
- Type hints and comprehensive documentation
- Error handling with descriptive messages

Models:
- SlackChannel: Represents a Slack channel associated with a security incident
- SlackMessage: Represents a message in a Slack channel
- SlackAttachment: Represents a file attachment in Slack
- SlackCommand: Represents a slash command invocation
"""

import datetime
import logging
import re
from typing import List, Dict, Optional, Any

# Configure logging
logger = logging.getLogger()


class SlackChannel:
    """
    Domain model for a Slack channel associated with a security incident case
    """

    def __init__(
        self,
        channel_id: str,
        channel_name: str,
        case_id: str,
        members: Optional[List[str]] = None,
        created_at: Optional[datetime.datetime] = ...,  # Use Ellipsis as sentinel
        topic: Optional[str] = None,
        purpose: Optional[str] = None
    ):
        """
        Initialize a SlackChannel

        Args:
            channel_id (str): Slack channel ID
            channel_name (str): Slack channel name
            case_id (str): Associated AWS SIR case ID
            members (Optional[List[str]]): List of channel member IDs
            created_at (Optional[datetime.datetime]): Channel creation time
            topic (Optional[str]): Channel topic
            purpose (Optional[str]): Channel purpose
        """
        self.channel_id = channel_id
        self.channel_name = channel_name
        self.case_id = case_id
        self.members = members or []
        # Set default timestamp only if not explicitly provided
        # Using Ellipsis (...) as sentinel to distinguish between None (explicit) 
        # and default parameter (implicit) - allows factory methods to pass None explicitly
        if created_at is ...:
            self.created_at = datetime.datetime.now(datetime.timezone.utc)
        else:
            self.created_at = created_at
        self.topic = topic
        self.purpose = purpose

    def validate(self) -> bool:
        """Validate the SlackChannel model.
        
        Performs comprehensive validation including:
        - Required field presence checks
        - Slack channel ID format validation (C + 8+ alphanumeric chars)
        - Channel name format validation (lowercase, alphanumeric, hyphens, underscores)

        Returns:
            bool: True if valid, False otherwise

        Raises:
            ValueError: If validation fails with specific error message
        """
        if not self.channel_id:
            raise ValueError("Channel ID is required")
        
        if not self.channel_name:
            raise ValueError("Channel name is required")
        
        if not self.case_id:
            raise ValueError("Case ID is required")
        
        # Validate Slack channel ID format (should start with 'C' and be alphanumeric)
        # Slack channel IDs follow pattern: C + 8 or more uppercase alphanumeric characters
        if not re.match(r'^C[A-Z0-9]{8,}$', self.channel_id):
            raise ValueError(f"Invalid Slack channel ID format: {self.channel_id}")
        
        # Validate channel name format (lowercase, alphanumeric, hyphens, underscores)
        # Slack channel names must be lowercase and can contain letters, numbers, hyphens, underscores
        if not re.match(r'^[a-z0-9\-_]+$', self.channel_name):
            raise ValueError(f"Invalid channel name format: {self.channel_name}")
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert the channel to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the channel
        """
        return {
            "channelId": self.channel_id,
            "channelName": self.channel_name,
            "caseId": self.case_id,
            "members": self.members,
            "createdAt": self.created_at.isoformat() if self.created_at else None,
            "topic": self.topic,
            "purpose": self.purpose
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SlackChannel':
        """Create a SlackChannel from a dictionary.

        Args:
            data (Dict[str, Any]): Dictionary representation of the channel

        Returns:
            SlackChannel: SlackChannel domain model
        """
        created_at = None
        if data.get("createdAt"):
            created_at = datetime.datetime.fromisoformat(data["createdAt"])
        
        return cls(
            channel_id=data.get("channelId"),
            channel_name=data.get("channelName"),
            case_id=data.get("caseId"),
            members=data.get("members", []),
            created_at=created_at,
            topic=data.get("topic"),
            purpose=data.get("purpose")
        )

    @classmethod
    def from_slack_response(cls, response: Dict[str, Any], case_id: str) -> 'SlackChannel':
        """Create a SlackChannel from Slack API response.

        Args:
            response (Dict[str, Any]): Slack API response
            case_id (str): Associated AWS SIR case ID

        Returns:
            SlackChannel: SlackChannel domain model
        """
        created_timestamp = response.get("created")
        created_at = datetime.datetime.fromtimestamp(created_timestamp) if created_timestamp else None
        
        return cls(
            channel_id=response.get("id"),
            channel_name=response.get("name"),
            case_id=case_id,
            members=response.get("members", []),
            created_at=created_at,
            topic=response.get("topic", {}).get("value") if response.get("topic") else None,
            purpose=response.get("purpose", {}).get("value") if response.get("purpose") else None
        )


class SlackMessage:
    """
    Domain model for a Slack message
    """

    def __init__(
        self,
        message_id: str,
        channel_id: str,
        user_id: str,
        text: str,
        timestamp: str,
        thread_ts: Optional[str] = None,
        message_type: str = "message",
        subtype: Optional[str] = None,
        user_name: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ):
        """
        Initialize a SlackMessage

        Args:
            message_id (str): Message ID (timestamp)
            channel_id (str): Slack channel ID
            user_id (str): User ID who sent the message
            text (str): Message text content
            timestamp (str): Message timestamp
            thread_ts (Optional[str]): Thread timestamp if message is in a thread
            message_type (str): Message type (default: "message")
            subtype (Optional[str]): Message subtype
            user_name (Optional[str]): User display name
            attachments (Optional[List[Dict[str, Any]]]): Message attachments
        """
        self.message_id = message_id
        self.channel_id = channel_id
        self.user_id = user_id
        self.text = text
        self.timestamp = timestamp
        self.thread_ts = thread_ts
        self.message_type = message_type
        self.subtype = subtype
        self.user_name = user_name
        self.attachments = attachments or []

    def validate(self) -> bool:
        """Validate the SlackMessage model.

        Returns:
            bool: True if valid, False otherwise

        Raises:
            ValueError: If validation fails with specific error message
        """
        if not self.message_id:
            raise ValueError("Message ID is required")
        
        if not self.channel_id:
            raise ValueError("Channel ID is required")
        
        if not self.user_id:
            raise ValueError("User ID is required")
        
        if not self.timestamp:
            raise ValueError("Timestamp is required")
        
        # Validate Slack channel ID format
        if not re.match(r'^C[A-Z0-9]{8,}$', self.channel_id):
            raise ValueError(f"Invalid Slack channel ID format: {self.channel_id}")
        
        # Validate Slack user ID format (should start with 'U' for users or 'B' for bots)
        if not re.match(r'^[UB][A-Z0-9]{8,}$', self.user_id):
            raise ValueError(f"Invalid Slack user ID format: {self.user_id}")
        
        # Validate timestamp format (should be a valid Slack timestamp)
        try:
            float(self.timestamp)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid timestamp format: {self.timestamp}")
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert the message to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the message
        """
        return {
            "messageId": self.message_id,
            "channelId": self.channel_id,
            "userId": self.user_id,
            "text": self.text,
            "timestamp": self.timestamp,
            "threadTs": self.thread_ts,
            "messageType": self.message_type,
            "subtype": self.subtype,
            "userName": self.user_name,
            "attachments": self.attachments
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SlackMessage':
        """Create a SlackMessage from a dictionary.

        Args:
            data (Dict[str, Any]): Dictionary representation of the message

        Returns:
            SlackMessage: SlackMessage domain model
        """
        return cls(
            message_id=data.get("messageId"),
            channel_id=data.get("channelId"),
            user_id=data.get("userId"),
            text=data.get("text", ""),
            timestamp=data.get("timestamp"),
            thread_ts=data.get("threadTs"),
            message_type=data.get("messageType", "message"),
            subtype=data.get("subtype"),
            user_name=data.get("userName"),
            attachments=data.get("attachments", [])
        )

    @classmethod
    def from_slack_event(cls, event: Dict[str, Any]) -> 'SlackMessage':
        """Create a SlackMessage from Slack event.

        Args:
            event (Dict[str, Any]): Slack message event

        Returns:
            SlackMessage: SlackMessage domain model
        """
        return cls(
            message_id=event.get("ts"),
            channel_id=event.get("channel"),
            user_id=event.get("user"),
            text=event.get("text", ""),
            timestamp=event.get("ts"),
            thread_ts=event.get("thread_ts"),
            message_type=event.get("type", "message"),
            subtype=event.get("subtype"),
            attachments=event.get("attachments", [])
        )

    def is_bot_message(self) -> bool:
        """Check if this is a bot message that should be filtered out.
        
        Bot messages should not be synchronized to AWS SIR to avoid loops and noise.
        This method identifies messages from bots, apps, or system-generated content.

        Returns:
            bool: True if this is a bot message, False otherwise
        """
        return (
            self.subtype in ["bot_message", "app_mention"] or
            self.user_id is None or
            self.user_id.startswith("B")  # Bot user IDs typically start with 'B'
        )


class SlackAttachment:
    """
    Domain model for a Slack file attachment
    """

    def __init__(
        self,
        file_id: str,
        filename: str,
        url: str,
        size: int,
        mimetype: str,
        title: Optional[str] = None,
        timestamp: Optional[str] = None,
        user_id: Optional[str] = None,
        channel_id: Optional[str] = None,
        initial_comment: Optional[str] = None
    ):
        """
        Initialize a SlackAttachment

        Args:
            file_id (str): Slack file ID
            filename (str): Original filename
            url (str): File download URL
            size (int): File size in bytes
            mimetype (str): File MIME type
            title (Optional[str]): File title
            timestamp (Optional[str]): Upload timestamp
            user_id (Optional[str]): User who uploaded the file
            channel_id (Optional[str]): Channel where file was shared
            initial_comment (Optional[str]): Initial comment with the file
        """
        self.file_id = file_id
        self.filename = filename
        self.url = url
        self.size = size
        self.mimetype = mimetype
        self.title = title or filename
        self.timestamp = timestamp
        self.user_id = user_id
        self.channel_id = channel_id
        self.initial_comment = initial_comment

    def validate(self) -> bool:
        """Validate the SlackAttachment model.

        Returns:
            bool: True if valid, False otherwise

        Raises:
            ValueError: If validation fails with specific error message
        """
        if not self.file_id:
            raise ValueError("File ID is required")
        
        if not self.filename:
            raise ValueError("Filename is required")
        
        if not self.url:
            raise ValueError("URL is required")
        
        if self.size < 0:
            raise ValueError("File size cannot be negative")
        
        if not self.mimetype:
            raise ValueError("MIME type is required")
        
        # Validate Slack file ID format
        if not re.match(r'^F[A-Z0-9]{8,}$', self.file_id):
            raise ValueError(f"Invalid Slack file ID format: {self.file_id}")
        
        # Validate URL format
        if not self.url.startswith(('http://', 'https://')):
            raise ValueError(f"Invalid URL format: {self.url}")
        
        # Validate user ID format if provided
        if self.user_id and not re.match(r'^[UB][A-Z0-9]{8,}$', self.user_id):
            raise ValueError(f"Invalid Slack user ID format: {self.user_id}")
        
        # Validate channel ID format if provided
        if self.channel_id and not re.match(r'^C[A-Z0-9]{8,}$', self.channel_id):
            raise ValueError(f"Invalid Slack channel ID format: {self.channel_id}")
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert the attachment to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the attachment
        """
        return {
            "fileId": self.file_id,
            "filename": self.filename,
            "url": self.url,
            "size": self.size,
            "mimetype": self.mimetype,
            "title": self.title,
            "timestamp": self.timestamp,
            "userId": self.user_id,
            "channelId": self.channel_id,
            "initialComment": self.initial_comment
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SlackAttachment':
        """Create a SlackAttachment from a dictionary.

        Args:
            data (Dict[str, Any]): Dictionary representation of the attachment

        Returns:
            SlackAttachment: SlackAttachment domain model
        """
        return cls(
            file_id=data.get("fileId"),
            filename=data.get("filename"),
            url=data.get("url"),
            size=data.get("size", 0),
            mimetype=data.get("mimetype", "application/octet-stream"),
            title=data.get("title"),
            timestamp=data.get("timestamp"),
            user_id=data.get("userId"),
            channel_id=data.get("channelId"),
            initial_comment=data.get("initialComment")
        )

    @classmethod
    def from_slack_file(cls, file_data: Dict[str, Any], channel_id: Optional[str] = None) -> 'SlackAttachment':
        """Create a SlackAttachment from Slack file data.

        Args:
            file_data (Dict[str, Any]): Slack file data
            channel_id (Optional[str]): Channel ID where file was shared

        Returns:
            SlackAttachment: SlackAttachment domain model
        """
        return cls(
            file_id=file_data.get("id"),
            filename=file_data.get("name"),
            url=file_data.get("url_private_download"),
            size=file_data.get("size", 0),
            mimetype=file_data.get("mimetype", "application/octet-stream"),
            title=file_data.get("title"),
            timestamp=str(file_data.get("timestamp", "")),
            user_id=file_data.get("user"),
            channel_id=channel_id,
            initial_comment=file_data.get("initial_comment", {}).get("comment")
        )


class SlackCommand:
    """
    Domain model for a Slack slash command
    """

    def __init__(
        self,
        command: str,
        text: str,
        user_id: str,
        channel_id: str,
        team_id: str,
        response_url: str,
        trigger_id: str,
        user_name: Optional[str] = None,
        channel_name: Optional[str] = None
    ):
        """
        Initialize a SlackCommand

        Args:
            command (str): The slash command (e.g., "/security-ir")
            text (str): Command text/arguments
            user_id (str): User who invoked the command
            channel_id (str): Channel where command was invoked
            team_id (str): Slack team/workspace ID
            response_url (str): URL for delayed responses
            trigger_id (str): Trigger ID for interactive components
            user_name (Optional[str]): User display name
            channel_name (Optional[str]): Channel name
        """
        self.command = command
        self.text = text
        self.user_id = user_id
        self.channel_id = channel_id
        self.team_id = team_id
        self.response_url = response_url
        self.trigger_id = trigger_id
        self.user_name = user_name
        self.channel_name = channel_name

    def validate(self) -> bool:
        """Validate the SlackCommand model.

        Returns:
            bool: True if valid, False otherwise

        Raises:
            ValueError: If validation fails with specific error message
        """
        if not self.command:
            raise ValueError("Command is required")
        
        if not self.user_id:
            raise ValueError("User ID is required")
        
        if not self.channel_id:
            raise ValueError("Channel ID is required")
        
        if not self.team_id:
            raise ValueError("Team ID is required")
        
        if not self.response_url:
            raise ValueError("Response URL is required")
        
        if not self.trigger_id:
            raise ValueError("Trigger ID is required")
        
        # Validate command format (should start with '/')
        if not self.command.startswith('/'):
            raise ValueError(f"Invalid command format: {self.command}")
        
        # Validate Slack user ID format
        if not re.match(r'^U[A-Z0-9]{8,}$', self.user_id):
            raise ValueError(f"Invalid Slack user ID format: {self.user_id}")
        
        # Validate Slack channel ID format
        if not re.match(r'^C[A-Z0-9]{8,}$', self.channel_id):
            raise ValueError(f"Invalid Slack channel ID format: {self.channel_id}")
        
        # Validate Slack team ID format
        if not re.match(r'^T[A-Z0-9]{8,}$', self.team_id):
            raise ValueError(f"Invalid Slack team ID format: {self.team_id}")
        
        # Validate response URL format
        if not self.response_url.startswith('https://hooks.slack.com/'):
            raise ValueError(f"Invalid response URL format: {self.response_url}")
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert the command to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the command
        """
        return {
            "command": self.command,
            "text": self.text,
            "userId": self.user_id,
            "channelId": self.channel_id,
            "teamId": self.team_id,
            "responseUrl": self.response_url,
            "triggerId": self.trigger_id,
            "userName": self.user_name,
            "channelName": self.channel_name
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SlackCommand':
        """Create a SlackCommand from a dictionary.

        Args:
            data (Dict[str, Any]): Dictionary representation of the command

        Returns:
            SlackCommand: SlackCommand domain model
        """
        return cls(
            command=data.get("command"),
            text=data.get("text", ""),
            user_id=data.get("userId"),
            channel_id=data.get("channelId"),
            team_id=data.get("teamId"),
            response_url=data.get("responseUrl"),
            trigger_id=data.get("triggerId"),
            user_name=data.get("userName"),
            channel_name=data.get("channelName")
        )

    @classmethod
    def from_slack_payload(cls, payload: Dict[str, Any]) -> 'SlackCommand':
        """Create a SlackCommand from Slack command payload.

        Args:
            payload (Dict[str, Any]): Slack command payload

        Returns:
            SlackCommand: SlackCommand domain model
        """
        return cls(
            command=payload.get("command"),
            text=payload.get("text", ""),
            user_id=payload.get("user_id"),
            channel_id=payload.get("channel_id"),
            team_id=payload.get("team_id"),
            response_url=payload.get("response_url"),
            trigger_id=payload.get("trigger_id"),
            user_name=payload.get("user_name"),
            channel_name=payload.get("channel_name")
        )

    def parse_subcommand(self) -> tuple[str, str]:
        """Parse the command text to extract subcommand and arguments.
        
        Splits the command text on the first space to separate the subcommand
        from its arguments. Handles cases with no arguments gracefully.
        
        Example:
            "/security-ir status" -> ("status", "")
            "/security-ir update-description New description" -> ("update-description", "New description")

        Returns:
            tuple[str, str]: (subcommand, arguments)
        """
        parts = self.text.strip().split(" ", 1)
        subcommand = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""
        return subcommand, args
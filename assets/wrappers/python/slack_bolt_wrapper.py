"""
Slack Bolt framework wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the Slack Bolt framework for use in the Security Incident Response integration.
"""

import os
import logging
import time
from typing import List, Dict, Optional, Any, Union, Callable

import boto3
from slack_bolt import App
from slack_sdk.errors import SlackApiError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
try:
    ssm_client: Optional[Any] = boto3.client("ssm")
except Exception:
    # For testing environments without AWS credentials
    ssm_client = None

# Import constants with fallbacks for different environments
try:
    from constants import (
        SLACK_MAX_RETRIES,
        SLACK_INITIAL_RETRY_DELAY,
        SLACK_MAX_RETRY_DELAY,
        SLACK_CHANNEL_PREFIX
    )
except ImportError:
    try:
        from aws_security_incident_response_sample_integrations.constants import (
            SLACK_MAX_RETRIES,
            SLACK_INITIAL_RETRY_DELAY,
            SLACK_MAX_RETRY_DELAY,
            SLACK_CHANNEL_PREFIX
        )
    except ImportError:
        # Fallback constants
        SLACK_MAX_RETRIES = 5
        SLACK_INITIAL_RETRY_DELAY = 1
        SLACK_MAX_RETRY_DELAY = 60
        SLACK_CHANNEL_PREFIX = "aws-security-incident-response-case-"


class SlackBoltClient:
    """Slack Bolt framework client for AWS Security Incident Response integration.
    
    This class provides a wrapper around the Slack Bolt framework to handle
    Slack API operations for security incident management. It includes
    authentication via SSM Parameter Store, retry logic with exponential
    backoff, and comprehensive error handling.
    
    Attributes:
        app (Optional[App]): Slack Bolt application instance
        client (Optional[WebClient]): Slack Web API client
        
    Example:
        >>> client = SlackBoltClient()
        >>> channel_id = client.create_channel('12345', 'Security Incident')
        >>> client.post_message(channel_id, 'Incident created')
    """

    def __init__(self) -> None:
        """Initialize the Slack Bolt client.
        
        Retrieves Slack credentials from SSM Parameter Store and creates
        a Slack Bolt application instance with proper authentication.
        
        Raises:
            Exception: If SSM Parameter Store access fails or credentials are invalid
        """
        self.app = self._create_app()
        self.client = self.app.client if self.app else None

    def _create_app(self) -> Optional[App]:
        """Create a Slack Bolt app instance.

        Returns:
            Optional[App]: Slack Bolt app or None if creation fails
        """
        try:
            bot_token = self._get_bot_token()
            signing_secret = self._get_signing_secret()

            if not bot_token or not signing_secret:
                logger.error("Failed to retrieve Slack credentials")
                return None

            return App(
                token=bot_token,
                signing_secret=signing_secret,
                process_before_response=True
            )
        except ValueError as e:
            logger.error(f"Invalid Slack credentials format: {str(e)}")
            return None
        except ImportError as e:
            logger.error(f"Missing Slack Bolt dependencies: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating Slack Bolt app: {str(e)}")
            return None

    def _get_bot_token(self) -> Optional[str]:
        """Fetch the Slack bot token from SSM Parameter Store.

        Returns:
            Optional[str]: Bot token or None if retrieval fails
        """
        try:
            if not ssm_client:
                logger.error("SSM client not available")
                return None
                
            bot_token_param_name = os.environ.get("SLACK_BOT_TOKEN", "/SecurityIncidentResponse/slackBotToken")
            response = ssm_client.get_parameter(
                Name=bot_token_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving Slack bot token from SSM: {str(e)}")
            return None

    def _get_signing_secret(self) -> Optional[str]:
        """Fetch the Slack signing secret from SSM Parameter Store.

        Returns:
            Optional[str]: Signing secret or None if retrieval fails
        """
        try:
            if not ssm_client:
                logger.error("SSM client not available")
                return None
                
            signing_secret_param_name = os.environ.get("SLACK_SIGNING_SECRET", "/SecurityIncidentResponse/slackSigningSecret")
            response = ssm_client.get_parameter(
                Name=signing_secret_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving Slack signing secret from SSM: {str(e)}")
            return None

    def _handle_retry_delay(self, attempt: int, delay: int, error_msg: str) -> int:
        """Handle retry delay logic.
        
        Args:
            attempt: Current attempt number
            delay: Current delay value
            error_msg: Error message to log
            
        Returns:
            Updated delay value
        """
        if attempt < SLACK_MAX_RETRIES - 1:
            logger.warning(f"{error_msg} on attempt {attempt + 1}")
            time.sleep(delay)
            return min(delay * 2, SLACK_MAX_RETRY_DELAY)
        else:
            logger.error(f"{error_msg} after {SLACK_MAX_RETRIES} attempts")
            raise

    def _retry_with_backoff(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute a function with exponential backoff retry logic.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result or None if all retries fail
        """
        delay = SLACK_INITIAL_RETRY_DELAY
        
        for attempt in range(SLACK_MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except SlackApiError as e:
                if e.response["error"] == "rate_limited":
                    headers = e.response.get("headers", {})
                    retry_after = int(headers.get("Retry-After", delay)) if hasattr(headers, 'get') else delay  # type: ignore
                    logger.warning(f"Rate limited, retrying after {retry_after} seconds")
                    time.sleep(retry_after)
                else:
                    delay = self._handle_retry_delay(attempt, delay, f"Slack API error: {e.response['error']}")
            except Exception as e:
                delay = self._handle_retry_delay(attempt, delay, f"Error: {str(e)}")
        
        return None

    def create_channel(self, case_id: str, case_title: Optional[str] = None) -> Optional[str]:
        """Create a new Slack channel for an incident.

        Creates a public Slack channel with the naming convention:
        'aws-security-incident-response-case-{case_id}'
        
        Args:
            case_id (str): The AWS SIR case ID (e.g., '12345')
            case_title (Optional[str]): The case title for channel topic.
                If provided, sets channel topic to 'AWS Security Incident: {case_title}'

        Returns:
            Optional[str]: Slack channel ID if successful (e.g., 'C1234567890'), 
                          None if creation fails
                          
        Example:
            >>> client = SlackBoltClient()
            >>> channel_id = client.create_channel('12345', 'Security Breach')
            >>> print(channel_id)  # 'C1234567890'
            
        Raises:
            SlackApiError: When Slack API returns an error
            Exception: For other unexpected errors
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return None

        try:
            channel_name = f"{SLACK_CHANNEL_PREFIX}{case_id}"
            
            def _create_channel() -> str:
                response = self.client.conversations_create(  # type: ignore
                    name=channel_name,
                    is_private=False
                )
                return response["channel"]["id"]  # type: ignore

            channel_id = self._retry_with_backoff(_create_channel)
            
            if channel_id and case_title:
                # Set channel topic
                self._retry_with_backoff(
                    self.client.conversations_setTopic,
                    channel=channel_id,
                    topic=f"AWS Security Incident: {case_title}"
                )
            
            logger.info(f"Created Slack channel {channel_name} with ID {channel_id}")
            return channel_id
            
        except Exception as e:
            logger.error(f"Error creating Slack channel for case {case_id}: {str(e)}")
            return None

    def post_message(self, channel_id: str, text: str, blocks: Optional[List[Dict[str, Any]]] = None) -> bool:
        """Post a message to a Slack channel.

        Args:
            channel_id (str): The Slack channel ID (e.g., 'C1234567890')
            text (str): Message text content
            blocks (Optional[List[Dict[str, Any]]]): Slack Block Kit elements for rich formatting.
                See https://api.slack.com/block-kit for format details

        Returns:
            bool: True if message posted successfully, False otherwise
            
        Example:
            >>> client = SlackBoltClient()
            >>> success = client.post_message(
            ...     'C1234567890', 
            ...     'New security incident created',
            ...     blocks=[{
            ...         'type': 'section',
            ...         'text': {'type': 'mrkdwn', 'text': '*Case ID:* 12345'}
            ...     }]
            ... )
            >>> print(success)  # True
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return False

        try:
            def _post_message() -> Any:
                return self.client.chat_postMessage(  # type: ignore
                    channel=channel_id,
                    text=text,
                    blocks=blocks
                )

            result = self._retry_with_backoff(_post_message)
            return result is not None
            
        except Exception as e:
            logger.error(f"Error posting message to channel {channel_id}: {str(e)}")
            return False

    def add_users_to_channel(self, channel_id: str, user_ids: List[str]) -> bool:
        """Add users to a Slack channel.

        Args:
            channel_id (str): The Slack channel ID
            user_ids (List[str]): List of user IDs to add

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client or not user_ids:
            return False

        try:
            def _invite_users() -> Any:
                return self.client.conversations_invite(  # type: ignore
                    channel=channel_id,
                    users=",".join(user_ids)
                )

            result = self._retry_with_backoff(_invite_users)
            return result is not None
            
        except Exception as e:
            logger.error(f"Error adding users to channel {channel_id}: {str(e)}")
            return False

    def get_channel_info(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a Slack channel.

        Args:
            channel_id (str): The Slack channel ID

        Returns:
            Optional[Dict[str, Any]]: Channel information or None if retrieval fails
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return None

        try:
            def _get_channel_info() -> Any:
                response = self.client.conversations_info(channel=channel_id)  # type: ignore
                return response["channel"]  # type: ignore

            return self._retry_with_backoff(_get_channel_info)
            
        except Exception as e:
            logger.error(f"Error getting channel info for {channel_id}: {str(e)}")
            return None

    def upload_file(self, channel_id: str, file_content: bytes, filename: str, 
                   title: Optional[str] = None, initial_comment: Optional[str] = None) -> bool:
        """Upload a file to a Slack channel.

        Args:
            channel_id (str): The Slack channel ID (e.g., 'C1234567890')
            file_content (bytes): File content as bytes
            filename (str): Name of the file (e.g., 'evidence.pdf')
            title (Optional[str]): File title displayed in Slack. Defaults to filename
            initial_comment (Optional[str]): Comment to accompany the file upload

        Returns:
            bool: True if file uploaded successfully, False otherwise
            
        Example:
            >>> client = SlackBoltClient()
            >>> with open('evidence.pdf', 'rb') as f:
            ...     content = f.read()
            >>> success = client.upload_file(
            ...     'C1234567890',
            ...     content,
            ...     'evidence.pdf',
            ...     title='Security Evidence',
            ...     initial_comment='Evidence from incident investigation'
            ... )
            >>> print(success)  # True
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return False

        try:
            def _upload_file() -> Any:
                return self.client.files_upload_v2(  # type: ignore
                    channel=channel_id,
                    file=file_content,
                    filename=filename,
                    title=title or filename,
                    initial_comment=initial_comment
                )

            result = self._retry_with_backoff(_upload_file)
            return result is not None
            
        except Exception as e:
            logger.error(f"Error uploading file to channel {channel_id}: {str(e)}")
            return False

    def remove_users_from_channel(self, channel_id: str, user_ids: List[str]) -> bool:
        """Remove users from a Slack channel.

        Args:
            channel_id (str): The Slack channel ID
            user_ids (List[str]): List of user IDs to remove

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client or not user_ids:
            return False

        try:
            def _kick_users() -> Dict[str, bool]:
                # Slack API requires individual kick operations
                for user_id in user_ids:
                    self.client.conversations_kick(  # type: ignore
                        channel=channel_id,
                        user=user_id
                    )
                return {"ok": True}

            result = self._retry_with_backoff(_kick_users)
            return result is not None
            
        except Exception as e:
            logger.error(f"Error removing users from channel {channel_id}: {str(e)}")
            return False

    def update_channel_topic(self, channel_id: str, topic: str) -> bool:
        """Update the topic of a Slack channel.

        Args:
            channel_id (str): The Slack channel ID
            topic (str): New topic text

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return False

        try:
            def _set_topic() -> Any:
                return self.client.conversations_setTopic(  # type: ignore
                    channel=channel_id,
                    topic=topic
                )

            result = self._retry_with_backoff(_set_topic)
            return result is not None
            
        except Exception as e:
            logger.error(f"Error updating channel topic for {channel_id}: {str(e)}")
            return False

    def get_channel_members(self, channel_id: str) -> Optional[List[str]]:
        """Get list of members in a Slack channel.

        Args:
            channel_id (str): The Slack channel ID

        Returns:
            Optional[List[str]]: List of user IDs or None if retrieval fails
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return None

        try:
            def _get_members() -> List[str]:
                response = self.client.conversations_members(channel=channel_id)  # type: ignore
                return response["members"]  # type: ignore

            return self._retry_with_backoff(_get_members)
            
        except Exception as e:
            logger.error(f"Error getting channel members for {channel_id}: {str(e)}")
            return None

    def archive_channel(self, channel_id: str) -> bool:
        """Archive a Slack channel.

        Args:
            channel_id (str): The Slack channel ID

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return False

        try:
            def _archive_channel() -> Any:
                return self.client.conversations_archive(channel=channel_id)  # type: ignore

            result = self._retry_with_backoff(_archive_channel)
            return result is not None
            
        except Exception as e:
            logger.error(f"Error archiving channel {channel_id}: {str(e)}")
            return False

    def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a Slack user.

        Args:
            user_id (str): The Slack user ID (e.g., 'U1234567890')

        Returns:
            Optional[Dict[str, Any]]: User information dictionary containing:
                - id: User ID
                - name: Username
                - real_name: Display name
                - email: User email (if available)
                Returns None if retrieval fails
                
        Example:
            >>> client = SlackBoltClient()
            >>> user_info = client.get_user_info('U1234567890')
            >>> print(user_info['real_name'])  # 'John Doe'
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return None

        try:
            def _get_user_info() -> Dict[str, Any]:
                response = self.client.users_info(user=user_id)  # type: ignore
                return response["user"]  # type: ignore

            return self._retry_with_backoff(_get_user_info)
            
        except Exception as e:
            logger.error(f"Error getting user info for {user_id}: {str(e)}")
            return None

    def get_channel_messages(self, channel_id: str, oldest: Optional[str] = None, latest: Optional[str] = None, 
                           limit: int = 100) -> Optional[List[Dict[str, Any]]]:
        """Get messages from a Slack channel.

        Args:
            channel_id (str): The Slack channel ID
            oldest (str, optional): Oldest timestamp to include
            latest (str, optional): Latest timestamp to include
            limit (int): Maximum number of messages to retrieve

        Returns:
            Optional[List[Dict[str, Any]]]: List of messages or None if retrieval fails
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return None

        try:
            def _get_messages() -> List[Dict[str, Any]]:
                response = self.client.conversations_history(  # type: ignore
                    channel=channel_id,
                    oldest=oldest,
                    latest=latest,
                    limit=limit
                )
                return response["messages"]  # type: ignore

            return self._retry_with_backoff(_get_messages)
            
        except Exception as e:
            logger.error(f"Error getting messages from channel {channel_id}: {str(e)}")
            return None
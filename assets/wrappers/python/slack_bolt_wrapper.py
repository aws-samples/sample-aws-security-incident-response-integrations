"""
Slack Bolt framework wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the Slack Bolt framework for use in the Security Incident Response integration.
"""

import os
import logging
import time
from typing import List, Dict, Optional, Any, Union

import boto3
from slack_bolt import App
from slack_sdk.errors import SlackApiError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
try:
    ssm_client = boto3.client("ssm")
except Exception:
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
    """Class to handle Slack Bolt framework interactions"""

    def __init__(self):
        """Initialize the Slack Bolt client."""
        self.app = self._create_app()
        self.client = self.app.client if self.app else None
        self.lambda_context = None
    
    def set_lambda_context(self, context):
        """Set the Lambda context for timeout-aware operations.
        
        Args:
            context: AWS Lambda context object
        """
        self.lambda_context = context

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
        except Exception as e:
            logger.error(f"Error creating Slack Bolt app: {str(e)}")
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

    def _retry_with_backoff(self, func, *args, **kwargs) -> Any:
        """Execute a function with exponential backoff retry logic.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result or None if all retries fail
        """
        delay = SLACK_INITIAL_RETRY_DELAY
        buffer_seconds = 30  # Buffer time before lambda timeout
        
        for attempt in range(SLACK_MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except SlackApiError as e:
                if attempt < SLACK_MAX_RETRIES - 1:
                    if e.response["error"] == "rate_limited":
                        # Handle rate limiting - check both response headers and nested headers
                        headers = e.response.get("headers", {})
                        if hasattr(headers, 'get'):
                            retry_after = int(headers.get("Retry-After", delay))
                        else:
                            retry_after = delay
                        sleep_time = retry_after
                        logger.warning(f"Rate limited, retrying after {retry_after} seconds")
                    else:
                        sleep_time = delay
                        logger.warning(f"Slack API error on attempt {attempt + 1}: {e.response['error']}")
                        delay = min(delay * 2, SLACK_MAX_RETRY_DELAY)
                    
                    # single timeout check for all sleep scenarios
                    if (self.lambda_context and 
                        hasattr(self.lambda_context, 'get_remaining_time_in_millis')):
                        remaining_ms = self.lambda_context.get_remaining_time_in_millis()
                        if remaining_ms < ((sleep_time + buffer_seconds) * 1000):
                            logger.warning(f"Insufficient time for delay ({sleep_time}s), aborting")
                            break
                    
                    time.sleep(sleep_time)
                else:
                    logger.error(f"Slack API error after {SLACK_MAX_RETRIES} attempts: {e.response['error']}")
                    raise
            except (ConnectionError, TimeoutError, OSError) as e:
                # Only retry network-related transient failures
                if attempt < SLACK_MAX_RETRIES - 1:
                    logger.warning(f"Network error on attempt {attempt + 1}: {str(e)}")
                    time.sleep(delay)
                    delay = min(delay * 2, SLACK_MAX_RETRY_DELAY)
                else:
                    logger.error(f"Network error after {SLACK_MAX_RETRIES} attempts: {str(e)}")
                    raise
            except Exception as e:
                # Don't retry programming errors - fail fast
                logger.error(f"Non-retryable error: {str(e)}")
                raise
        
        return None

    def create_channel(self, case_id: str, case_title: str = None) -> Optional[str]:
        """Create a new Slack channel for an incident.

        Args:
            case_id (str): The AWS SIR case ID
            case_title (str, optional): The case title for channel topic

        Returns:
            Optional[str]: Channel ID if successful, None otherwise
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return None

        try:
            channel_name = f"{SLACK_CHANNEL_PREFIX}{case_id}"
            
            def _create_channel():
                response = self.client.conversations_create(
                    name=channel_name,
                    is_private=False
                )
                return response["channel"]["id"]

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

    def post_message(self, channel_id: str, text: str, blocks: Optional[List[Dict]] = None) -> bool:
        """Post a message to a Slack channel.

        Args:
            channel_id (str): The Slack channel ID
            text (str): Message text
            blocks (Optional[List[Dict]]): Optional Slack blocks for rich formatting

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return False

        try:
            def _post_message():
                return self.client.chat_postMessage(
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
            def _invite_users():
                return self.client.conversations_invite(
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
            def _get_channel_info():
                response = self.client.conversations_info(channel=channel_id)
                return response["channel"]

            return self._retry_with_backoff(_get_channel_info)
            
        except Exception as e:
            logger.error(f"Error getting channel info for {channel_id}: {str(e)}")
            return None

    def upload_file(self, channel_id: str, file_content: bytes, filename: str, 
                   title: str = None, initial_comment: str = None) -> bool:
        """Upload a file to a Slack channel.

        Args:
            channel_id (str): The Slack channel ID
            file_content (bytes): File content as bytes
            filename (str): Name of the file
            title (str, optional): File title
            initial_comment (str, optional): Initial comment for the file

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return False

        try:
            def _upload_file():
                return self.client.files_upload_v2(
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
            def _kick_users():
                # Slack API requires individual kick operations
                for user_id in user_ids:
                    self.client.conversations_kick(
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
            def _set_topic():
                return self.client.conversations_setTopic(
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
            def _get_members():
                response = self.client.conversations_members(channel=channel_id)
                return response["members"]

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
            def _archive_channel():
                return self.client.conversations_archive(channel=channel_id)

            result = self._retry_with_backoff(_archive_channel)
            return result is not None
            
        except Exception as e:
            logger.error(f"Error archiving channel {channel_id}: {str(e)}")
            return False

    def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a Slack user.

        Args:
            user_id (str): The Slack user ID

        Returns:
            Optional[Dict[str, Any]]: User information or None if retrieval fails
        """
        if not self.client:
            logger.error("Slack client not initialized")
            return None

        try:
            def _get_user_info():
                response = self.client.users_info(user=user_id)
                return response["user"]

            return self._retry_with_backoff(_get_user_info)
            
        except Exception as e:
            logger.error(f"Error getting user info for {user_id}: {str(e)}")
            return None

    def get_channel_messages(self, channel_id: str, oldest: str = None, latest: str = None, 
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
            def _get_messages():
                response = self.client.conversations_history(
                    channel=channel_id,
                    oldest=oldest,
                    latest=latest,
                    limit=limit
                )
                return response["messages"]

            return self._retry_with_backoff(_get_messages)
            
        except Exception as e:
            logger.error(f"Error getting messages from channel {channel_id}: {str(e)}")
            return None
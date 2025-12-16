"""
Slack Client Lambda function for AWS Security Incident Response integration.
This function processes AWS SIR events and synchronizes them to Slack channels.
"""

import json
import logging
import os
import re
import datetime
import time
import secrets
from functools import wraps
from typing import Dict, Any, Optional, List, Tuple, Union, Callable

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()

# Get log level from environment variable
log_level = os.environ.get("LOG_LEVEL", "error").lower()
if log_level == "debug":
    logger.setLevel(logging.DEBUG)
elif log_level == "info":
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

# Initialize AWS clients
security_incident_response_client = boto3.client("security-ir")
dynamodb = boto3.resource("dynamodb")

# System comment tag for Slack updates
SLACK_SYSTEM_COMMENT_TAG = "[Slack Update]"

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from slack_bolt_wrapper import SlackBoltClient
    from slack_sir_mapper import (
        map_case_to_slack_channel_name,
        map_case_to_slack_channel_topic,
        map_case_to_slack_notification,
        map_case_update_to_slack_message,
        map_comment_to_slack_message,
        map_watchers_to_slack_users,
        map_slack_message_to_sir_comment,
        map_attachment_to_slack_file,
        create_system_comment,
        should_skip_comment
    )
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..wrappers.python.slack_bolt_wrapper import SlackBoltClient
    from ..mappers.python.slack_sir_mapper import (
        map_case_to_slack_channel_name,
        map_case_to_slack_channel_topic,
        map_case_to_slack_notification,
        map_case_update_to_slack_message,
        map_comment_to_slack_message,
        map_watchers_to_slack_users,
        map_slack_message_to_sir_comment,
        map_attachment_to_slack_file,
        create_system_comment,
        should_skip_comment
    )


def exponential_backoff_retry(max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0):
    """
    Decorator for exponential backoff retry logic.
    
    Args:
        max_retries (int): Maximum number of retry attempts
        base_delay (float): Base delay in seconds
        max_delay (float): Maximum delay in seconds
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt == max_retries:
                        logger.error(f"Function {func.__name__} failed after {max_retries} retries: {str(e)}")
                        raise e
                    
                    # Calculate delay with exponential backoff and jitter
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    jitter = secrets.randbelow(int(delay * 0.1 * 1000)) / 1000.0  # Add up to 10% jitter (cryptographically secure)
                    total_delay = delay + jitter
                    
                    logger.warning(f"Function {func.__name__} failed on attempt {attempt + 1}, retrying in {total_delay:.2f}s: {str(e)}")
                    time.sleep(total_delay)
            
            # This should never be reached, but just in case
            raise last_exception
        
        return wrapper
    return decorator


class DatabaseService:
    """Class to handle database operations"""

    def __init__(self):
        """Initialize the database service."""
        self.table_name = os.environ["INCIDENTS_TABLE_NAME"]
        self.table = dynamodb.Table(self.table_name)

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get a case from the database.

        Args:
            case_id (str): The IR case ID

        Returns:
            Optional[Dict[str, Any]]: Case data or None if retrieval fails
        """
        try:
            response = self.table.get_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"}
            )
            return response
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(
                f"Error retrieving details from the DynamoDB table: {error_code}"
            )
            return None
        except KeyError:
            logger.error(f"Slack channel for Case#{case_id} not found in database")
            return None

    @exponential_backoff_retry(max_retries=3, base_delay=0.5, max_delay=15.0)
    def update_slack_mapping(self, case_id: str, slack_channel_id: str) -> bool:
        """Update the mapping between an IR case and a Slack channel.

        Args:
            case_id (str): The IR case ID
            slack_channel_id (str): The Slack channel ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            current_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression="set slackChannelId = :s, slackChannelUpdateTimestamp = :t",
                ExpressionAttributeValues={
                    ":s": slack_channel_id,
                    ":t": current_timestamp
                },
                ReturnValues="UPDATED_NEW",
            )
            logger.info(f"IR case {case_id} mapped to Slack channel {slack_channel_id}")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error updating DynamoDB table: {error_code}")
            return False

    @exponential_backoff_retry(max_retries=3, base_delay=0.5, max_delay=15.0)
    def update_case_details(
        self, case_id: str, case_title: str = None, case_description: str = None, 
        case_comments: List[Any] = None, case_status: str = None, case_severity: str = None,
        case_watchers: List[Any] = None
    ) -> bool:
        """Update case details in the database.

        Args:
            case_id (str): The IR case ID
            case_title (str, optional): Case title
            case_description (str, optional): Case description
            case_comments (List[Any], optional): Case comments (can be strings or dicts)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            current_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            update_expression_parts = ["slackChannelUpdateTimestamp = :t"]
            expression_values = {":t": current_timestamp}

            if case_title is not None:
                update_expression_parts.append("slackChannelCaseTitle = :title")
                expression_values[":title"] = case_title

            if case_description is not None:
                update_expression_parts.append("slackChannelCaseDescription = :desc")
                expression_values[":desc"] = case_description

            if case_comments is not None:
                update_expression_parts.append("slackChannelCaseComments = :comments")
                expression_values[":comments"] = case_comments

            if case_status is not None:
                update_expression_parts.append("slackChannelCaseStatus = :status")
                expression_values[":status"] = case_status

            if case_severity is not None:
                update_expression_parts.append("slackChannelCaseSeverity = :severity")
                expression_values[":severity"] = case_severity

            if case_watchers is not None:
                update_expression_parts.append("slackChannelCaseWatchers = :watchers")
                expression_values[":watchers"] = case_watchers

            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression="set " + ", ".join(update_expression_parts),
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW",
            )
            logger.info(f"Updated case details in DynamoDB for case {case_id}")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error updating case details in DynamoDB: {error_code}")
            return False

    @exponential_backoff_retry(max_retries=3, base_delay=0.5, max_delay=15.0)
    def update_case_field(self, case_id: str, field_name: str, field_value: Any) -> bool:
        """Update a specific field in the case record.

        Args:
            case_id (str): The IR case ID
            field_name (str): Name of the field to update
            field_value (Any): Value to set for the field

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            current_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression=f"set {field_name} = :value, slackChannelUpdateTimestamp = :timestamp",
                ExpressionAttributeValues={
                    ":value": field_value,
                    ":timestamp": current_timestamp
                },
                ReturnValues="UPDATED_NEW",
            )
            logger.info(f"Updated field {field_name} for case {case_id}")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error updating field {field_name} in DynamoDB: {error_code}")
            return False


class SlackService:
    """Class to handle Slack operations"""

    def __init__(self):
        """Initialize the Slack service."""
        # Validate required environment variables
        slack_bot_token_param = os.environ.get('SLACK_BOT_TOKEN', '/SecurityIncidentResponse/slackBotToken')
        if not slack_bot_token_param:
            raise ValueError("SLACK_BOT_TOKEN environment variable is required")
        
        logger.info("Initializing Slack service with bot token parameter")
        
        self.slack_client = SlackBoltClient()
        self.db_service = DatabaseService()

    @exponential_backoff_retry(max_retries=3, base_delay=1.0, max_delay=30.0)
    def create_channel_for_case(self, case_id: str, case_data: Dict[str, Any]) -> Optional[str]:
        """Create a Slack channel for a new case.

        Args:
            case_id (str): The IR case ID
            case_data (Dict[str, Any]): Case data from AWS SIR

        Returns:
            Optional[str]: Slack channel ID if successful, None otherwise
        """
        try:
            # Generate channel name
            channel_name = map_case_to_slack_channel_name(case_id)
            case_title = case_data.get("title", "Security Incident")
            
            # Create the channel
            channel_id = self.slack_client.create_channel(case_id, case_title)
            if not channel_id:
                logger.error(f"Failed to create Slack channel for case {case_id}")
                return None

            # Update channel topic
            topic = map_case_to_slack_channel_topic(case_data)
            self.slack_client.update_channel_topic(channel_id, topic)

            # Add watchers to the channel
            watchers = case_data.get("watchers", [])
            if watchers:
                slack_users = map_watchers_to_slack_users(watchers)
                if slack_users:
                    self.slack_client.add_users_to_channel(channel_id, slack_users)

            # Store mapping in database
            self.db_service.update_slack_mapping(case_id, channel_id)

            # Ensure case_data has caseId for notification mapping
            case_data_with_id = case_data.copy()
            if "caseId" not in case_data_with_id:
                case_data_with_id["caseId"] = case_id

            # Post initial notification
            notification = map_case_to_slack_notification(case_data_with_id)
            self.slack_client.post_message(
                channel_id, 
                notification["text"], 
                notification.get("blocks")
            )

            # Add system comment to AWS SIR case
            system_comment = create_system_comment(
                f"Slack channel created: #{channel_name} (ID: {channel_id})"
            )
            self._add_system_comment_to_case(case_id, system_comment)

            logger.info(f"Successfully created Slack channel {channel_id} for case {case_id}")
            return channel_id

        except Exception as e:
            logger.error(f"Error creating Slack channel for case {case_id}: {str(e)}")
            # Add error comment to AWS SIR case
            error_comment = create_system_comment(
                "Failed to create Slack channel",
                str(e)
            )
            self._add_system_comment_to_case(case_id, error_comment)
            return None

    @exponential_backoff_retry(max_retries=3, base_delay=1.0, max_delay=30.0)
    def update_channel_for_case(self, case_id: str, case_data: Dict[str, Any], 
                               update_type: str) -> bool:
        """Update a Slack channel for an existing case.

        Args:
            case_id (str): The IR case ID
            case_data (Dict[str, Any]): Case data from AWS SIR
            update_type (str): Type of update (status, title, description, etc.)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get channel ID from database
            case_from_db = self.db_service.get_case(case_id)
            if not case_from_db or "Item" not in case_from_db:
                logger.error(f"No case found in database for IR case {case_id}")
                return False

            slack_channel_id = case_from_db["Item"].get("slackChannelId")
            if not slack_channel_id:
                logger.warning(f"No Slack channel found for case {case_id}, creating new channel")
                return self.create_channel_for_case(case_id, case_data) is not None

            # Update channel topic if status changed
            if update_type == "status":
                topic = map_case_to_slack_channel_topic(case_data)
                self.slack_client.update_channel_topic(slack_channel_id, topic)
            
            # Post description update message if description changed
            if update_type == "description":
                description = case_data.get("description", "No description provided")
                desc_message = f"📝 **Case Description Updated**\n{description}"
                self.slack_client.post_message(slack_channel_id, desc_message)
                
                # Try to update channel purpose/description if method exists
                try:
                    if hasattr(self.slack_client, 'update_channel_purpose'):
                        self.slack_client.update_channel_purpose(slack_channel_id, description)
                    elif hasattr(self.slack_client, 'update_channel_description'):
                        self.slack_client.update_channel_description(slack_channel_id, description)
                except Exception as e:
                    logger.warning(f"Could not update channel purpose for case {case_id}: {str(e)}")
            
            # Sync watchers if watchers changed
            if update_type == "watchers":
                watchers = case_data.get("watchers", [])
                self.sync_watchers_to_slack(case_id, watchers)

            # Ensure case_data has caseId for update message mapping
            case_data_with_id = case_data.copy()
            if "caseId" not in case_data_with_id:
                case_data_with_id["caseId"] = case_id

            # Post update message
            update_message = map_case_update_to_slack_message(case_data_with_id, update_type)
            success = self.slack_client.post_message(
                slack_channel_id,
                update_message["text"],
                update_message.get("blocks")
            )

            if success:
                # Update database with latest case details
                self.db_service.update_case_details(
                    case_id,
                    case_data.get("title"),
                    case_data.get("description"),
                    None,  # case_comments
                    case_data.get("caseStatus"),
                    case_data.get("severity"),
                    case_data.get("watchers")
                )
                logger.info(f"Successfully updated Slack channel for case {case_id}")
                return True
            else:
                logger.error(f"Failed to post update message to Slack channel for case {case_id}")
                return False

        except Exception as e:
            logger.error(f"Error updating Slack channel for case {case_id}: {str(e)}")
            # Check if this is the specific method missing error
            if "has no attribute 'update_channel_purpose'" in str(e):
                logger.warning(f"update_channel_purpose method not available, skipping channel purpose update for case {case_id}")
                # Still return True since the main update succeeded, just the purpose update failed
                return True
            else:
                # Add error comment to AWS SIR case for other errors
                error_comment = create_system_comment(
                    f"Failed to update Slack channel for {update_type} change",
                    str(e)
                )
                self._add_system_comment_to_case(case_id, error_comment)
                return False

            # Sync attachments if this is a case update
            if update_type in ["created", "updated"] and case_data.get("caseAttachments"):
                self.sync_attachments_to_slack(case_id, case_data["caseAttachments"])

    @exponential_backoff_retry(max_retries=3, base_delay=1.0, max_delay=30.0)
    def sync_comment_to_slack(self, case_id: str, comment: Dict[str, Any]) -> bool:
        """Sync a comment from AWS SIR to Slack with duplicate detection.

        Args:
            case_id (str): The IR case ID
            comment (Dict[str, Any]): Comment data from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Skip comments with Slack system tag to prevent loops
            comment_body = comment.get("body", "")
            if should_skip_comment(comment_body):
                logger.info(f"Skipping Slack system comment for case {case_id}")
                return True

            # Get channel ID from database
            case_from_db = self.db_service.get_case(case_id)
            if not case_from_db or "Item" not in case_from_db:
                logger.error(f"No case found in database for IR case {case_id}")
                return False

            slack_channel_id = case_from_db["Item"].get("slackChannelId")
            if not slack_channel_id:
                logger.warning(f"No Slack channel found for case {case_id}")
                return False

            # Check for duplicate comments using slackChannelUpdateTimestamp
            if self._is_duplicate_comment(case_id, comment, case_from_db["Item"]):
                logger.info(f"Skipping duplicate comment for case {case_id}")
                return True

            # Map comment to Slack message
            slack_message = map_comment_to_slack_message(comment, case_id)
            
            # Post comment to Slack
            success = self.slack_client.post_message(
                slack_channel_id,
                slack_message["text"],
                slack_message.get("blocks")
            )

            if success:
                # Update comment tracking in database
                self._track_synced_comment(case_id, comment)
                logger.info(f"Successfully synced comment to Slack for case {case_id}")
                return True
            else:
                logger.error(f"Failed to sync comment to Slack for case {case_id}")
                return False

        except Exception as e:
            logger.error(f"Error syncing comment to Slack for case {case_id}: {str(e)}")
            return False

    def sync_all_comments_to_slack(self, case_id: str, comments: List[Dict[str, Any]]) -> bool:
        """Sync all comments from AWS SIR to Slack, skipping duplicates.

        Args:
            case_id (str): The IR case ID
            comments (List[Dict[str, Any]]): List of all comments from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not comments:
                return True
            
            success_count = 0
            for comment in comments:
                if self.sync_comment_to_slack(case_id, comment):
                    success_count += 1
            
            logger.info(f"Synced {success_count}/{len(comments)} comments to Slack for case {case_id}")
            return True
        except Exception as e:
            logger.error(f"Error syncing all comments to Slack for case {case_id}: {str(e)}")
            return False

    def sync_watchers_to_slack(self, case_id: str, watchers: List[Any]) -> bool:
        """Sync watchers from AWS SIR to Slack channel.

        Args:
            case_id (str): The IR case ID
            watchers (List[Any]): List of watchers from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get channel ID from database
            case_from_db = self.db_service.get_case(case_id)
            if not case_from_db or "Item" not in case_from_db:
                logger.error(f"No case found in database for IR case {case_id}")
                return False

            slack_channel_id = case_from_db["Item"].get("slackChannelId")
            if not slack_channel_id:
                logger.warning(f"No Slack channel found for case {case_id}")
                return False

            # Get current channel members
            current_members = self.slack_client.get_channel_members(slack_channel_id)
            if current_members is None:
                logger.error(f"Failed to get current channel members for case {case_id}")
                return False

            # Process each watcher
            users_to_add = []
            for watcher in watchers:
                watcher_email = None
                watcher_name = "Unknown"
                
                if isinstance(watcher, dict):
                    watcher_email = watcher.get("email")
                    watcher_name = watcher.get("name") or watcher_email or "Unknown"
                
                if not watcher_email:
                    continue
                
                # Try to find the user in Slack
                slack_user_id = self.slack_client.find_user_by_email(watcher_email)
                
                if slack_user_id:
                    # User exists in Slack, check if they're in the channel
                    if slack_user_id not in current_members:
                        users_to_add.append(slack_user_id)
                        logger.info(f"Will add user {watcher_name} ({watcher_email}) to channel for case {case_id}")
                    else:
                        logger.debug(f"User {watcher_name} ({watcher_email}) already in channel for case {case_id}")
                else:
                    # User not found in Slack, check if message already posted
                    message = f"👤 New watcher added to Security IR case: **{watcher_name}** ({watcher_email}) - not found in Slack workspace"
                    if not self._is_watcher_message_posted(slack_channel_id, watcher_email):
                        self.slack_client.post_message(slack_channel_id, message)
                        logger.info(f"Posted notification for watcher not found in Slack: {watcher_name} ({watcher_email})")
                    else:
                        logger.debug(f"Watcher notification already posted for: {watcher_name} ({watcher_email})")

            # Add users to channel if any need to be added
            if users_to_add:
                success, failed_users = self.slack_client.add_users_to_channel(slack_channel_id, users_to_add)
                if success:
                    logger.info(f"Added {len(users_to_add)} users to Slack channel for case {case_id}")
                elif failed_users:
                    # Handle users who couldn't be added (e.g., not in workspace)
                    for user_id in failed_users:
                        user_email = next((w.get("email") for w in watchers if isinstance(w, dict) and self.slack_client.find_user_by_email(w.get("email")) == user_id), "unknown")
                        message = f"👤 New watcher added to Security IR case: **{user_email}** - user exists in Slack but not in this workspace"
                        self.slack_client.post_message(slack_channel_id, message)
                    logger.warning(f"Some users could not be added to Slack channel for case {case_id}")
                else:
                    logger.error(f"Failed to add users to Slack channel for case {case_id}")
                    return False
            else:
                logger.info(f"No users need to be added to Slack channel for case {case_id}")

            return True

        except Exception as e:
            logger.error(f"Error syncing watchers to Slack for case {case_id}: {str(e)}")
            return False

    def sync_attachments_to_slack(self, case_id: str, attachments: List[Dict[str, Any]]) -> bool:
        """Sync attachments from AWS SIR to Slack channel.

        Args:
            case_id (str): The IR case ID
            attachments (List[Dict[str, Any]]): List of attachments from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get channel ID from database
            case_from_db = self.db_service.get_case(case_id)
            if not case_from_db or "Item" not in case_from_db:
                logger.error(f"No case found in database for IR case {case_id}")
                return False

            slack_channel_id = case_from_db["Item"].get("slackChannelId")
            if not slack_channel_id:
                logger.warning(f"No Slack channel found for case {case_id}")
                return False

            if not attachments:
                logger.debug(f"No attachments to sync for case {case_id}")
                return True

            # Track synced attachments to avoid duplicates
            synced_attachments = case_from_db["Item"].get("syncedAttachments", [])
            new_attachments_synced = []
            
            for attachment in attachments:
                attachment_id = attachment.get("attachmentId")
                filename = attachment.get("fileName", "unknown_file")
                
                if not attachment_id:
                    logger.warning(f"Attachment missing ID for case {case_id}: {filename}")
                    continue
                
                # Skip if already synced
                if attachment_id in synced_attachments:
                    logger.debug(f"Attachment {filename} (ID: {attachment_id}) already synced for case {case_id}")
                    continue
                
                logger.info(f"Syncing new attachment {filename} (ID: {attachment_id}) for case {case_id}")
                
                # Download and upload actual file
                success = self.sync_attachment_to_slack(case_id, attachment)
                
                if success:
                    # Track this attachment as synced
                    new_attachments_synced.append(attachment_id)
                    logger.info(f"Successfully synced attachment {filename} to Slack for case {case_id}")
                else:
                    logger.error(f"Failed to sync attachment {filename} for case {case_id}")
            
            # Update synced attachments in database if we synced any new ones
            if new_attachments_synced:
                updated_synced_attachments = synced_attachments + new_attachments_synced
                self.db_service.update_case_field(case_id, "syncedAttachments", updated_synced_attachments)
                logger.info(f"Updated synced attachments list for case {case_id}: {updated_synced_attachments}")
            
            return True

        except Exception as e:
            logger.error(f"Error syncing attachments to Slack for case {case_id}: {str(e)}")
            return False

    def _download_and_upload_attachment(self, case_id: str, attachment_id: str, filename: str, slack_channel_id: str) -> bool:
        """Download attachment from Security IR and upload to Slack.

        Args:
            case_id (str): The IR case ID
            attachment_id (str): The attachment ID
            filename (str): The attachment filename
            slack_channel_id (str): The Slack channel ID

        Returns:
            bool: True if successful, False otherwise
        """
        import tempfile
        import os
        import requests
        
        try:
            # Get download URL from Security IR
            response = security_incident_response_client.get_case_attachment_download_url(
                caseId=case_id,
                attachmentId=attachment_id
            )
            
            download_url = response.get("attachmentPresignedUrl")
            if not download_url:
                logger.error(f"Failed to get download URL for attachment {attachment_id}")
                return False

            # Download file to temp directory
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as temp_file:
                temp_path = temp_file.name
                
                download_response = requests.get(download_url, timeout=30)
                download_response.raise_for_status()
                
                temp_file.write(download_response.content)
                temp_file.flush()
                
                # Upload to Slack
                with open(temp_path, 'rb') as file_content:
                    success = self.slack_client.upload_file(
                        channel_id=slack_channel_id,
                        file_content=file_content.read(),
                        filename=filename,
                        title=f"Attachment from Security IR Case {case_id}",
                        initial_comment=f"📎 Attachment from AWS Security Incident Response case {case_id}"
                    )
                
                # Clean up temp file
                os.unlink(temp_path)
                
                return success
                
        except Exception as e:
            logger.error(f"Error downloading/uploading attachment {attachment_id}: {str(e)}")
            return False

    def _add_system_comment_to_case(self, case_id: str, comment: str) -> bool:
        """Add a system comment to an AWS SIR case.

        Args:
            case_id (str): The IR case ID
            comment (str): Comment text

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            security_incident_response_client.create_case_comment(
                caseId=case_id,
                body=comment
            )
            logger.info(f"Added system comment to case {case_id}")
            return True
        except Exception as e:
            logger.error(f"Error adding system comment to case {case_id}: {str(e)}")
            return False

    def _is_duplicate_comment(self, case_id: str, comment: Dict[str, Any], case_data: Dict[str, Any]) -> bool:
        """Check if a comment is a duplicate using timestamp and content comparison.

        Args:
            case_id (str): The IR case ID
            comment (Dict[str, Any]): Comment data from AWS SIR
            case_data (Dict[str, Any]): Case data from DynamoDB

        Returns:
            bool: True if comment is a duplicate, False otherwise
        """
        try:
            # Get comment details
            comment_body = comment.get("body", "")
            comment_created_date = comment.get("createdDate", "")
            comment_id = comment.get("commentId", "")

            # Get stored comments from DynamoDB
            stored_comments = case_data.get("slackChannelCaseComments", [])
            
            # Check if this exact comment already exists
            for stored_comment in stored_comments:
                if isinstance(stored_comment, dict):
                    # Compare by comment ID if available
                    if comment_id and stored_comment.get("commentId") == comment_id:
                        return True
                    # Compare by body and creation date
                    if (stored_comment.get("body") == comment_body and 
                        stored_comment.get("createdDate") == comment_created_date):
                        return True
                elif isinstance(stored_comment, str):
                    # Legacy string format - compare body content
                    if comment_body in stored_comment:
                        return True

            # Only rely on exact comment ID and content matching for duplicate detection
            # Don't use timestamp comparison as it can incorrectly flag new comments as duplicates
            # when CaseUpdated events are processed before CommentAdded events

            return False

        except Exception as e:
            logger.error(f"Error checking for duplicate comment: {str(e)}")
            return False

    def _is_watcher_message_posted(self, channel_id: str, watcher_email: str) -> bool:
        """Check if watcher notification message already exists in channel.

        Args:
            channel_id (str): Slack channel ID
            watcher_email (str): Watcher email to check

        Returns:
            bool: True if message already posted, False otherwise
        """
        try:
            messages = self.slack_client.get_channel_messages(channel_id, limit=50)
            if not messages:
                return False
            
            # Check for both types of watcher messages
            search_texts = [
                f"({watcher_email}) - not found in Slack workspace",
                f"**{watcher_email}** - user exists in Slack but not in this workspace"
            ]
            return any(any(search_text in msg.get("text", "") for search_text in search_texts) for msg in messages)
        except Exception as e:
            logger.error(f"Error checking for existing watcher message: {str(e)}")
            return False

    def _track_synced_comment(self, case_id: str, comment: Dict[str, Any]) -> bool:
        """Track a synced comment in DynamoDB for duplicate detection.

        Args:
            case_id (str): The IR case ID
            comment (Dict[str, Any]): Comment data from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get current case data
            case_response = self.db_service.get_case(case_id)
            if not case_response or "Item" not in case_response:
                logger.error(f"Case {case_id} not found for comment tracking")
                return False

            case_data = case_response["Item"]
            # Get current comments
            current_comments = case_data.get("slackChannelCaseComments", [])
            
            # Create comment record for tracking
            comment_record = {
                "commentId": comment.get("commentId", ""),
                "body": comment.get("body", ""),
                "createdDate": comment.get("createdDate", ""),
                "createdBy": comment.get("createdBy", {}),
                "syncedToSlack": True,
                "syncTimestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

            # Add to comments list
            current_comments.append(comment_record)

            # Update database with new comment list
            return self.db_service.update_case_details(
                case_id=case_id,
                case_comments=current_comments
            )

        except Exception as e:
            logger.error(f"Error tracking synced comment for case {case_id}: {str(e)}")
            return False

    def sync_comments_from_slack(self, case_id: str, slack_messages: List[Dict[str, Any]]) -> bool:
        """Sync comments from Slack to AWS SIR (reverse direction).

        Args:
            case_id (str): The IR case ID
            slack_messages (List[Dict[str, Any]]): List of Slack messages to sync

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            success_count = 0
            
            for message in slack_messages:
                # Skip bot messages and system notifications
                if self._should_skip_slack_message(message):
                    continue

                # Check if message is already synced to avoid duplicates
                if self._is_slack_message_synced(case_id, message):
                    logger.debug(f"Skipping already synced Slack message for case {case_id}")
                    continue

                # Convert Slack message to SIR comment format
                user_name = self._get_slack_user_name(message.get("user", ""))
                sir_comment = map_slack_message_to_sir_comment(message, user_name)

                # Add comment to AWS SIR case
                try:
                    security_incident_response_client.create_case_comment(
                        caseId=case_id,
                        body=sir_comment
                    )
                    
                    # Track the synced message
                    self._track_slack_message_sync(case_id, message)
                    success_count += 1
                    logger.info(f"Synced Slack message to AWS SIR case {case_id}")
                    
                except Exception as e:
                    logger.error(f"Failed to sync Slack message to AWS SIR: {str(e)}")
                    continue

            logger.info(f"Successfully synced {success_count} Slack messages to AWS SIR case {case_id}")
            return success_count > 0

        except Exception as e:
            logger.error(f"Error syncing comments from Slack for case {case_id}: {str(e)}")
            return False

    def _should_skip_slack_message(self, message: Dict[str, Any]) -> bool:
        """Determine if a Slack message should be skipped during sync.

        Args:
            message (Dict[str, Any]): Slack message data

        Returns:
            bool: True if message should be skipped, False otherwise
        """
        # Skip bot messages
        if message.get("bot_id") or message.get("subtype") == "bot_message":
            return True

        # Skip system messages
        if message.get("subtype") in ["channel_join", "channel_leave", "channel_topic", "channel_purpose"]:
            return True

        # Skip messages with no text content
        if not message.get("text", "").strip():
            return True

        # Skip messages that look like system notifications
        text = message.get("text", "")
        if text.startswith("Case ") and ("status updated" in text or "updated" in text):
            return True

        return False

    def _is_slack_message_synced(self, case_id: str, message: Dict[str, Any]) -> bool:
        """Check if a Slack message has already been synced to AWS SIR.

        Args:
            case_id (str): The IR case ID
            message (Dict[str, Any]): Slack message data

        Returns:
            bool: True if message is already synced, False otherwise
        """
        try:
            # Get case data from database
            case_response = self.db_service.get_case(case_id)
            if not case_response or "Item" not in case_response:
                return False

            case_data = case_response["Item"]
            # Check if message timestamp is tracked
            message_ts = message.get("ts", "")
            if not message_ts:
                return False

            # Look for message in synced messages tracking
            synced_messages = case_data.get("slackSyncedMessages", [])
            for synced_msg in synced_messages:
                if isinstance(synced_msg, dict) and synced_msg.get("ts") == message_ts:
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking if Slack message is synced: {str(e)}")
            return False

    def _track_slack_message_sync(self, case_id: str, message: Dict[str, Any]) -> bool:
        """Track a Slack message that has been synced to AWS SIR.

        Args:
            case_id (str): The IR case ID
            message (Dict[str, Any]): Slack message data

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get current case data
            case_response = self.db_service.get_case(case_id)
            if not case_response or "Item" not in case_response:
                return False

            case_data = case_response["Item"]
            # Get current synced messages
            synced_messages = case_data.get("slackSyncedMessages", [])
            
            # Create message record
            message_record = {
                "ts": message.get("ts", ""),
                "user": message.get("user", ""),
                "text": message.get("text", ""),
                "syncedToSIR": True,
                "syncTimestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

            # Add to synced messages list
            synced_messages.append(message_record)

            # Update database - we need to extend the database service for this
            current_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.db_service.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression="set slackSyncedMessages = :messages, slackChannelUpdateTimestamp = :timestamp",
                ExpressionAttributeValues={
                    ":messages": synced_messages,
                    ":timestamp": current_timestamp
                },
                ReturnValues="UPDATED_NEW",
            )

            return True

        except Exception as e:
            logger.error(f"Error tracking Slack message sync: {str(e)}")
            return False

    def _get_slack_user_name(self, user_id: str) -> str:
        """Get Slack user display name from user ID.

        Args:
            user_id (str): Slack user ID

        Returns:
            str: User display name or user ID if lookup fails
        """
        try:
            if not user_id:
                return "Unknown User"

            # Try to get user info from Slack API
            user_info = self.slack_client.get_user_info(user_id)
            if user_info:
                return user_info.get("real_name", user_info.get("name", user_id))
            
            return user_id

        except Exception as e:
            logger.warning(f"Could not get user name for {user_id}: {str(e)}")
            return user_id

    def sync_attachment_to_slack(self, case_id: str, attachment: Dict[str, Any]) -> bool:
        """Sync an attachment from AWS SIR to Slack channel.

        Args:
            case_id (str): The IR case ID
            attachment (Dict[str, Any]): Attachment data from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get channel ID from database
            case_from_db = self.db_service.get_case(case_id)
            if not case_from_db or "Item" not in case_from_db:
                logger.error(f"No case found in database for IR case {case_id}")
                return False

            slack_channel_id = case_from_db["Item"].get("slackChannelId")
            if not slack_channel_id:
                logger.warning(f"No Slack channel found for case {case_id}")
                return False

            # Extract attachment details - try multiple field names
            attachment_id = attachment.get("attachmentId") or attachment.get("id") or ""
            filename = attachment.get("fileName") or attachment.get("filename") or attachment.get("name") or "attachment"
            
            logger.info(f"Processing attachment - ID: {attachment_id}, filename: {filename}")
            logger.debug(f"Full attachment data: {attachment}")
            
            # Check file size limits before download if size is available
            max_size = 100 * 1024 * 1024  # 100MB
            file_size = attachment.get("size", 0)
            if file_size > max_size:
                # Add system comment to AWS SIR case about size limit
                error_comment = create_system_comment(
                    f"Large attachment '{filename}' ({file_size} bytes) could not be uploaded to Slack due to size limits"
                )
                self._add_system_comment_to_case(case_id, error_comment)
                return False
            
            # Download attachment from AWS SIR
            try:
                # Get presigned URL for download
                presigned_response = security_incident_response_client.get_case_attachment_download_url(
                    caseId=case_id,
                    attachmentId=attachment_id
                )
                
                download_url = presigned_response.get("attachmentPresignedUrl")
                if not download_url:
                    logger.error(f"Failed to get download URL for attachment {attachment_id}")
                    return False

                # Download the file content
                import requests
                response = requests.get(download_url, timeout=30)
                response.raise_for_status()
                
                file_content = response.content
                
                # Check file size limits (Slack has a 1GB limit, but we'll be more conservative)
                max_size = 100 * 1024 * 1024  # 100MB
                if len(file_content) > max_size:
                    # Post a message about the large file instead
                    message = f"📎 Large attachment '{filename}' ({len(file_content)} bytes) from AWS SIR case {case_id} could not be uploaded due to size limits. Please download from the Security IR case."
                    self.slack_client.post_message(slack_channel_id, message)
                    
                    # Also add system comment to AWS SIR case
                    error_comment = create_system_comment(
                        f"Large attachment '{filename}' ({len(file_content)} bytes) could not be uploaded to Slack due to size limits"
                    )
                    self._add_system_comment_to_case(case_id, error_comment)
                    return False
                
                # Upload to Slack
                success = self.slack_client.upload_file(
                    channel_id=slack_channel_id,
                    file_content=file_content,
                    filename=filename,
                    title=f"Attachment from AWS SIR Case {case_id}",
                    initial_comment=f"📎 Attachment from AWS Security Incident Response case {case_id}"
                )
                
                if success:
                    logger.info(f"Successfully synced attachment {filename} to Slack for case {case_id}")
                    return True
                else:
                    logger.error(f"Failed to upload attachment {filename} to Slack for case {case_id}")
                    # Add system comment to AWS SIR case about upload failure
                    error_comment = create_system_comment(
                        f"Failed to upload attachment '{filename}' to Slack"
                    )
                    self._add_system_comment_to_case(case_id, error_comment)
                    return False
                    
            except Exception as download_error:
                logger.error(f"Error downloading attachment {attachment_id}: {str(download_error)}")
                # Post error message to Slack
                error_message = f"❌ Failed to sync attachment '{filename}' from AWS SIR case {case_id}: {str(download_error)}"
                self.slack_client.post_message(slack_channel_id, error_message)
                
                # Also add system comment to AWS SIR case
                error_comment = create_system_comment(
                    f"Failed to sync attachment '{filename}' to Slack",
                    str(download_error)
                )
                self._add_system_comment_to_case(case_id, error_comment)
                return False

        except Exception as e:
            logger.error(f"Error syncing attachment to Slack for case {case_id}: {str(e)}")
            return False

    def sync_attachments_from_sir_to_slack(self, case_id: str, attachments: List[Dict[str, Any]]) -> bool:
        """Sync multiple attachments from AWS SIR to Slack channel.

        Args:
            case_id (str): The IR case ID
            attachments (List[Dict[str, Any]]): List of attachment data from AWS SIR

        Returns:
            bool: True if all successful, False if any failed
        """
        if not attachments:
            logger.info(f"No attachments to sync for case {case_id}")
            return True

        success_count = 0
        total_count = len(attachments)

        for attachment in attachments:
            if self.sync_attachment_to_slack(case_id, attachment):
                success_count += 1
            else:
                logger.warning(f"Failed to sync attachment {attachment.get('filename', 'unknown')} for case {case_id}")

        logger.info(f"Synced {success_count}/{total_count} attachments to Slack for case {case_id}")
        return success_count == total_count

    def _download_sir_attachment(self, case_id: str, attachment: Dict[str, Any]) -> Optional[bytes]:
        """Download attachment content from AWS SIR.

        Args:
            case_id (str): The IR case ID
            attachment (Dict[str, Any]): Attachment metadata

        Returns:
            Optional[bytes]: Attachment content or None if download fails
        """
        try:
            attachment_id = attachment.get("attachmentId")
            if not attachment_id:
                logger.error(f"No attachment ID found for case {case_id}")
                logger.debug(f"Attachment data keys: {list(attachment.keys())}")
                return None

            # Download attachment from AWS SIR
            response = security_incident_response_client.get_case_attachment_download_url(
                caseId=case_id,
                attachmentId=attachment_id
            )
            
            download_url = response.get("attachmentDownloadUrl")
            if not download_url:
                logger.error(f"No download URL received for attachment {attachment_id}")
                return None

            # Download the file content
            import requests
            download_response = requests.get(download_url, timeout=30)
            download_response.raise_for_status()
            
            return download_response.content

        except Exception as e:
            logger.error(f"Error downloading attachment from AWS SIR: {str(e)}")
            return None

    def _get_slack_user_name(self, user_id: str) -> str:
        """Get Slack user display name from user ID.

        Args:
            user_id (str): Slack user ID

        Returns:
            str: User display name or user ID if name not found
        """
        try:
            if not user_id:
                return "Unknown User"

            # Try to get user info from Slack API
            user_info = self.slack_client.get_user_info(user_id)
            if user_info:
                return user_info.get("display_name") or user_info.get("real_name") or user_id
            
            return user_id

        except Exception as e:
            logger.warning(f"Error getting Slack user name for {user_id}: {str(e)}")
            return user_id


class IncidentService:
    """Class to handle incident operations"""

    def __init__(self):
        """Initialize the incident service."""
        self.slack_service = SlackService()
        self.db_service = DatabaseService()

    def extract_case_details(
        self, ir_case: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], str, str, str]:
        """Extract case details from an IR case.

        Args:
            ir_case (Dict[str, Any]): IR case data

        Returns:
            Tuple[Dict[str, Any], str, str, str]: Tuple of (ir_case_detail, ir_event_type, ir_case_id, sir_case_status)
        """
        ir_case_detail = ir_case["detail"]
        ir_event_type = ir_case_detail["eventType"]
        ir_case_arn = ir_case_detail["caseArn"]

        try:
            # TODO: update the following to retrieve GUID from ARN when the service starts using GUIDs
            ir_case_id = re.search(r"/(\d+)$", ir_case_arn).group(1)
        except (AttributeError, IndexError):
            logger.error(f"Failed to extract case ID from ARN: {ir_case_arn}")
            raise ValueError(f"Invalid case ARN format: {ir_case_arn}")

        sir_case_status = ir_case_detail.get("caseStatus")

        return ir_case_detail, ir_event_type, ir_case_id, sir_case_status

    def process_case_event(self, ir_case: Dict[str, Any]) -> bool:
        """Process a security incident event from AWS SIR.

        Args:
            ir_case (Dict[str, Any]): IR case data

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Extract case details
            ir_case_detail, ir_event_type, ir_case_id, sir_case_status = (
                self.extract_case_details(ir_case)
            )

            # Handle based on event type using dedicated handler methods
            if ir_event_type == "CaseCreated":
                return self.handle_case_created(ir_case_id, ir_case_detail)
            elif ir_event_type == "CaseUpdated":
                return self.handle_case_updated(ir_case_id, ir_case_detail)
            elif ir_event_type == "CommentAdded":
                return self.handle_comment_added(ir_case_id, ir_case_detail)
            elif ir_event_type == "AttachmentAdded":
                return self.handle_attachment_added(ir_case_id, ir_case_detail)
            else:
                logger.warning(f"Unhandled event type: {ir_event_type}")
                return False

        except Exception as e:
            logger.error(f"Error processing security incident: {str(e)}")
            return False

    def handle_case_created(self, case_id: str, case_detail: Dict[str, Any]) -> bool:
        """Handle CaseCreated event by creating a new Slack channel.

        Args:
            case_id (str): The IR case ID
            case_detail (Dict[str, Any]): Case detail data from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Handling CaseCreated event for case {case_id}")
            channel_id = self.slack_service.create_channel_for_case(case_id, case_detail)
            return channel_id is not None
        except Exception as e:
            logger.error(f"Error handling CaseCreated event for case {case_id}: {str(e)}")
            return False

    def handle_case_updated(self, case_id: str, case_detail: Dict[str, Any]) -> bool:
        """Handle CaseUpdated event by updating the Slack channel.

        Args:
            case_id (str): The IR case ID
            case_detail (Dict[str, Any]): Case detail data from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Handling CaseUpdated event for case {case_id}")
            
            # Sync all comments that haven't been synced yet
            comments = case_detail.get("caseComments", [])
            if comments:
                self.slack_service.sync_all_comments_to_slack(case_id, comments)
            
            # Always sync watchers on every CaseUpdated event
            watchers = case_detail.get("watchers", [])
            if watchers:
                self.slack_service.sync_watchers_to_slack(case_id, watchers)
            
            # Sync attachments in CaseUpdated events since AttachmentAdded events don't exist
            attachments = case_detail.get("caseAttachments", [])
            if attachments:
                self.slack_service.sync_attachments_to_slack(case_id, attachments)
            
            # Check what actually changed by comparing with stored state
            changed_fields = self._get_changed_fields(case_id, case_detail)
            
            if changed_fields:
                logger.info(f"Detected changes in fields: {changed_fields} for case {case_id}")
                update_type = self._determine_update_type_from_changes(changed_fields)
                return self.slack_service.update_channel_for_case(
                    case_id, case_detail, update_type
                )
            else:
                logger.info(f"No field changes detected for case {case_id}, skipping update notification")
            
            return True
        except Exception as e:
            logger.error(f"Error handling CaseUpdated event for case {case_id}: {str(e)}")
            return False

    def handle_comment_added(self, case_id: str, case_detail: Dict[str, Any]) -> bool:
        """Handle CommentAdded event by syncing comment to Slack.

        Args:
            case_id (str): The IR case ID
            case_detail (Dict[str, Any]): Case detail data from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Handling CommentAdded event for case {case_id}")
            # Handle comment synchronization
            comments = case_detail.get("caseComments", [])
            if comments:
                # Get the latest comment
                latest_comment = comments[-1] if isinstance(comments, list) else comments
                
                # Only sync the comment, never sync attachments in CommentAdded events
                # Attachments should only be synced in AttachmentAdded events
                return self.slack_service.sync_comment_to_slack(case_id, latest_comment)
            else:
                logger.warning(f"No comments found in CommentAdded event for case {case_id}")
                return True
        except Exception as e:
            logger.error(f"Error handling CommentAdded event for case {case_id}: {str(e)}")
            return False

    def handle_attachment_added(self, case_id: str, case_detail: Dict[str, Any]) -> bool:
        """Handle AttachmentAdded event by syncing attachment to Slack.

        Args:
            case_id (str): The IR case ID
            case_detail (Dict[str, Any]): Case detail data from AWS SIR

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Handling AttachmentAdded event for case {case_id}")
            logger.debug(f"Event detail keys: {list(case_detail.keys())}")
            
            # Handle attachment synchronization
            attachments = case_detail.get("caseAttachments", [])
            if not attachments:
                # Also check for 'attachments' key as used in some events
                attachments = case_detail.get("attachments", [])
            
            logger.info(f"Found {len(attachments)} attachments in AttachmentAdded event for case {case_id}")
            
            if attachments:
                # Get the latest attachment
                latest_attachment = attachments[-1] if isinstance(attachments, list) else attachments
                logger.info(f"Processing latest attachment: {latest_attachment}")
                
                success = self.slack_service.sync_attachment_to_slack(case_id, latest_attachment)
                
                if success:
                    # Update synced attachments tracking
                    attachment_id = latest_attachment.get("attachmentId")
                    if attachment_id:
                        case_from_db = self.db_service.get_case(case_id)
                        if case_from_db and "Item" in case_from_db:
                            synced_attachments = case_from_db["Item"].get("syncedAttachments", [])
                            if attachment_id not in synced_attachments:
                                synced_attachments.append(attachment_id)
                                self.db_service.update_case_field(case_id, "syncedAttachments", synced_attachments)
                                logger.info(f"Updated synced attachments for case {case_id}: {synced_attachments}")
                
                return success
            else:
                logger.warning(f"No attachments found in AttachmentAdded event for case {case_id}")
                return True
        except Exception as e:
            logger.error(f"Error handling AttachmentAdded event for case {case_id}: {str(e)}")
            return False

    def process_slack_event(self, event: Dict[str, Any]) -> bool:
        """Process a Slack event (for future use with bidirectional sync).

        Args:
            event (Dict[str, Any]): Slack event data

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # This would handle events from Slack (messages, file uploads, etc.)
            # For now, this is a placeholder for future bidirectional sync
            logger.info("Slack event processing not yet implemented")
            return True
        except Exception as e:
            logger.error(f"Error processing Slack event: {str(e)}")
            return False

    def _get_changed_fields(self, case_id: str, case_detail: Dict[str, Any]) -> List[str]:
        """Compare current case detail with stored state to find changed fields.

        Args:
            case_id (str): The IR case ID
            case_detail (Dict[str, Any]): Current case detail data

        Returns:
            List[str]: List of field names that have changed
        """
        try:
            # Get stored case data from database
            case_from_db = self.db_service.get_case(case_id)
            if not case_from_db or "Item" not in case_from_db:
                # If no stored data, only treat as changed if channel exists (not first time)
                return []
            
            stored_data = case_from_db["Item"]
            
            # If no Slack channel exists yet, don't report changes
            if not stored_data.get("slackChannelId"):
                return []
            
            changed_fields = []
            
            # Only check fields that have been previously stored
            current_status = case_detail.get("caseStatus")
            stored_status = stored_data.get("slackChannelCaseStatus")
            if stored_status is not None and current_status != stored_status:
                changed_fields.append("caseStatus")
            
            current_title = case_detail.get("title")
            stored_title = stored_data.get("slackChannelCaseTitle")
            if stored_title is not None and current_title != stored_title:
                changed_fields.append("title")
            
            current_description = case_detail.get("description")
            stored_description = stored_data.get("slackChannelCaseDescription")
            logger.debug(f"Description comparison for case {case_id}: current='{current_description}', stored='{stored_description}'")
            if current_description and (stored_description is None or current_description != stored_description):
                changed_fields.append("description")
            
            current_severity = case_detail.get("severity")
            stored_severity = stored_data.get("slackChannelCaseSeverity")
            if stored_severity is not None and current_severity != stored_severity:
                changed_fields.append("severity")
            
            current_watchers = case_detail.get("watchers", [])
            stored_watchers = stored_data.get("slackChannelCaseWatchers", [])
            if stored_watchers != [] and current_watchers != stored_watchers:
                changed_fields.append("watchers")
            
            return changed_fields
        except Exception as e:
            logger.error(f"Error detecting changed fields for case {case_id}: {str(e)}")
            return []

    def _determine_update_type_from_changes(self, changed_fields: List[str]) -> str:
        """Determine the type of case update based on changed fields.

        Args:
            changed_fields (List[str]): List of fields that changed

        Returns:
            str: Update type (status, title, description, etc.)
        """
        if "caseStatus" in changed_fields:
            return "status"
        elif "title" in changed_fields:
            return "title"
        elif "description" in changed_fields:
            return "description"
        elif "severity" in changed_fields:
            return "severity"
        elif "watchers" in changed_fields:
            return "watchers"
        else:
            return "general"

    def _determine_update_type(self, case_detail: Dict[str, Any]) -> str:
        """Determine the type of case update based on changed fields.

        Args:
            case_detail (Dict[str, Any]): Case detail data

        Returns:
            str: Update type (status, title, description, watchers, etc.)
        """
        # This is a simplified implementation - in practice, you might want to
        # compare with previous state to determine what actually changed
        if "caseStatus" in case_detail:
            return "status"
        elif "title" in case_detail:
            return "title"
        elif "description" in case_detail:
            return "description"
        elif "watchers" in case_detail:
            return "watchers"
        else:
            return "general"


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing AWS SIR events and syncing to Slack.
    
    Args:
        event: EventBridge event containing AWS SIR case information or Records format
        context: Lambda context object
        
    Returns:
        Dict containing status and response information
    """
    try:
        logger.info(f"Processing event: {json.dumps(event, default=str)}")
        
        EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "security-ir")
        
        # Parse event - support both Records format and direct EventBridge format
        actual_event = event
        if "Records" in event:
            if len(event["Records"]) == 0:
                raise ValueError("Empty Records array - no event to process")
            
            # Records format: event['Records'][0]['body'] contains the EventBridge event
            record_body = event["Records"][0]["body"]
            if isinstance(record_body, str):
                actual_event = json.loads(record_body)
            else:
                actual_event = record_body
            logger.info(f"Parsed EventBridge event from Records: {json.dumps(actual_event, default=str)}")
        
        event_source = actual_event.get("source", "")
        
        # Only process events from Security Incident Response
        if event_source == EVENT_SOURCE:
            incident_service = IncidentService()
            success = incident_service.process_case_event(actual_event)
            
            if success:
                return {
                    "statusCode": 200,
                    "body": json.dumps({"message": "Event processed successfully"})
                }
            else:
                return {
                    "statusCode": 500,
                    "body": json.dumps({"error": "Failed to process event"})
                }
        else:
            logger.info(f"Slack Client lambda will skip processing event from source: {event_source}")
            return {
                "statusCode": 200,
                "body": json.dumps(f"Event skipped - source {event_source} not matching EVENT_SOURCE {EVENT_SOURCE}")
            }
        
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
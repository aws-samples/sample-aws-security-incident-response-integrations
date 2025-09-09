"""
Slack Client Lambda function for AWS Security Incident Response integration.
This function processes AWS SIR events and synchronizes them to Slack channels.
"""

import json
import logging
import os
import re
import datetime
from typing import Dict, Any, Optional, List, Tuple, Union

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

    def update_slack_mapping(self, case_id: str, slack_channel_id: str) -> bool:
        """Update the mapping between an IR case and a Slack channel.

        Args:
            case_id (str): The IR case ID
            slack_channel_id (str): The Slack channel ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            current_timestamp = datetime.datetime.utcnow().isoformat()
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

    def update_case_details(
        self, case_id: str, case_title: str = None, case_description: str = None, 
        case_comments: List[Any] = None
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
            current_timestamp = datetime.datetime.utcnow().isoformat()
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


class SlackService:
    """Class to handle Slack operations"""

    def __init__(self):
        """Initialize the Slack service."""
        self.slack_client = SlackBoltClient()
        self.db_service = DatabaseService()

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

            # Post initial notification
            notification = map_case_to_slack_notification(case_data)
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

            # Post update message
            update_message = map_case_update_to_slack_message(case_data, update_type)
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
                    case_data.get("description")
                )
                logger.info(f"Successfully updated Slack channel for case {case_id}")
                return True
            else:
                logger.error(f"Failed to post update message to Slack channel for case {case_id}")
                return False

        except Exception as e:
            logger.error(f"Error updating Slack channel for case {case_id}: {str(e)}")
            # Add error comment to AWS SIR case
            error_comment = create_system_comment(
                f"Failed to update Slack channel for {update_type} change",
                str(e)
            )
            self._add_system_comment_to_case(case_id, error_comment)
            return False

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
            if not case_from_db:
                logger.error(f"No case found in database for IR case {case_id}")
                return False

            slack_channel_id = case_from_db.get("slackChannelId")
            if not slack_channel_id:
                logger.warning(f"No Slack channel found for case {case_id}")
                return False

            # Map watchers to Slack users
            slack_users = map_watchers_to_slack_users(watchers)
            if not slack_users:
                logger.info(f"No Slack users found for watchers in case {case_id}")
                return True

            # Get current channel members
            current_members = self.slack_client.get_channel_members(slack_channel_id)
            if current_members is None:
                logger.error(f"Failed to get current channel members for case {case_id}")
                return False

            # Add new users
            users_to_add = [user for user in slack_users if user not in current_members]
            if users_to_add:
                success = self.slack_client.add_users_to_channel(slack_channel_id, users_to_add)
                if success:
                    logger.info(f"Added {len(users_to_add)} users to Slack channel for case {case_id}")
                else:
                    logger.error(f"Failed to add users to Slack channel for case {case_id}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Error syncing watchers to Slack for case {case_id}: {str(e)}")
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

            # Check timestamp-based duplicate detection
            last_update = case_data.get("slackChannelUpdateTimestamp")
            if last_update and comment_created_date:
                try:
                    # Parse timestamps for comparison
                    from datetime import datetime
                    comment_time = datetime.fromisoformat(comment_created_date.replace('Z', '+00:00'))
                    last_update_time = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
                    
                    # If comment is older than last update, it might be a duplicate
                    if comment_time <= last_update_time:
                        logger.debug(f"Comment timestamp {comment_created_date} is older than last update {last_update}")
                        # Additional check: see if comment body exists in stored comments
                        for stored_comment in stored_comments:
                            stored_body = stored_comment.get("body", "") if isinstance(stored_comment, dict) else stored_comment
                            if comment_body == stored_body:
                                return True
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error parsing timestamps for duplicate detection: {e}")

            return False

        except Exception as e:
            logger.error(f"Error checking for duplicate comment: {str(e)}")
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
                "syncTimestamp": datetime.datetime.utcnow().isoformat()
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
                "syncTimestamp": datetime.datetime.utcnow().isoformat()
            }

            # Add to synced messages list
            synced_messages.append(message_record)

            # Update database - we need to extend the database service for this
            current_timestamp = datetime.datetime.utcnow().isoformat()
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

            # Check file size limits (Slack has 1GB limit, but we'll be more conservative)
            file_size = attachment.get("size", 0)
            max_size = 100 * 1024 * 1024  # 100MB limit
            
            if file_size > max_size:
                error_msg = f"Attachment '{attachment.get('filename', 'unknown')}' exceeds size limit ({file_size} bytes > {max_size} bytes)"
                logger.warning(error_msg)
                
                # Add system comment about size limit
                system_comment = create_system_comment(
                    f"Failed to sync attachment to Slack: {error_msg}"
                )
                self._add_system_comment_to_case(case_id, system_comment)
                return False

            # Download attachment content from AWS SIR
            attachment_content = self._download_sir_attachment(case_id, attachment)
            if not attachment_content:
                logger.error(f"Failed to download attachment content for case {case_id}")
                # Add system comment about download failure
                system_comment = create_system_comment(
                    f"Failed to download attachment '{attachment.get('filename', 'unknown')}' from AWS SIR"
                )
                self._add_system_comment_to_case(case_id, system_comment)
                return False

            # Map attachment to Slack file format
            attachment_with_content = attachment.copy()
            attachment_with_content["content"] = attachment_content
            slack_file = map_attachment_to_slack_file(attachment_with_content)
            
            # Upload file to Slack
            success = self.slack_client.upload_file(
                channel_id=slack_channel_id,
                file_content=attachment_content,
                filename=slack_file["filename"],
                title=slack_file.get("title"),
                initial_comment=slack_file.get("initial_comment")
            )

            if success:
                logger.info(f"Successfully synced attachment to Slack for case {case_id}")
                return True
            else:
                logger.error(f"Failed to upload attachment to Slack for case {case_id}")
                # Add system comment about upload failure
                system_comment = create_system_comment(
                    f"Failed to upload attachment '{attachment.get('filename', 'unknown')}' to Slack channel"
                )
                self._add_system_comment_to_case(case_id, system_comment)
                return False

        except Exception as e:
            logger.error(f"Error syncing attachment to Slack for case {case_id}: {str(e)}")
            # Add system comment about sync failure
            system_comment = create_system_comment(
                f"Failed to sync attachment to Slack",
                str(e)
            )
            self._add_system_comment_to_case(case_id, system_comment)
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

    def extract_case_details(self, ir_case: Dict[str, Any]) -> Tuple[Dict[str, Any], str, str]:
        """Extract case details from an IR case.

        Args:
            ir_case (Dict[str, Any]): IR case data

        Returns:
            Tuple[Dict[str, Any], str, str]: Tuple of (ir_case_detail, ir_event_type, ir_case_id)
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

        return ir_case_detail, ir_event_type, ir_case_id

    def process_case_event(self, ir_case: Dict[str, Any]) -> bool:
        """Process an AWS SIR case event and sync to Slack.

        Args:
            ir_case (Dict[str, Any]): IR case data

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Extract case details
            ir_case_detail, ir_event_type, ir_case_id = self.extract_case_details(ir_case)

            logger.info(f"Processing {ir_event_type} event for case {ir_case_id}")

            # Handle based on event type
            if ir_event_type == "CaseCreated":
                return self.slack_service.create_channel_for_case(ir_case_id, ir_case_detail)
            
            elif ir_event_type == "CaseUpdated":
                # Determine update type based on changed fields
                update_type = "general"
                if "caseStatus" in ir_case_detail:
                    update_type = "status"
                elif "title" in ir_case_detail:
                    update_type = "title"
                elif "description" in ir_case_detail:
                    update_type = "description"
                
                return self.slack_service.update_channel_for_case(
                    ir_case_id, ir_case_detail, update_type
                )
            
            elif ir_event_type == "CommentAdded":
                # Extract comment from case detail
                comments = ir_case_detail.get("caseComments", [])
                if comments:
                    # Get the latest comment (assuming it's the last one)
                    latest_comment = comments[-1]
                    return self.slack_service.sync_comment_to_slack(ir_case_id, latest_comment)
                else:
                    logger.warning(f"No comments found in CommentAdded event for case {ir_case_id}")
                    return True
            
            elif ir_event_type == "WatchersUpdated":
                watchers = ir_case_detail.get("watchers", [])
                return self.slack_service.sync_watchers_to_slack(ir_case_id, watchers)
            
            elif ir_event_type == "AttachmentAdded":
                # Extract attachment from case detail
                attachments = ir_case_detail.get("attachments", [])
                if attachments:
                    # Get the latest attachment (assuming it's the last one)
                    latest_attachment = attachments[-1]
                    return self.slack_service.sync_attachment_to_slack(ir_case_id, latest_attachment)
                else:
                    logger.warning(f"No attachments found in AttachmentAdded event for case {ir_case_id}")
                    return True
            
            else:
                logger.warning(f"Unhandled event type: {ir_event_type}")
                return True

        except Exception as e:
            logger.error(f"Error processing case event: {str(e)}")
            return False

    def process_slack_event(self, slack_event: Dict[str, Any]) -> bool:
        """Process a Slack event and sync to AWS SIR.

        Args:
            slack_event (Dict[str, Any]): Slack event data from EventBridge

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            detail_type = slack_event.get("detail-type", "")
            detail = slack_event.get("detail", {})

            logger.info(f"Processing Slack event: {detail_type}")

            if detail_type == "Message Added":
                return self._process_slack_message_event(detail)
            
            elif detail_type == "Channel Member Added":
                return self._process_member_joined_event(detail)
            
            elif detail_type == "Channel Member Removed":
                return self._process_member_left_event(detail)
            
            elif detail_type == "File Uploaded":
                return self._process_file_upload_event(detail)
            
            else:
                logger.warning(f"Unhandled Slack event type: {detail_type}")
                return True

        except Exception as e:
            logger.error(f"Error processing Slack event: {str(e)}")
            return False

    def _process_slack_message_event(self, detail: Dict[str, Any]) -> bool:
        """Process a Slack message event and sync to AWS SIR.

        Args:
            detail (Dict[str, Any]): Message event detail

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            case_id = detail.get("caseId")
            if not case_id:
                logger.error("No case ID found in Slack message event")
                return False

            # Skip messages that should not be synced
            message_text = detail.get("text", "")
            if not message_text.strip():
                logger.debug("Skipping empty message")
                return True

            # Skip messages with Slack system tag to prevent loops
            if SLACK_SYSTEM_COMMENT_TAG in message_text:
                logger.debug("Skipping message with Slack system tag")
                return True

            # Create message object for sync
            message = {
                "ts": detail.get("messageId", ""),
                "user": detail.get("userId", ""),
                "text": message_text,
                "thread_ts": detail.get("threadTs"),
                "userName": detail.get("userName", detail.get("userId", "Unknown User"))
            }

            # Check if message is already synced to avoid duplicates
            if self.slack_service._is_slack_message_synced(case_id, message):
                logger.debug(f"Skipping already synced Slack message for case {case_id}")
                return True

            # Convert Slack message to SIR comment format
            user_name = message.get("userName", message.get("user", "Unknown User"))
            sir_comment = map_slack_message_to_sir_comment(message, user_name)

            # Add comment to AWS SIR case
            try:
                security_incident_response_client.create_case_comment(
                    caseId=case_id,
                    body=sir_comment
                )
                
                # Track the synced message
                self.slack_service._track_slack_message_sync(case_id, message)
                logger.info(f"Synced Slack message to AWS SIR case {case_id}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to sync Slack message to AWS SIR: {str(e)}")
                return False

        except Exception as e:
            logger.error(f"Error processing Slack message event: {str(e)}")
            return False

    def _process_member_joined_event(self, detail: Dict[str, Any]) -> bool:
        """Process a member joined event and add system comment to AWS SIR.

        Args:
            detail (Dict[str, Any]): Member joined event detail

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            case_id = detail.get("caseId")
            user_name = detail.get("userName", detail.get("userId", "Unknown User"))
            timestamp = detail.get("timestamp", "")

            if not case_id:
                logger.error("No case ID found in member joined event")
                return False

            # Create system comment
            system_comment = create_system_comment(
                f"User {user_name} joined the Slack channel",
                f"Timestamp: {timestamp}"
            )

            # Add system comment to AWS SIR case
            return self.slack_service._add_system_comment_to_case(case_id, system_comment)

        except Exception as e:
            logger.error(f"Error processing member joined event: {str(e)}")
            return False

    def _process_member_left_event(self, detail: Dict[str, Any]) -> bool:
        """Process a member left event and add system comment to AWS SIR.

        Args:
            detail (Dict[str, Any]): Member left event detail

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            case_id = detail.get("caseId")
            user_name = detail.get("userName", detail.get("userId", "Unknown User"))
            timestamp = detail.get("timestamp", "")

            if not case_id:
                logger.error("No case ID found in member left event")
                return False

            # Create system comment
            system_comment = create_system_comment(
                f"User {user_name} left the Slack channel",
                f"Timestamp: {timestamp}"
            )

            # Add system comment to AWS SIR case
            return self.slack_service._add_system_comment_to_case(case_id, system_comment)

        except Exception as e:
            logger.error(f"Error processing member left event: {str(e)}")
            return False

    def _process_file_upload_event(self, detail: Dict[str, Any]) -> bool:
        """Process a file upload event and sync to AWS SIR.

        Args:
            detail (Dict[str, Any]): File upload event detail

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            case_id = detail.get("caseId")
            if not case_id:
                logger.error("No case ID found in file upload event")
                return False

            # Create attachment object for sync
            attachment = {
                "fileId": detail.get("fileId", ""),
                "filename": detail.get("filename", ""),
                "size": detail.get("fileSize", 0),
                "mimetype": detail.get("mimetype", ""),
                "url": detail.get("url", ""),
                "title": detail.get("title", ""),
                "initialComment": detail.get("initialComment", ""),
                "uploadedBy": detail.get("userName", detail.get("userId", "Unknown User")),
                "timestamp": detail.get("timestamp", "")
            }

            # Sync attachment to AWS SIR (this would need to be implemented)
            logger.info(f"File upload event processed for case {case_id}, filename: {attachment['filename']}")
            return True

        except Exception as e:
            logger.error(f"Error processing file upload event: {str(e)}")
            return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing AWS SIR events and Slack events.
    
    Args:
        event: EventBridge event containing AWS SIR case information or Slack event
        context: Lambda context object
        
    Returns:
        Dict containing status and response information
    """
    try:
        logger.info(f"Processing event: {json.dumps(event, default=str)}")
        
        event_source = event.get("source", "")
        incident_service = IncidentService()
        
        # Process based on event source
        if event_source == "security-ir":
            # Process AWS SIR events
            success = incident_service.process_case_event(event)
        elif event_source == "slack":
            # Process Slack events
            success = incident_service.process_slack_event(event)
        else:
            logger.info(f"Slack Client lambda will skip processing event from unknown source: {event_source}")
            return {
                "statusCode": 200,
                "body": json.dumps(f"Event skipped - unknown source: {event_source}")
            }
        
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
        
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
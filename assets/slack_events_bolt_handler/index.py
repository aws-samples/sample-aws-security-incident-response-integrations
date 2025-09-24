"""
Slack Events Bolt Handler Lambda function for AWS Security Incident Response integration.
This function uses Slack Bolt framework to handle all Slack events and route slash commands.
"""

import json
import logging
import os
import re
import boto3
import requests
import time
from typing import Dict, Any, Optional

from slack_bolt import App
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
from slack_sdk.errors import SlackApiError

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

# Initialize AWS clients
eventbridge_client = boto3.client("events")
dynamodb = boto3.resource("dynamodb")
ssm_client = boto3.client("ssm")
lambda_client = boto3.client("lambda")

# Environment variables
EVENT_BUS_NAME = os.environ.get("EVENT_BUS_NAME", "security-incident-event-bus")
INCIDENTS_TABLE_NAME = os.environ.get("INCIDENTS_TABLE_NAME")
EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "slack")
SLACK_COMMAND_HANDLER_FUNCTION = os.environ.get("SLACK_COMMAND_HANDLER_FUNCTION")

# Constants
SLACK_CHANNEL_PREFIX = "aws-security-incident-response-case-"
SLACK_SYSTEM_COMMENT_TAG = "[Slack Update]"
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB limit for AWS SIR attachments
SLACK_MAX_RETRIES = 5
SLACK_INITIAL_RETRY_DELAY = 1
SLACK_MAX_RETRY_DELAY = 60

# Initialize DynamoDB table
incidents_table = dynamodb.Table(INCIDENTS_TABLE_NAME) if INCIDENTS_TABLE_NAME else None


def get_ssm_parameter(parameter_name: str, with_decryption: bool = True) -> Optional[str]:
    """Get parameter from SSM Parameter Store.
    
    Args:
        parameter_name: Name of the SSM parameter
        with_decryption: Whether to decrypt the parameter
        
    Returns:
        Parameter value or None if not found
    """
    try:
        response = ssm_client.get_parameter(
            Name=parameter_name,
            WithDecryption=with_decryption
        )
        return response["Parameter"]["Value"]
    except Exception as e:
        logger.error(f"Error retrieving SSM parameter {parameter_name}: {str(e)}")
        return None


# Initialize Slack Bolt app
def create_slack_app() -> Optional[App]:
    """Create and configure Slack Bolt app.
    
    Returns:
        Configured Slack Bolt app or None if initialization fails
    """
    try:
        bot_token = get_ssm_parameter(
            os.environ.get("SLACK_BOT_TOKEN", "/SecurityIncidentResponse/slackBotToken")
        )
        signing_secret = get_ssm_parameter(
            os.environ.get("SLACK_SIGNING_SECRET", "/SecurityIncidentResponse/slackSigningSecret")
        )
        
        if not bot_token or not signing_secret:
            logger.error("Failed to retrieve Slack credentials from SSM")
            return None
            
        return App(
            token=bot_token,
            signing_secret=signing_secret,
            process_before_response=True
        )
    except Exception as e:
        logger.error(f"Error creating Slack app: {str(e)}")
        return None


app = create_slack_app()


def get_case_id_from_channel(channel_id: str) -> Optional[str]:
    """Extract case ID from channel mapping in DynamoDB.
    
    Args:
        channel_id: Slack channel ID
        
    Returns:
        Case ID if found, None otherwise
    """
    if not incidents_table:
        logger.error("Incidents table not configured")
        return None
        
    try:
        # Query DynamoDB to find case ID by slack channel ID
        response = incidents_table.scan(
            FilterExpression="slackChannelId = :channel_id",
            ExpressionAttributeValues={":channel_id": channel_id}
        )
        
        if response["Items"]:
            # Extract case ID from PK (format: Case#<case-id>)
            pk = response["Items"][0]["PK"]
            if pk.startswith("Case#"):
                return pk[5:]  # Remove "Case#" prefix
                
        return None
    except Exception as e:
        logger.error(f"Error querying case ID for channel {channel_id}: {str(e)}")
        return None


def get_channel_id_from_case(case_id: str) -> Optional[str]:
    """Get Slack channel ID from case ID.
    
    Args:
        case_id: AWS SIR case ID
        
    Returns:
        Slack channel ID if found, None otherwise
    """
    if not incidents_table:
        logger.error("Incidents table not configured")
        return None
        
    try:
        response = incidents_table.get_item(
            Key={"PK": f"Case#{case_id}", "SK": "latest"}
        )
        
        if "Item" in response:
            return response["Item"].get("slackChannelId")
            
        return None
    except Exception as e:
        logger.error(f"Error getting channel ID for case {case_id}: {str(e)}")
        return None


def download_slack_file(file_url: str, bot_token: str, max_size: int = MAX_FILE_SIZE_BYTES) -> Optional[bytes]:
    """Download a file from Slack with size validation and retry logic.
    
    Args:
        file_url: Slack file download URL
        bot_token: Slack bot token for authentication
        max_size: Maximum allowed file size in bytes
        
    Returns:
        File content as bytes or None if download fails
    """
    headers = {
        "Authorization": f"Bearer {bot_token}",
        "User-Agent": "AWS-Security-IR-Slack-Integration/1.0"
    }
    
    delay = SLACK_INITIAL_RETRY_DELAY
    
    for attempt in range(SLACK_MAX_RETRIES):
        try:
            # First, make a HEAD request to check file size
            head_response = requests.head(file_url, headers=headers, timeout=30)
            head_response.raise_for_status()
            
            content_length = head_response.headers.get('content-length')
            if content_length:
                file_size = int(content_length)
                if file_size > max_size:
                    logger.error(f"File size {file_size} bytes exceeds maximum allowed size {max_size} bytes")
                    return None
                    
            # Download the file
            response = requests.get(file_url, headers=headers, timeout=60, stream=True)
            response.raise_for_status()
            
            # Download with size checking
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    content += chunk
                    if len(content) > max_size:
                        logger.error(f"File size during download exceeds maximum allowed size {max_size} bytes")
                        return None
                        
            logger.info(f"Successfully downloaded file of size {len(content)} bytes")
            return content
            
        except requests.exceptions.RequestException as e:
            if attempt < SLACK_MAX_RETRIES - 1:
                logger.warning(f"File download attempt {attempt + 1} failed: {str(e)}, retrying in {delay}s")
                time.sleep(delay)
                delay = min(delay * 2, SLACK_MAX_RETRY_DELAY)
            else:
                logger.error(f"File download failed after {SLACK_MAX_RETRIES} attempts: {str(e)}")
                return None
        except Exception as e:
            logger.error(f"Unexpected error downloading file: {str(e)}")
            return None
            
    return None


def publish_event_to_eventbridge(event_type: str, detail: Dict[str, Any]) -> bool:
    """Publish event to EventBridge.
    
    Args:
        event_type: Type of event
        detail: Event detail data
        
    Returns:
        True if successful, False otherwise
    """
    try:
        eventbridge_client.put_events(
            Entries=[
                {
                    "Source": EVENT_SOURCE,
                    "DetailType": event_type,
                    "Detail": json.dumps(detail),
                    "EventBusName": EVENT_BUS_NAME
                }
            ]
        )
        logger.info(f"Published {event_type} event to EventBridge")
        return True
    except Exception as e:
        logger.error(f"Error publishing event to EventBridge: {str(e)}")
        return False


def is_incident_channel(channel_name: str) -> bool:
    """Check if channel is an incident response channel.
    
    Args:
        channel_name: Slack channel name
        
    Returns:
        True if incident channel, False otherwise
    """
    return channel_name.startswith(SLACK_CHANNEL_PREFIX)


def invoke_command_handler(command_payload: Dict[str, Any]) -> bool:
    """Invoke the Slack Command Handler Lambda function.
    
    Args:
        command_payload: Slack command payload
        
    Returns:
        True if successful, False otherwise
    """
    if not SLACK_COMMAND_HANDLER_FUNCTION:
        logger.error("Slack Command Handler function not configured")
        return False
        
    try:
        lambda_client.invoke(
            FunctionName=SLACK_COMMAND_HANDLER_FUNCTION,
            InvocationType="Event",  # Async invocation
            Payload=json.dumps(command_payload)
        )
        logger.info("Invoked Slack Command Handler")
        return True
    except Exception as e:
        logger.error(f"Error invoking command handler: {str(e)}")
        return False


if app:
    # Message handler for incident channels
    @app.message(re.compile(rf"{SLACK_CHANNEL_PREFIX}.*"))
    def handle_incident_message(message, say, client, logger):
        """Handle messages in incident channels.
        
        Args:
            message: Slack message event
            say: Function to send messages
            client: Slack client
            logger: Logger instance
        """
        try:
            # Skip bot messages and system notifications
            if message.get("subtype") in ["bot_message", "app_mention"] or not message.get("user"):
                logger.info("Skipping bot message or system notification")
                return
            
            # Skip messages with Slack Update tag to prevent loops
            if SLACK_SYSTEM_COMMENT_TAG in message.get("text", ""):
                logger.info("Skipping message with Slack Update tag")
                return
            
            channel_id = message["channel"]
            case_id = get_case_id_from_channel(channel_id)
            
            if not case_id:
                logger.warning(f"Could not find case ID for channel {channel_id}")
                return
            
            # Get user info for attribution
            user_info = None
            try:
                user_response = client.users_info(user=message["user"])
                user_info = user_response["user"]
            except SlackApiError as e:
                logger.warning(f"Could not get user info: {e}")
            
            # Publish message sync event to EventBridge
            event_detail = {
                "caseId": case_id,
                "channelId": channel_id,
                "messageId": message["ts"],
                "userId": message["user"],
                "userName": user_info.get("real_name") if user_info else message["user"],
                "text": message["text"],
                "timestamp": message["ts"],
                "threadTs": message.get("thread_ts"),
                "messageType": "user_message"
            }
            
            publish_event_to_eventbridge("Message Added", event_detail)
            logger.info(f"Processed message from user {message['user']} in case {case_id}")
            
        except Exception as e:
            logger.error(f"Error handling incident message: {str(e)}")
    
    
    # Channel member joined event
    @app.event("member_joined_channel")
    def handle_member_joined(event, client, logger):
        """Handle member joined channel events.
        
        Args:
            event: Slack event data
            client: Slack client
            logger: Logger instance
        """
        try:
            channel_id = event["channel"]
            user_id = event["user"]
            
            # Get channel info to check if it's an incident channel
            try:
                channel_response = client.conversations_info(channel=channel_id)
                channel_name = channel_response["channel"]["name"]
            except SlackApiError as e:
                logger.warning(f"Could not get channel info: {e}")
                return
            
            if not is_incident_channel(channel_name):
                logger.info(f"Ignoring member joined event for non-incident channel: {channel_name}")
                return
            
            case_id = get_case_id_from_channel(channel_id)
            if not case_id:
                logger.warning(f"Could not find case ID for channel {channel_id}")
                return
            
            # Get user info
            user_info = None
            try:
                user_response = client.users_info(user=user_id)
                user_info = user_response["user"]
            except SlackApiError as e:
                logger.warning(f"Could not get user info: {e}")
            
            # Publish member joined event to EventBridge
            event_detail = {
                "caseId": case_id,
                "channelId": channel_id,
                "userId": user_id,
                "userName": user_info.get("real_name") if user_info else user_id,
                "eventType": "member_joined",
                "timestamp": str(event.get("event_ts", ""))
            }
            
            publish_event_to_eventbridge("Channel Member Added", event_detail)
            logger.info(f"Processed member joined event for user {user_id} in case {case_id}")
            
        except Exception as e:
            logger.error(f"Error handling member joined event: {str(e)}")
    
    
    # Channel member left event
    @app.event("member_left_channel")
    def handle_member_left(event, client, logger):
        """Handle member left channel events.
        
        Args:
            event: Slack event data
            client: Slack client
            logger: Logger instance
        """
        try:
            channel_id = event["channel"]
            user_id = event["user"]
            
            # Get channel info to check if it's an incident channel
            try:
                channel_response = client.conversations_info(channel=channel_id)
                channel_name = channel_response["channel"]["name"]
            except SlackApiError as e:
                logger.warning(f"Could not get channel info: {e}")
                return
            
            if not is_incident_channel(channel_name):
                logger.info(f"Ignoring member left event for non-incident channel: {channel_name}")
                return
            
            case_id = get_case_id_from_channel(channel_id)
            if not case_id:
                logger.warning(f"Could not find case ID for channel {channel_id}")
                return
            
            # Get user info
            user_info = None
            try:
                user_response = client.users_info(user=user_id)
                user_info = user_response["user"]
            except SlackApiError as e:
                logger.warning(f"Could not get user info: {e}")
            
            # Publish member left event to EventBridge
            event_detail = {
                "caseId": case_id,
                "channelId": channel_id,
                "userId": user_id,
                "userName": user_info.get("real_name") if user_info else user_id,
                "eventType": "member_left",
                "timestamp": str(event.get("event_ts", ""))
            }
            
            publish_event_to_eventbridge("Channel Member Removed", event_detail)
            logger.info(f"Processed member left event for user {user_id} in case {case_id}")
            
        except Exception as e:
            logger.error(f"Error handling member left event: {str(e)}")
    
    
    # File upload handler
    @app.event("file_shared")
    def handle_file_upload(event, client, logger):
        """Handle file upload events.
        
        Args:
            event: Slack event data
            client: Slack client
            logger: Logger instance
        """
        try:
            file_id = event["file_id"]
            channel_id = event["channel_id"]
            user_id = event["user_id"]
            
            # Get channel info to check if it's an incident channel
            try:
                channel_response = client.conversations_info(channel=channel_id)
                channel_name = channel_response["channel"]["name"]
            except SlackApiError as e:
                logger.warning(f"Could not get channel info: {e}")
                return
            
            if not is_incident_channel(channel_name):
                logger.info(f"Ignoring file upload for non-incident channel: {channel_name}")
                return
            
            case_id = get_case_id_from_channel(channel_id)
            if not case_id:
                logger.warning(f"Could not find case ID for channel {channel_id}")
                return
            
            # Get file info
            try:
                file_response = client.files_info(file=file_id)
                file_info = file_response["file"]
            except SlackApiError as e:
                logger.error(f"Could not get file info for {file_id}: {e}")
                # Publish error event for failed file info retrieval
                error_detail = {
                    "caseId": case_id,
                    "channelId": channel_id,
                    "fileId": file_id,
                    "userId": user_id,
                    "error": f"Failed to retrieve file information: {str(e)}",
                    "errorType": "file_info_retrieval_failed"
                }
                publish_event_to_eventbridge("File Upload Error", error_detail)
                return
            
            # Validate file size before downloading
            file_size = file_info.get("size", 0)
            if file_size > MAX_FILE_SIZE_BYTES:
                logger.error(f"File {file_id} size {file_size} bytes exceeds maximum allowed size {MAX_FILE_SIZE_BYTES} bytes")
                # Publish size limit error event
                error_detail = {
                    "caseId": case_id,
                    "channelId": channel_id,
                    "fileId": file_id,
                    "userId": user_id,
                    "filename": file_info.get("name"),
                    "fileSize": file_size,
                    "error": f"File size {file_size} bytes exceeds platform limit of {MAX_FILE_SIZE_BYTES} bytes",
                    "errorType": "file_size_exceeded"
                }
                publish_event_to_eventbridge("File Upload Error", error_detail)
                return
            
            # Get user info
            user_info = None
            try:
                user_response = client.users_info(user=user_id)
                user_info = user_response["user"]
            except SlackApiError as e:
                logger.warning(f"Could not get user info for {user_id}: {e}")
            
            # Get bot token for file download
            bot_token = get_ssm_parameter(
                os.environ.get("SLACK_BOT_TOKEN", "/SecurityIncidentResponse/slackBotToken")
            )
            
            if not bot_token:
                logger.error("Could not retrieve bot token for file download")
                error_detail = {
                    "caseId": case_id,
                    "channelId": channel_id,
                    "fileId": file_id,
                    "userId": user_id,
                    "filename": file_info.get("name"),
                    "error": "Could not retrieve bot token for file download",
                    "errorType": "authentication_failed"
                }
                publish_event_to_eventbridge("File Upload Error", error_detail)
                return
            
            # Download file content
            file_url = file_info.get("url_private_download")
            if not file_url:
                logger.error(f"No download URL available for file {file_id}")
                error_detail = {
                    "caseId": case_id,
                    "channelId": channel_id,
                    "fileId": file_id,
                    "userId": user_id,
                    "filename": file_info.get("name"),
                    "error": "No download URL available for file",
                    "errorType": "download_url_missing"
                }
                publish_event_to_eventbridge("File Upload Error", error_detail)
                return
            
            logger.info(f"Downloading file {file_id} ({file_info.get('name')}) of size {file_size} bytes")
            file_content = download_slack_file(file_url, bot_token, MAX_FILE_SIZE_BYTES)
            
            if file_content is None:
                logger.error(f"Failed to download file {file_id}")
                error_detail = {
                    "caseId": case_id,
                    "channelId": channel_id,
                    "fileId": file_id,
                    "userId": user_id,
                    "filename": file_info.get("name"),
                    "fileSize": file_size,
                    "error": "Failed to download file content from Slack",
                    "errorType": "download_failed"
                }
                publish_event_to_eventbridge("File Upload Error", error_detail)
                return
            
            # Prepare event detail with file content
            event_detail = {
                "caseId": case_id,
                "channelId": channel_id,
                "fileId": file_id,
                "userId": user_id,
                "userName": user_info.get("real_name") if user_info else user_id,
                "filename": file_info.get("name"),
                "fileSize": len(file_content),
                "mimetype": file_info.get("mimetype", "application/octet-stream"),
                "title": file_info.get("title"),
                "initialComment": file_info.get("initial_comment", {}).get("comment"),
                "timestamp": str(file_info.get("timestamp", "")),
                "fileContent": file_content.hex(),  # Convert bytes to hex string for JSON serialization
                "downloadUrl": file_url
            }
            
            # Publish successful file upload event to EventBridge
            success = publish_event_to_eventbridge("File Uploaded", event_detail)
            
            if success:
                logger.info(f"Successfully processed file upload {file_id} ({file_info.get('name')}) from user {user_id} in case {case_id}")
            else:
                logger.error(f"Failed to publish file upload event for {file_id}")
                # Note: We don't retry here as publish_event_to_eventbridge should handle its own retries
            
        except Exception as e:
            logger.error(f"Unexpected error handling file upload event: {str(e)}")
            # Try to publish error event if we have enough context
            try:
                if 'case_id' in locals() and 'channel_id' in locals() and 'file_id' in locals():
                    error_detail = {
                        "caseId": case_id,
                        "channelId": channel_id,
                        "fileId": file_id,
                        "userId": user_id if 'user_id' in locals() else "unknown",
                        "error": f"Unexpected error: {str(e)}",
                        "errorType": "unexpected_error"
                    }
                    publish_event_to_eventbridge("File Upload Error", error_detail)
            except Exception as e:
                logger.error(f"Failed to publish error event for file upload: {str(e)}")
    
    
    # Slash command router
    @app.command("/security-ir")
    def handle_security_ir_command(ack, command, client, logger):
        """Handle /security-ir slash commands.
        
        Args:
            ack: Function to acknowledge the command
            command: Slack command data
            client: Slack client
            logger: Logger instance
        """
        try:
            # Acknowledge the command immediately (required within 3 seconds)
            ack()
            
            # Validate that command is in an incident channel
            channel_id = command["channel_id"]
            
            # Get channel info
            try:
                channel_response = client.conversations_info(channel=channel_id)
                channel_name = channel_response["channel"]["name"]
            except SlackApiError as e:
                logger.error(f"Could not get channel info: {e}")
                client.chat_postEphemeral(
                    channel=channel_id,
                    user=command["user_id"],
                    text="❌ Error: Could not verify channel information."
                )
                return
            
            if not is_incident_channel(channel_name):
                client.chat_postEphemeral(
                    channel=channel_id,
                    user=command["user_id"],
                    text="❌ Error: Security IR commands can only be used in incident channels."
                )
                return
            
            case_id = get_case_id_from_channel(channel_id)
            if not case_id:
                client.chat_postEphemeral(
                    channel=channel_id,
                    user=command["user_id"],
                    text="❌ Error: Could not find associated case for this channel."
                )
                return
            
            # Prepare command payload for the command handler
            command_payload = {
                "command": command["command"],
                "text": command["text"],
                "user_id": command["user_id"],
                "user_name": command["user_name"],
                "channel_id": channel_id,
                "channel_name": channel_name,
                "team_id": command["team_id"],
                "response_url": command["response_url"],
                "trigger_id": command["trigger_id"],
                "case_id": case_id
            }
            
            # Route to dedicated command handler
            if invoke_command_handler(command_payload):
                logger.info(f"Routed command '{command['text']}' to handler for case {case_id}")
            else:
                client.chat_postEphemeral(
                    channel=channel_id,
                    user=command["user_id"],
                    text="❌ Error: Could not process command. Please try again later."
                )
            
        except Exception as e:
            logger.error(f"Error handling slash command: {str(e)}")
            try:
                client.chat_postEphemeral(
                    channel=command["channel_id"],
                    user=command["user_id"],
                    text="❌ Error: An unexpected error occurred while processing your command."
                )
            except Exception as e:
                logger.error(f"Failed to send error message to Slack: {str(e)}")
    
    
    # URL verification handler (required for Slack Events API)
    @app.event("url_verification")
    def handle_url_verification(event, logger):
        """Handle URL verification for Slack Events API setup.
        
        Args:
            event: Slack event data
            logger: Logger instance
        """
        logger.info("Handling URL verification")
        return {"challenge": event["challenge"]}


# Lambda request handler
slack_handler = SlackRequestHandler(app=app) if app else None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing Slack events using Bolt framework.
    
    Args:
        event: API Gateway event containing Slack webhook payload
        context: Lambda context object
        
    Returns:
        Dict containing status and response information
    """
    try:
        if not slack_handler:
            logger.error("Slack handler not initialized - check credentials")
            return {
                "statusCode": 500,
                "body": json.dumps({"error": "Slack handler not initialized"})
            }
        
        logger.info("Processing Slack event with Bolt framework")
        
        # Use Slack Bolt framework to handle the request
        return slack_handler.handle(event, context)
        
    except Exception as e:
        logger.error(f"Error processing Slack event: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }
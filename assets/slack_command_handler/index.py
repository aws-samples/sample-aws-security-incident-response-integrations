"""
Slack Command Handler Lambda function for AWS Security Incident Response integration.
This function processes Slack slash commands for incident management.
"""

import json
import logging
import os
import re
import time
from typing import Dict, Any, Optional, Tuple
import requests

import boto3
from botocore.exceptions import ClientError

try:
    # Lambda layer import
    from permission_models import PermissionConfig, PermissionMode, PermissionCheckResult
except ImportError:
    # Local development import
    from ..domain.python.permission_models import PermissionConfig, PermissionMode, PermissionCheckResult

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

# Initialize AWS clients
security_incident_response_client = boto3.client("security-ir")
dynamodb = boto3.resource("dynamodb")
ssm_client = boto3.client("ssm")

# Environment variables
INCIDENTS_TABLE_NAME = os.environ.get("INCIDENTS_TABLE_NAME")
SLACK_BOT_TOKEN_PARAM = os.environ.get("SLACK_BOT_TOKEN", "/SecurityIncidentResponse/slackBotToken")
SLACK_PERMISSION_CONFIG_PARAM = os.environ.get("SLACK_PERMISSION_CONFIG", "/SecurityIncidentResponse/slackPermissionConfig")

# Initialize DynamoDB table
incidents_table = dynamodb.Table(INCIDENTS_TABLE_NAME) if INCIDENTS_TABLE_NAME else None

# Valid AWS SIR case statuses
VALID_STATUSES = [
    "Submitted",
    "Acknowledged", 
    "Detection and Analysis",
    "Containment, Eradication and Recovery",
    "Post-incident Activities",
    "Resolved"
]

# Command help text
COMMAND_HELP = """
*Available /security-ir commands:*

• `/security-ir status` - Get current case status and details
• `/security-ir incident-details` - Get incident details
• `/security-ir update-status <status>` - Update case status
• `/security-ir update-description <description>` - Update case description
• `/security-ir update-title <title>` - Update case title
• `/security-ir close` - Close the case

*Valid statuses:*
• Submitted
• Acknowledged
• Detection and Analysis
• Containment, Eradication and Recovery
• Post-incident Activities
• Resolved
"""


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
        logger.error(f"Error retrieving SSM parameter: {str(e)}")
        return None


def get_case_id_from_channel(channel_id: str) -> Optional[str]:
    """Get case ID from Slack channel ID.
    
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


def get_case_details(case_id: str) -> Optional[Dict[str, Any]]:
    """Get case details from AWS Security IR.
    
    Args:
        case_id: AWS SIR case ID
        
    Returns:
        Case details or None if retrieval fails
    """
    try:
        response = security_incident_response_client.get_case(caseId=case_id)
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"Error retrieving case {case_id}: {error_code}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error retrieving case {case_id}: {str(e)}")
        return None


def send_slack_response(response_url: str, text: str, response_type: str = "ephemeral") -> bool:
    """Send a response to Slack using the response URL.
    
    Args:
        response_url: Slack response URL
        text: Message text
        response_type: "ephemeral" (only visible to user) or "in_channel" (visible to all)
        
    Returns:
        True if successful, False otherwise
    """
    try:
        payload = {
            "response_type": response_type,
            "text": text
        }
        
        response = requests.post(response_url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Error sending Slack response: {str(e)}")
        return False


def parse_command(command_text: str) -> Tuple[str, str]:
    """Parse command text to extract subcommand and arguments.
    
    Args:
        command_text: Full command text
        
    Returns:
        Tuple of (subcommand, arguments)
    """
    parts = command_text.strip().split(" ", 1)
    subcommand = parts[0].lower() if parts else ""
    args = parts[1].strip() if len(parts) > 1 else ""
    return subcommand, args


def get_permission_config() -> PermissionConfig:
    """Get permission configuration from SSM Parameter Store.
    
    Returns:
        PermissionConfig instance with current configuration
    """
    try:
        # Try to get permission config from SSM
        config_json = get_ssm_parameter(SLACK_PERMISSION_CONFIG_PARAM, with_decryption=False)
        
        if config_json:
            config_dict = json.loads(config_json)
            return PermissionConfig.from_dict(config_dict)
        else:
            # Default to allow-all mode if parameter doesn't exist
            logger.info("Permission config not found in SSM, using default allow-all mode")
            return PermissionConfig(permission_mode=PermissionMode.ALLOW_ALL)
            
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing permission config JSON: {str(e)}")
        return PermissionConfig(permission_mode=PermissionMode.ALLOW_ALL)
    except Exception as e:
        logger.error(f"Error retrieving permission config: {str(e)}")
        return PermissionConfig(permission_mode=PermissionMode.ALLOW_ALL)


def check_watcher_based_permission(slack_user_id: str, case_id: str, config: PermissionConfig) -> PermissionCheckResult:
    """Check if user has permission based on case watcher list.
    
    Args:
        slack_user_id: Slack user ID
        case_id: AWS SIR case ID
        config: Permission configuration
        
    Returns:
        PermissionCheckResult with validation result
    """
    try:
        # Get AWS identity for Slack user
        aws_identity = config.get_aws_identity(slack_user_id)
        if not aws_identity:
            return PermissionCheckResult(
                allowed=False,
                reason=f"Slack user {slack_user_id} is not mapped to an AWS identity",
                user_id=slack_user_id,
                case_id=case_id,
                command="unknown"
            )
        
        # Get case details to check watchers
        case_details = get_case_details(case_id)
        if not case_details:
            return PermissionCheckResult(
                allowed=False,
                reason=f"Could not retrieve case details for {case_id}",
                user_id=slack_user_id,
                case_id=case_id,
                command="unknown"
            )
        
        # Check if user is in watchers list
        watchers = case_details.get("watchers", [])
        for watcher in watchers:
            watcher_arn = watcher.get("principal", {}).get("arn", "") if isinstance(watcher, dict) else str(watcher)
            if aws_identity in watcher_arn or watcher_arn in aws_identity:
                return PermissionCheckResult(
                    allowed=True,
                    reason=f"User is a case watcher (AWS identity: {aws_identity})",
                    user_id=slack_user_id,
                    case_id=case_id,
                    command="unknown"
                )
        
        return PermissionCheckResult(
            allowed=False,
            reason=f"User is not a case watcher (AWS identity: {aws_identity})",
            user_id=slack_user_id,
            case_id=case_id,
            command="unknown"
        )
        
    except Exception as e:
        logger.error(f"Error checking watcher-based permission: {str(e)}")
        return PermissionCheckResult(
            allowed=False,
            reason=f"Error during permission check: {str(e)}",
            user_id=slack_user_id,
            case_id=case_id,
            command="unknown"
        )


def validate_user_permissions(user_id: str, case_id: str, command: str = "unknown") -> bool:
    """Validate that user has permissions to manage the case.
    
    This function implements a flexible permission system that supports:
    1. Allow-all mode (backward compatibility)
    2. Watcher-based validation (user must be a case watcher)
    3. User-mapping mode (explicit Slack-to-AWS user mapping)
    
    Args:
        user_id: Slack user ID
        case_id: AWS SIR case ID
        command: Command being executed
        
    Returns:
        True if user has permissions, False otherwise
    """
    try:
        # Get permission configuration
        config = get_permission_config()
        
        # Check if user is an admin (always allowed)
        if config.is_admin_user(user_id):
            logger.info(f"Permission ALLOWED for admin user {user_id} on case {case_id} (command: {command})")
            return True
        
        # Handle different permission modes
        if config.permission_mode == PermissionMode.ALLOW_ALL:
            logger.info(f"Permission ALLOWED for user {user_id} on case {case_id} (mode: allow-all, command: {command})")
            return True
        
        elif config.permission_mode == PermissionMode.WATCHER_BASED:
            # For read-only commands, allow all users
            if config.is_read_only_command(command):
                logger.info(f"Permission ALLOWED for user {user_id} on case {case_id} (read-only command: {command})")
                return True
            
            # Check watcher-based permissions
            result = check_watcher_based_permission(user_id, case_id, config)
            result.command = command
            logger.info(str(result))
            return result.allowed
        
        elif config.permission_mode == PermissionMode.USER_MAPPING:
            # Check if user has AWS identity mapping
            aws_identity = config.get_aws_identity(user_id)
            if aws_identity:
                logger.info(f"Permission ALLOWED for user {user_id} on case {case_id} (mapped to: {aws_identity}, command: {command})")
                return True
            else:
                logger.warning(f"Permission DENIED for user {user_id} on case {case_id} (no AWS identity mapping, command: {command})")
                return False
        
        else:
            # Unknown mode, default to deny
            logger.warning(f"Permission DENIED for user {user_id} on case {case_id} (unknown mode: {config.permission_mode}, command: {command})")
            return False
            
    except Exception as e:
        logger.error(f"Error validating permissions for user {user_id} on case {case_id}: {str(e)}")
        # Fail closed - deny access on error
        return False


def handle_status_command(case_id: str, response_url: str) -> bool:
    """Handle the status command.
    
    Args:
        case_id: AWS SIR case ID
        response_url: Slack response URL
        
    Returns:
        True if successful, False otherwise
    """
    try:
        case_details = get_case_details(case_id)
        if not case_details:
            send_slack_response(response_url, "❌ Error: Could not retrieve case details.")
            return False
        
        status = case_details.get("caseStatus", "N/A")
        response_text = f"*Case {case_id} Status:* {status}"
        
        send_slack_response(response_url, response_text)
        return True
        
    except Exception as e:
        logger.error(f"Error handling status command: {str(e)}")
        send_slack_response(response_url, f"❌ Error: {str(e)}")
        return False


def handle_incident_details_command(case_id: str, response_url: str) -> bool:
    """Handle the incident-details command.
    
    Args:
        case_id: AWS SIR case ID
        response_url: Slack response URL
        
    Returns:
        True if successful, False otherwise
    """
    try:
        case_details = get_case_details(case_id)
        if not case_details:
            send_slack_response(response_url, "❌ Error: Could not retrieve case details.")
            return False
        
        # Get case details
        title = case_details.get("title", "N/A")
        status = case_details.get("caseStatus", "N/A")
        severity = case_details.get("severity", "N/A")
        created_date = case_details.get("createdDate", "N/A")
        
        # Count watchers and comments
        watchers = case_details.get("watchers", [])
        watcher_count = len(watchers) if watchers else 0
        
        # Get comment count from DynamoDB
        comment_count = 0
        try:
            if incidents_table:
                db_response = incidents_table.get_item(
                    Key={"PK": f"Case#{case_id}", "SK": "latest"}
                )
                if "Item" in db_response:
                    comments = db_response["Item"].get("slackChannelCaseComments", [])
                    comment_count = len(comments) if comments else 0
        except Exception as e:
            logger.warning(f"Could not get comment count: {str(e)}")
        
        # Get investigations for this case
        investigations_text = ""
        try:
            investigations_response = security_incident_response_client.list_investigations(
                caseId=case_id
            )
            investigations = investigations_response.get("investigations", [])
            
            if investigations:
                investigations_text = f"\n*Investigations:* {len(investigations)}"
                for i, investigation in enumerate(investigations[:3], 1):  # Show first 3
                    inv_id = investigation.get("investigationId", "N/A")
                    inv_status = investigation.get("status", "N/A")
                    investigations_text += f"\n  {i}. {inv_id} - {inv_status}"
                if len(investigations) > 3:
                    investigations_text += f"\n  ... and {len(investigations) - 3} more"
            else:
                investigations_text = "\n*Investigations:* None"
        except Exception as e:
            logger.warning(f"Could not get investigations: {str(e)}")
            investigations_text = "\n*Investigations:* Unable to retrieve"
        
        response_text = f"""*Incident Details for {case_id}*

*Title:* {title}
*Current Status:* {status}
*Severity:* {severity}
*Created:* {created_date}
*Watchers:* {watcher_count}
*Comments:* {comment_count}
*Investigation details:* {investigations_text}

This case is currently in *{status}* status. Use `/security-ir status` for full details.
"""
        
        send_slack_response(response_url, response_text)
        return True
        
    except Exception as e:
        logger.error(f"Error handling incident-details command: {str(e)}")
        send_slack_response(response_url, f"❌ Error: {str(e)}")
        return False


def handle_update_status_command(case_id: str, new_status: str, response_url: str) -> bool:
    """Handle the update-status command.
    
    Args:
        case_id: AWS SIR case ID
        new_status: New status value
        response_url: Slack response URL
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not new_status:
            send_slack_response(response_url, f"❌ Error: Status value is required.\n\n{COMMAND_HELP}")
            return False
        
        # Validate status value
        if new_status not in VALID_STATUSES:
            send_slack_response(
                response_url, 
                f"❌ Error: Invalid status '{new_status}'.\n\nValid statuses are:\n" + 
                "\n".join(f"• {s}" for s in VALID_STATUSES)
            )
            return False
        
        # Update case status
        security_incident_response_client.update_case_status(
            caseId=case_id,
            caseStatus=new_status
        )
        
        send_slack_response(
            response_url,
            f"ℹ️ Case status updated to *{new_status}*",
            response_type="in_channel"
        )
        return True
        
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"Error updating case status: {error_code}")
        send_slack_response(response_url, f"❌ Error updating status: {error_code}")
        return False
    except Exception as e:
        logger.error(f"Error handling update-status command: {str(e)}")
        send_slack_response(response_url, f"❌ Error: {str(e)}")
        return False


def mark_slack_update(case_id: str) -> None:
    """Mark a case update as originating from Slack to prevent notification loops.
    
    Args:
        case_id: AWS SIR case ID
    """
    if not incidents_table:
        return
    
    try:
        incidents_table.put_item(
            Item={
                "PK": f"Case#{case_id}",
                "SK": "slack_update_flag",
                "timestamp": int(time.time()),
                "ttl": int(time.time()) + 300  # Expire after 5 minutes
            }
        )
    except Exception as e:
        logger.warning(f"Could not set Slack update flag for case {case_id}: {str(e)}")


def handle_update_description_command(case_id: str, new_description: str, response_url: str) -> bool:
    """Handle the update-description command.
    
    Args:
        case_id: AWS SIR case ID
        new_description: New description text
        response_url: Slack response URL
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not new_description:
            send_slack_response(response_url, "❌ Error: Description text is required.")
            return False
        
        # Mark this as a Slack update to prevent notification loops
        mark_slack_update(case_id)
        
        # Update case description
        security_incident_response_client.update_case(
            caseId=case_id,
            description=new_description
        )
        
        send_slack_response(
            response_url,
            f"ℹ️ Case description updated to: *{new_description}*",
            response_type="in_channel"
        )
        return True
        
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"Error updating case description: {error_code}")
        send_slack_response(response_url, f"❌ Error updating description: {error_code}")
        return False
    except Exception as e:
        logger.error(f"Error handling update-description command: {str(e)}")
        send_slack_response(response_url, f"❌ Error: {str(e)}")
        return False


def handle_update_title_command(case_id: str, new_title: str, response_url: str) -> bool:
    """Handle the update-title command.
    
    Args:
        case_id: AWS SIR case ID
        new_title: New title text
        response_url: Slack response URL
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not new_title:
            send_slack_response(response_url, "❌ Error: Title text is required.")
            return False
        
        # Mark this as a Slack update to prevent notification loops
        mark_slack_update(case_id)
        
        # Update case title
        security_incident_response_client.update_case(
            caseId=case_id,
            title=new_title
        )
        
        send_slack_response(
            response_url,
            f"ℹ️ Case title updated to: *{new_title}*",
            response_type="in_channel"
        )
        return True
        
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"Error updating case title: {error_code}")
        send_slack_response(response_url, f"❌ Error updating title: {error_code}")
        return False
    except Exception as e:
        logger.error(f"Error handling update-title command: {str(e)}")
        send_slack_response(response_url, f"❌ Error: {str(e)}")
        return False


def handle_close_command(case_id: str, response_url: str) -> bool:
    """Handle the close command.
    
    Args:
        case_id: AWS SIR case ID
        response_url: Slack response URL
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Close the case using the close_case API
        security_incident_response_client.close_case(
            caseId=case_id
        )
        
        send_slack_response(
            response_url,
            f"✅ Case {case_id} has been closed successfully",
            response_type="in_channel"
        )
        return True
        
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        logger.error(f"Error closing case: {error_code}")
        send_slack_response(response_url, f"❌ Error closing case: {error_code}")
        return False
    except Exception as e:
        logger.error(f"Error handling close command: {str(e)}")
        send_slack_response(response_url, f"❌ Error: {str(e)}")
        return False


def process_command(command_payload: Dict[str, Any]) -> bool:
    """Process a Slack command.
    
    Args:
        command_payload: Command payload from Slack Events Bolt Handler
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Extract command details
        subcommand = command_payload.get("command", "")
        args = command_payload.get("args", "")
        user_id = command_payload.get("user_id")
        channel_id = command_payload.get("channel_id")
        response_url = command_payload.get("response_url")
        case_id = command_payload.get("case_id")
        
        logger.info(f"Processing command payload - subcommand: '{subcommand}', args: '{args}', case_id: '{case_id}', user_id: '{user_id}'")
        
        if not response_url:
            logger.error("No response URL provided in command payload")
            return False
        
        if not case_id:
            logger.error("No case ID provided in command payload")
            send_slack_response(response_url, "❌ Error: Could not determine case ID for this channel.")
            return False
        
        if not user_id:
            logger.error("No user ID provided in command payload")
            send_slack_response(response_url, "❌ Error: Could not determine user for this command.")
            return False
        
        logger.info(f"Processing command '{subcommand}' for case {case_id} from user {user_id}")
        
        # Validate user permissions
<<<<<<< HEAD
        if not validate_user_permissions(user_id, case_id, subcommand):
            send_slack_response(response_url, "❌ Error: You do not have permission to execute this command.")
=======
        if not validate_user_permissions(user_id, case_id):
            logger.warning(f"User {user_id} does not have permission to manage case {case_id}")
            send_slack_response(response_url, "❌ Error: You do not have permission to manage this case.")
>>>>>>> upstream/v4/slack-integration
            return False
        
        # Route to appropriate handler
        if subcommand == "status":
            logger.info(f"Routing to status handler for case {case_id}")
            return handle_status_command(case_id, response_url)
        
        elif subcommand == "incident-details":
            logger.info(f"Routing to incident-details handler for case {case_id}")
            return handle_incident_details_command(case_id, response_url)
        
        elif subcommand == "update-status":
            logger.info(f"Routing to update-status handler for case {case_id} with args: '{args}'")
            return handle_update_status_command(case_id, args, response_url)
        
        elif subcommand == "update-description":
            logger.info(f"Routing to update-description handler for case {case_id}")
            return handle_update_description_command(case_id, args, response_url)
        
        elif subcommand == "update-title":
            logger.info(f"Routing to update-title handler for case {case_id}")
            return handle_update_title_command(case_id, args, response_url)
        
        elif subcommand == "close":
            logger.info(f"Routing to close handler for case {case_id}")
            return handle_close_command(case_id, response_url)
        
        else:
            logger.warning(f"Unknown subcommand '{subcommand}' for case {case_id}")
            send_slack_response(
                response_url,
                f"❌ Error: Unknown command '{subcommand}'.\n\n{COMMAND_HELP}"
            )
            return False
        
    except Exception as e:
        logger.error(f"Unexpected error processing command: {str(e)}", exc_info=True)
        response_url = command_payload.get("response_url")
        if response_url:
            send_slack_response(response_url, f"❌ Error: {str(e)}")
        return False


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing Slack slash commands.
    
    Args:
        event: Command payload from Slack Events Bolt Handler
        context: Lambda context object
        
    Returns:
        Dict containing status and response information
    """
    try:
        logger.info("Processing Slack command handler request")
        logger.info(f"Received event keys: {list(event.keys())}")
        logger.debug(f"Full event: {json.dumps(event, default=str)}")
        
        # Validate event structure
        required_fields = ['command', 'case_id', 'user_id', 'response_url']
        missing_fields = [field for field in required_fields if not event.get(field)]
        
        if missing_fields:
            error_msg = f"Missing required fields: {missing_fields}"
            logger.error(error_msg)
            return {
                "statusCode": 400,
                "body": json.dumps({"error": error_msg, "success": False})
            }
        
        # Process the command
        success = process_command(event)
        
        result = {
            "statusCode": 200 if success else 500,
            "body": json.dumps({"success": success})
        }
        
        logger.info(f"Command processing completed with success: {success}")
        return result
        
    except Exception as e:
        logger.error(f"Unexpected error in lambda handler: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e), "success": False})
        }

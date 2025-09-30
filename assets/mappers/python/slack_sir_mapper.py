"""
Slack Field Mapper for AWS Security Incident Response Integration

This module provides mapping functionality between AWS Security Incident Response
and Slack data formats, including channels, messages, attachments, and user mappings.
"""

import logging
from typing import Dict, List, Tuple, Any, Optional, Union
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Import constants with fallbacks for different environments
try:
    from constants import SLACK_SYSTEM_COMMENT_TAG, SLACK_CHANNEL_PREFIX
except ImportError:
    try:
        from aws_security_incident_response_sample_integrations.constants import (
            SLACK_SYSTEM_COMMENT_TAG,
            SLACK_CHANNEL_PREFIX
        )
    except ImportError:
        # Fallback constants
        SLACK_SYSTEM_COMMENT_TAG = "[Slack Update]"
        SLACK_CHANNEL_PREFIX = "aws-security-incident-response-case-"

# Status mapping from AWS SIR to Slack channel topic/description
STATUS_MAPPING = {
    "Acknowledged": "🔍 Acknowledged",
    "Detection and Analysis": "🔍 Under Investigation", 
    "Containment, Eradication and Recovery": "🚨 Active Response",
    "Post-incident Activities": "📋 Post-Incident Review",
    "Ready to Close": "✅ Ready to Close",
    "Closed": "✅ Closed",
}

# Default status if no mapping exists
DEFAULT_SLACK_STATUS = "🔍 Under Investigation"

# Severity to emoji mapping for visual indicators
SEVERITY_MAPPING = {
    "Critical": "🔴",
    "High": "🟠", 
    "Medium": "🟡",
    "Low": "🟢",
    "Informational": "🔵"
}

# Field mappings for AWS SIR case to Slack message formatting
FIELD_DISPLAY_NAMES = {
    "caseId": "Case ID",
    "caseArn": "Case ARN",
    "title": "Title",
    "description": "Description",
    "caseStatus": "Status",
    "severity": "Severity",
    "incidentStartDate": "Incident Start Date",
    "impactedAccounts": "Impacted Accounts",
    "impactedRegions": "Impacted Regions",
    "createdDate": "Created Date",
    "lastUpdated": "Last Updated",
    "watchers": "Watchers",
    "closureCode": "Closure Code"
}


def map_case_to_slack_channel_name(case_id: str) -> str:
    """
    Maps AWS SIR case ID to Slack channel name.

    Args:
        case_id (str): AWS SIR case ID

    Returns:
        str: Slack channel name
    """
    return f"{SLACK_CHANNEL_PREFIX}{case_id}"


def map_case_to_slack_channel_topic(sir_case: Dict[str, Any]) -> str:
    """
    Maps AWS SIR case to Slack channel topic.

    Args:
        sir_case (Dict[str, Any]): AWS SIR case data

    Returns:
        str: Slack channel topic
    """
    title = sir_case.get("title", "Security Incident")
    status = sir_case.get("caseStatus", "Unknown")
    severity = sir_case.get("severity", "Unknown")
    
    status_emoji = STATUS_MAPPING.get(status, DEFAULT_SLACK_STATUS)
    severity_emoji = SEVERITY_MAPPING.get(severity, "⚪")
    
    return f"{severity_emoji} {status_emoji} | {title}"


def map_case_to_slack_notification(sir_case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps AWS SIR case to Slack notification message with blocks.

    Args:
        sir_case (Dict[str, Any]): AWS SIR case data

    Returns:
        Dict[str, Any]: Slack message payload with blocks
    """
    case_id = sir_case.get("caseId", "Unknown")
    title = sir_case.get("title", "Security Incident")
    description = sir_case.get("description", "No description provided")
    status = sir_case.get("caseStatus", "Unknown")
    severity = sir_case.get("severity", "Unknown")
    created_date = sir_case.get("createdDate", "Unknown")
    
    severity_emoji = SEVERITY_MAPPING.get(severity, "⚪")
    status_display = STATUS_MAPPING.get(status, status)
    
    # Create Slack blocks for rich formatting
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{severity_emoji} New Security Incident: {case_id}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Title:*\n{title}"
                },
                {
                    "type": "mrkdwn", 
                    "text": f"*Status:*\n{status_display}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:*\n{severity_emoji} {severity}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Created:*\n{created_date}"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Description:*\n{description}"
            }
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Available Commands:*\n" +
                        "• `/security-ir status` - Get current case status\n" +
                        "• `/security-ir update-status <status>` - Update case status\n" +
                        "• `/security-ir update-title <title>` - Update case title\n" +
                        "• `/security-ir update-description <description>` - Update description\n" +
                        "• `/security-ir close` - Close the case\n" +
                        "• `/security-ir summarize` - Get case summary"
            }
        }
    ]
    
    # Add impacted accounts and regions if available
    if sir_case.get("impactedAccounts") or sir_case.get("impactedRegions"):
        impact_fields = []
        
        if sir_case.get("impactedAccounts"):
            accounts = sir_case["impactedAccounts"]
            accounts_text = ", ".join(accounts) if isinstance(accounts, list) else str(accounts)
            impact_fields.append({
                "type": "mrkdwn",
                "text": f"*Impacted Accounts:*\n{accounts_text}"
            })
        
        if sir_case.get("impactedRegions"):
            regions = sir_case["impactedRegions"]
            regions_text = ", ".join(regions) if isinstance(regions, list) else str(regions)
            impact_fields.append({
                "type": "mrkdwn",
                "text": f"*Impacted Regions:*\n{regions_text}"
            })
        
        # Insert impact section before divider
        blocks.insert(-2, {
            "type": "section",
            "fields": impact_fields
        })
    
    return {
        "text": f"New Security Incident: {case_id}",
        "blocks": blocks
    }


def map_case_update_to_slack_message(sir_case: Dict[str, Any], update_type: str) -> Dict[str, Any]:
    """
    Maps AWS SIR case update to Slack message.

    Args:
        sir_case (Dict[str, Any]): AWS SIR case data
        update_type (str): Type of update (status, title, description, etc.)

    Returns:
        Dict[str, Any]: Slack message payload
    """
    case_id = sir_case.get("caseId", "Unknown")
    
    if update_type == "status":
        status = sir_case.get("caseStatus", "Unknown")
        status_display = STATUS_MAPPING.get(status, status)
        severity = sir_case.get("severity", "Unknown")
        severity_emoji = SEVERITY_MAPPING.get(severity, "⚪")
        
        return {
            "text": f"Case {case_id} status updated to: {status_display}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{severity_emoji} *Case Status Updated*\n" +
                                f"Case {case_id} status changed to: *{status_display}*"
                    }
                }
            ]
        }
    
    elif update_type == "title":
        title = sir_case.get("title", "Unknown")
        return {
            "text": f"Case {case_id} title updated",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📝 *Case Title Updated*\n" +
                                f"Case {case_id} title: *{title}*"
                    }
                }
            ]
        }
    
    elif update_type == "description":
        description = sir_case.get("description", "No description")
        return {
            "text": f"Case {case_id} description updated",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📝 *Case Description Updated*\n" +
                                f"Case {case_id} description updated"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "plain_text",
                        "text": description
                    }
                }
            ]
        }
    
    else:
        return {
            "text": f"Case {case_id} updated",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🔄 *Case Updated*\nCase {case_id} has been updated"
                    }
                }
            ]
        }


def map_comment_to_slack_message(comment: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    """
    Maps AWS SIR case comment to Slack message.

    Args:
        comment (Dict[str, Any]): AWS SIR comment data
        case_id (str): AWS SIR case ID

    Returns:
        Dict[str, Any]: Slack message payload
    """
    body = comment.get("body", "")
    created_date = comment.get("createdDate", "")
    created_by = comment.get("createdBy", {})
    
    # Extract user information
    user_name = "Unknown User"
    if isinstance(created_by, dict):
        user_name = created_by.get("name", created_by.get("email", "Unknown User"))
    elif isinstance(created_by, str):
        user_name = created_by
    
    return {
        "text": f"New comment on case {case_id}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"💬 *New Comment by {user_name}*\n{body}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Case {case_id} • {created_date}"
                    }
                ]
            }
        ]
    }


def map_slack_message_to_sir_comment(message: Dict[str, Any], user_name: str = None) -> str:
    """
    Maps Slack message to AWS SIR case comment format.

    Args:
        message (Dict[str, Any]): Slack message data
        user_name (str, optional): Slack user display name

    Returns:
        str: Formatted comment for AWS SIR
    """
    text = message.get("text", "")
    timestamp = message.get("ts", "")
    user_id = message.get("user", "")
    
    # Format timestamp if available
    formatted_time = ""
    if timestamp:
        try:
            dt = datetime.fromtimestamp(float(timestamp))
            formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (ValueError, TypeError):
            formatted_time = timestamp
    
    # Use provided user name or fall back to user ID
    display_name = user_name or user_id or "Slack User"
    
    # Format comment with Slack attribution
    comment_header = f"[Slack Message from {display_name}"
    if formatted_time:
        comment_header += f" at {formatted_time}"
    comment_header += "]"
    
    return f"{comment_header}\n{text}"


def map_watchers_to_slack_users(sir_watchers: List[Union[str, Dict[str, str]]], 
                                slack_user_mapping: Dict[str, str] = None) -> List[str]:
    """
    Maps AWS SIR watchers to Slack user IDs.

    Args:
        sir_watchers (List[Union[str, Dict[str, str]]]): List of SIR watchers
        slack_user_mapping (Dict[str, str], optional): Email to Slack user ID mapping

    Returns:
        List[str]: List of Slack user IDs
    """
    if not slack_user_mapping:
        slack_user_mapping = {}
    
    slack_users = []
    
    for watcher in sir_watchers:
        email = None
        
        # Extract email from watcher
        if isinstance(watcher, dict) and "email" in watcher:
            email = watcher["email"].lower()
        elif isinstance(watcher, str):
            email = watcher.lower()
        
        if email:
            # Look up Slack user ID by email
            slack_user_id = slack_user_mapping.get(email)
            if slack_user_id:
                slack_users.append(slack_user_id)
            else:
                logger.warning(f"No Slack user mapping found for email: {email}")
    
    return slack_users


def map_slack_users_to_watchers(slack_user_ids: List[str], 
                                slack_user_mapping: Dict[str, str] = None) -> List[str]:
    """
    Maps Slack user IDs to email addresses for AWS SIR watchers.

    Args:
        slack_user_ids (List[str]): List of Slack user IDs
        slack_user_mapping (Dict[str, str], optional): Email to Slack user ID mapping

    Returns:
        List[str]: List of email addresses
    """
    if not slack_user_mapping:
        slack_user_mapping = {}
    
    # Create reverse mapping
    reverse_mapping = {v: k for k, v in slack_user_mapping.items()}
    
    emails = []
    for user_id in slack_user_ids:
        email = reverse_mapping.get(user_id)
        if email:
            emails.append(email)
        else:
            logger.warning(f"No email mapping found for Slack user ID: {user_id}")
    
    return emails


def map_attachment_to_slack_file(attachment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps AWS SIR attachment to Slack file upload format.

    Args:
        attachment (Dict[str, Any]): AWS SIR attachment data

    Returns:
        Dict[str, Any]: Slack file upload parameters
    """
    filename = attachment.get("filename", "attachment")
    content = attachment.get("content", b"")
    
    return {
        "filename": filename,
        "file": content,
        "title": attachment.get("title", filename),
        "initial_comment": f"Attachment from AWS Security Incident Response: {filename}"
    }


def map_slack_file_to_attachment(file_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps Slack file data to AWS SIR attachment format.

    Args:
        file_data (Dict[str, Any]): Slack file data

    Returns:
        Dict[str, Any]: AWS SIR attachment format
    """
    return {
        "filename": file_data.get("name", "slack_file"),
        "url": file_data.get("url_private_download"),
        "size": file_data.get("size", 0),
        "mimetype": file_data.get("mimetype", "application/octet-stream"),
        "title": file_data.get("title"),
        "description": f"File shared in Slack by {file_data.get('user', 'Unknown User')}"
    }


def should_skip_comment(comment_body: str) -> bool:
    """
    Determines if a comment should be skipped to prevent notification loops.

    Args:
        comment_body (str): Comment body text

    Returns:
        bool: True if comment should be skipped, False otherwise
    """
    return SLACK_SYSTEM_COMMENT_TAG in comment_body


def create_system_comment(message: str, error_details: str = None) -> str:
    """
    Creates a system comment with the Slack update tag.

    Args:
        message (str): System message
        error_details (str, optional): Additional error details

    Returns:
        str: Formatted system comment
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    comment = f"{SLACK_SYSTEM_COMMENT_TAG} {message} (at {timestamp})"
    
    if error_details:
        comment += f"\nError Details: {error_details}"
    
    return comment


def map_case_summary_to_slack_message(sir_case: Dict[str, Any], 
                                     comments: List[Dict[str, Any]] = None,
                                     attachments: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Maps AWS SIR case data to a comprehensive Slack summary message.

    Args:
        sir_case (Dict[str, Any]): AWS SIR case data
        comments (List[Dict[str, Any]], optional): Case comments
        attachments (List[Dict[str, Any]], optional): Case attachments

    Returns:
        Dict[str, Any]: Slack message payload with summary
    """
    case_id = sir_case.get("caseId", "Unknown")
    title = sir_case.get("title", "Security Incident")
    description = sir_case.get("description", "No description provided")
    status = sir_case.get("caseStatus", "Unknown")
    severity = sir_case.get("severity", "Unknown")
    created_date = sir_case.get("createdDate", "Unknown")
    last_updated = sir_case.get("lastUpdated", "Unknown")
    
    severity_emoji = SEVERITY_MAPPING.get(severity, "⚪")
    status_display = STATUS_MAPPING.get(status, status)
    
    # Build summary blocks
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{severity_emoji} Case Summary: {case_id}"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Title:*\n{title}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Status:*\n{status_display}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:*\n{severity_emoji} {severity}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Created:*\n{created_date}"
                }
            ]
        }
    ]
    
    # Add description if not too long
    if len(description) <= 500:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Description:*\n{description}"
            }
        })
    
    # Add activity summary
    activity_text = f"*Last Updated:* {last_updated}\n"
    
    if comments:
        activity_text += f"*Comments:* {len(comments)}\n"
    
    if attachments:
        activity_text += f"*Attachments:* {len(attachments)}\n"
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": activity_text
        }
    })
    
    # Add impacted resources if available
    if sir_case.get("impactedAccounts") or sir_case.get("impactedRegions"):
        impact_fields = []
        
        if sir_case.get("impactedAccounts"):
            accounts = sir_case["impactedAccounts"]
            accounts_text = ", ".join(accounts) if isinstance(accounts, list) else str(accounts)
            impact_fields.append({
                "type": "mrkdwn",
                "text": f"*Impacted Accounts:*\n{accounts_text}"
            })
        
        if sir_case.get("impactedRegions"):
            regions = sir_case["impactedRegions"]
            regions_text = ", ".join(regions) if isinstance(regions, list) else str(regions)
            impact_fields.append({
                "type": "mrkdwn",
                "text": f"*Impacted Regions:*\n{regions_text}"
            })
        
        blocks.append({
            "type": "section",
            "fields": impact_fields
        })
    
    return {
        "text": f"Case Summary: {case_id}",
        "blocks": blocks
    }


def validate_slack_channel_mapping(case_id: str, channel_id: str) -> bool:
    """
    Validates that a Slack channel ID is properly formatted and associated with a case.

    Args:
        case_id (str): AWS SIR case ID
        channel_id (str): Slack channel ID

    Returns:
        bool: True if valid mapping, False otherwise
    """
    if not case_id or not channel_id:
        return False
    
    # Validate Slack channel ID format
    import re
    if not re.match(r'^C[A-Z0-9]{8,}$', channel_id):
        logger.error(f"Invalid Slack channel ID format: {channel_id}")
        return False
    
    return True


def extract_case_id_from_channel_name(channel_name: str) -> Optional[str]:
    """
    Extracts AWS SIR case ID from Slack channel name.

    Args:
        channel_name (str): Slack channel name

    Returns:
        Optional[str]: Case ID if found, None otherwise
    """
    if not channel_name or not channel_name.startswith(SLACK_CHANNEL_PREFIX):
        return None
    
    return channel_name[len(SLACK_CHANNEL_PREFIX):]


def format_slack_error_message(error: str, case_id: str = None) -> Dict[str, Any]:
    """
    Formats an error message for Slack display.

    Args:
        error (str): Error message
        case_id (str, optional): Associated case ID

    Returns:
        Dict[str, Any]: Slack message payload
    """
    text = f"❌ Error: {error}"
    if case_id:
        text = f"❌ Error for case {case_id}: {error}"
    
    return {
        "text": text,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"❌ *Error*\n{error}"
                }
            }
        ]
    }
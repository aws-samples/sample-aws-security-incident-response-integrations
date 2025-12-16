"""
Slack Field Mapper for AWS Security Incident Response Integration

This module provides mapping functionality between AWS Security Incident Response
and Slack data formats, including channels, messages, attachments, and user mappings.
"""

import logging
import re
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
    "Medium": "�",
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


class SlackToSirMapper:
    """
    Handles transformations from Slack data formats to AWS Security Incident Response formats.
    """

    def __init__(self, slack_user_mapping: Dict[str, str] = None):
        """
        Initialize the SlackToSirMapper.

        Args:
            slack_user_mapping (Dict[str, str], optional): Email to Slack user ID mapping
        """
        self.slack_user_mapping = slack_user_mapping or {}
        self.logger = logging.getLogger(self.__class__.__name__)

    # Message in Slack to comment in SIR.
    def map_message_to_comment(self, slack_message: Dict[str, Any], 
                              case_id: str,
                              slack_channel_name: str = None, 
                              user_name: str = None) -> str:
        """
        Maps Slack message to AWS SIR case comment format.

        Args:
            slack_message (Dict[str, Any]): Slack message data
            case_id (str): AWS SIR case ID that this comment belongs to
            slack_channel_name (str, optional): Slack channel name for context
            user_name (str, optional): Slack user display name

        Returns:
            str: Formatted comment for AWS SIR
        """
        text = slack_message.get("text", "")
        timestamp = slack_message.get("ts", "")
        user_id = slack_message.get("user", "")
        
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
        if slack_channel_name:
            comment_header += f" in #{slack_channel_name}"
        comment_header += f" for Case {case_id}]"
        
        return f"{comment_header}\n{text}"

    # Slack Channel name to SIR case Id
    def map_channel_name_to_case_id(self, slack_channel_name: str) -> Optional[str]:
        """
        Extracts AWS SIR case ID from Slack channel name.

        Args:
            slack_channel_name (str): Slack channel name

        Returns:
            Optional[str]: Case ID if found, None otherwise
        """
        if not slack_channel_name or not slack_channel_name.startswith(SLACK_CHANNEL_PREFIX):
            return None
        
        return slack_channel_name[len(SLACK_CHANNEL_PREFIX):]

    # Slack Channel topic to SIR case title
    def map_channel_topic_to_case_title(self, slack_channel_topic: str) -> str:
        """
        Extracts case title from Slack channel topic.

        Args:
            slack_channel_topic (str): Slack channel topic

        Returns:
            str: Extracted case title
        """
        if not slack_channel_topic:
            return "Security Incident"
        
        # Remove emojis and status indicators to extract title
        # Pattern matches: emoji + status + | + title
        pattern = r'^[🔴🟠🟡🟢🔵⚪]\s*[🔍🚨📋✅][^|]*\|\s*(.+)$'
        match = re.match(pattern, slack_channel_topic.strip())
        
        if match:
            return match.group(1).strip()
        
        # Fallback: return the topic as-is if pattern doesn't match
        return slack_channel_topic.strip()

    # Slack Channel description to SIR case description
    def map_channel_description_to_case_description(self, slack_channel_description: str) -> str:
        """
        Maps Slack channel description to AWS SIR case description.

        Args:
            slack_channel_description (str): Slack channel description

        Returns:
            str: Case description
        """
        return slack_channel_description or "No description provided"

     # Slack Channel attachment to SIR case attachment
    def map_attachment_to_case_attachment(self, slack_file_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Maps Slack file data to AWS SIR attachment format.

        Args:
            slack_file_data (Dict[str, Any]): Slack file data

        Returns:
            Dict[str, Any]: AWS SIR attachment format
        """
        return {
            "filename": slack_file_data.get("name", "slack_file"),
            "url": slack_file_data.get("url_private_download"),
            "size": slack_file_data.get("size", 0),
            "mimetype": slack_file_data.get("mimetype", "application/octet-stream"),
            "title": slack_file_data.get("title"),
            "description": f"File shared in Slack by {slack_file_data.get('user', 'Unknown User')}"
        }

    # existinng users to watchers
    def map_users_to_watchers(self, slack_user_ids: List[str]) -> List[str]:
        """
        Maps Slack user IDs to email addresses for AWS SIR watchers.

        Args:
            slack_user_ids (List[str]): List of Slack user IDs

        Returns:
            List[str]: List of email addresses
        """
        # Create reverse mapping
        reverse_mapping = {v: k for k, v in self.slack_user_mapping.items()}
        
        emails = []
        for user_id in slack_user_ids:
            email = reverse_mapping.get(user_id)
            if email:
                emails.append(email)
            else:
                self.logger.warning(f"No email mapping found for Slack user ID: {user_id}")
        
        return emails

    def validate_channel_mapping(self, case_id: str, channel_id: str) -> bool:
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
        if not re.match(r'^C[A-Z0-9]{8,}$', channel_id):
            self.logger.error(f"Invalid Slack channel ID format: {channel_id}")
            return False
        
        return True


class SirToSlackMapper:
    """
    Handles transformations from AWS Security Incident Response formats to Slack data formats.
    """

    def __init__(self, slack_user_mapping: Dict[str, str] = None):
        """
        Initialize the SirToSlackMapper.

        Args:
            slack_user_mapping (Dict[str, str], optional): Email to Slack user ID mapping
        """
        self.slack_user_mapping = slack_user_mapping or {}
        self.logger = logging.getLogger(self.__class__.__name__)

    # SIR case Id to Slack Channel name
    def map_case_id_to_channel_name(self, sir_case_id: str) -> str:
        """
        Maps AWS SIR case ID to Slack channel name.

        Args:
            sir_case_id (str): AWS SIR case ID

        Returns:
            str: Slack channel name
        """
        return f"{SLACK_CHANNEL_PREFIX}{sir_case_id}"

    # SIR case title to Slack Channel topic
    def map_case_title_to_channel_topic(self, sir_case: Dict[str, Any]) -> str:
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

    # SIR case description to Slack Channel description
    def map_case_description_to_channel_description(self, sir_case: Dict[str, Any]) -> str:
        """
        Maps AWS SIR case description to Slack channel description.

        Args:
            sir_case (Dict[str, Any]): AWS SIR case data

        Returns:
            str: Slack channel description
        """
        description = sir_case.get("description", "No description provided")
        
        # Try multiple possible case ID fields and extract from ARN if needed
        case_id = sir_case.get("caseId")
        if not case_id:
            case_arn = sir_case.get("caseArn")
            if case_arn:
                import re
                match = re.search(r"/(\d+)$", case_arn)
                case_id = match.group(1) if match else "Unknown"
            else:
                case_id = "Unknown"
        
        severity = sir_case.get("severity", "Unknown")
        
        return f"AWS Security Incident Response Case {case_id} - {severity} Severity\n\n{description}"

    # SIR case attachment to Slack Channel attachment
    def map_case_attachment_to_slack_file(self, sir_attachment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Maps AWS SIR attachment to Slack file upload format.

        Args:
            sir_attachment (Dict[str, Any]): AWS SIR attachment data

        Returns:
            Dict[str, Any]: Slack file upload parameters
        """
        filename = sir_attachment.get("filename", "attachment")
        content = sir_attachment.get("content", b"")
        
        return {
            "filename": filename,
            "file": content,
            "title": sir_attachment.get("title", filename),
            "initial_comment": f"Attachment from AWS Security Incident Response: {filename}"
        }

    # Comment in SIR to message in Slack. 
    def map_comment_to_slack_message(self, sir_comment: Dict[str, Any], case_comment: str, sir_case_id: str) -> Dict[str, Any]:
        """
        Maps AWS SIR case comment to Slack message.

        Args:
            sir_comment (Dict[str, Any]): AWS SIR comment data
            case_comment (str): Comment text
            sir_case_id (str): AWS SIR case ID

        Returns:
            Dict[str, Any]: Slack message payload
        """
        body = sir_comment.get("body", case_comment)
        created_date = sir_comment.get("createdDate", "")
        created_by = sir_comment.get("createdBy", {})
        
        # Extract user information
        user_name = "Unknown User"
        if isinstance(created_by, dict):
            user_name = created_by.get("name", created_by.get("email", "Unknown User"))
        elif isinstance(created_by, str):
            user_name = created_by
        
        return {
            "text": f"New comment on case {sir_case_id}",
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
                            "text": f"Case {sir_case_id} • {created_date}"
                        }
                    ]
                }
            ]
        }

    def map_watchers_to_slack_users(self, sir_watchers: List[Union[str, Dict[str, str]]]) -> List[str]:
        """
        Maps AWS SIR watchers to Slack user IDs.

        Args:
            sir_watchers (List[Union[str, Dict[str, str]]]): List of SIR watchers

        Returns:
            List[str]: List of Slack user IDs
        """
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
                slack_user_id = self.slack_user_mapping.get(email)
                if slack_user_id:
                    slack_users.append(slack_user_id)
                else:
                    self.logger.warning(f"No Slack user mapping found for email: {email}")
        
        return slack_users

    def map_case_to_notification_message(self, sir_case: Dict[str, Any]) -> Dict[str, Any]:
        """
        Maps AWS SIR case to Slack notification message with blocks.

        Args:
            sir_case (Dict[str, Any]): AWS SIR case data

        Returns:
            Dict[str, Any]: Slack message payload with blocks
        """
        # Try multiple possible case ID fields and extract from ARN if needed
        case_id = sir_case.get("caseId")
        if not case_id:
            case_arn = sir_case.get("caseArn")
            if case_arn:
                import re
                match = re.search(r"/(\d+)$", case_arn)
                case_id = match.group(1) if match else "Unknown"
            else:
                case_id = "Unknown"
        
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

    def map_case_update_to_message(self, sir_case: Dict[str, Any], update_type: str) -> Dict[str, Any]:
        """
        Maps AWS SIR case update to Slack message.

        Args:
            sir_case (Dict[str, Any]): AWS SIR case data
            update_type (str): Type of update (status, title, description, etc.)

        Returns:
            Dict[str, Any]: Slack message payload
        """
        # Try multiple possible case ID fields and extract from ARN if needed
        case_id = sir_case.get("caseId")
        if not case_id:
            case_arn = sir_case.get("caseArn")
            if case_arn:
                import re
                match = re.search(r"/(\d+)$", case_arn)
                case_id = match.group(1) if match else "Unknown"
            else:
                case_id = "Unknown"
        
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
                "text": f"Title updated: {title}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"📝 *Case Title Updated*\n*{title}*"
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
                            "text": f"📝 *Case Description Updated*\n"
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

    def map_case_summary_to_message(self, sir_case: Dict[str, Any], 
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
        # Try multiple possible case ID fields and extract from ARN if needed
        case_id = sir_case.get("caseId")
        if not case_id:
            case_arn = sir_case.get("caseArn")
            if case_arn:
                import re
                match = re.search(r"/(\d+)$", case_arn)
                case_id = match.group(1) if match else "Unknown"
            else:
                case_id = "Unknown"
        
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

    def format_error_message(self, error: str, case_id: str = None) -> Dict[str, Any]:
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


# Utility functions for backward compatibility and common operations

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


# Backward compatibility functions - most functions all across codebase use this.
# Class is simply instatiated and functionality is returned rather than refactoring codebase
def map_case_to_slack_channel_name(case_id: str) -> str:
    """
    Maps AWS SIR case ID to Slack channel name.
    
    Args:
        case_id (str): AWS SIR case ID
    
    Returns:
        str: Slack channel name
    """
    mapper = SirToSlackMapper()
    return mapper.map_case_id_to_channel_name(case_id)


def map_case_to_slack_channel_topic(sir_case: Dict[str, Any]) -> str:
    """
    Maps AWS SIR case to Slack channel topic.
    
    Args:
        sir_case (Dict[str, Any]): AWS SIR case data
    
    Returns:
        str: Slack channel topic
    """
    mapper = SirToSlackMapper()
    return mapper.map_case_title_to_channel_topic(sir_case)


def map_case_to_slack_notification(sir_case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps AWS SIR case to Slack notification message with blocks.

    Args:
        sir_case (Dict[str, Any]): AWS SIR case data

    Returns:
        Dict[str, Any]: Slack message payload with blocks
    """
    mapper = SirToSlackMapper()
    return mapper.map_case_to_notification_message(sir_case)


def map_case_update_to_slack_message(sir_case: Dict[str, Any], update_type: str) -> Dict[str, Any]:
    """
    Maps AWS SIR case update to Slack message.

    Args:
        sir_case (Dict[str, Any]): AWS SIR case data
        update_type (str): Type of update (status, title, description, etc.)

    Returns:
        Dict[str, Any]: Slack message payload
    """
    mapper = SirToSlackMapper()
    return mapper.map_case_update_to_message(sir_case, update_type)


def map_comment_to_slack_message(comment: Dict[str, Any], case_id: str) -> Dict[str, Any]:
    """
    Maps AWS SIR case comment to Slack message.

    Args:
        comment (Dict[str, Any]): AWS SIR comment data
        case_id (str): AWS SIR case ID

    Returns:
        Dict[str, Any]: Slack message payload
    """
    mapper = SirToSlackMapper()
    return mapper.map_comment_to_slack_message(comment, "", case_id)


def map_slack_message_to_sir_comment(message: Dict[str, Any], case_id: str, user_name: str = None) -> str:
    """
    Maps Slack message to AWS SIR case comment format.
    
    Args:
        message (Dict[str, Any]): Slack message data
        case_id (str): AWS SIR case ID that this comment belongs to
        user_name (str, optional): Slack user display name
    
    Returns:
        str: Formatted comment for AWS SIR
    """
    mapper = SlackToSirMapper()
    return mapper.map_message_to_comment(message, case_id, user_name=user_name)


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
    mapper = SirToSlackMapper(slack_user_mapping)
    return mapper.map_watchers_to_slack_users(sir_watchers)


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
    mapper = SlackToSirMapper(slack_user_mapping)
    return mapper.map_users_to_watchers(slack_user_ids)


def map_attachment_to_slack_file(attachment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps AWS SIR attachment to Slack file upload format.

    Args:
        attachment (Dict[str, Any]): AWS SIR attachment data

    Returns:
        Dict[str, Any]: Slack file upload parameters
    """
    mapper = SirToSlackMapper()
    return mapper.map_case_attachment_to_slack_file(attachment)


def map_slack_file_to_attachment(file_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps Slack file data to AWS SIR attachment format.

    Args:
        file_data (Dict[str, Any]): Slack file data

    Returns:
        Dict[str, Any]: AWS SIR attachment format
    """
    mapper = SlackToSirMapper()
    return mapper.map_attachment_to_case_attachment(file_data)


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
    mapper = SirToSlackMapper()
    return mapper.map_case_summary_to_message(sir_case, comments, attachments)


def validate_slack_channel_mapping(case_id: str, channel_id: str) -> bool:
    """
    Validates that a Slack channel ID is properly formatted and associated with a case.
    
    Args:
        case_id (str): AWS SIR case ID
        channel_id (str): Slack channel ID
    
    Returns:
        bool: True if valid mapping, False otherwise
    """
    mapper = SlackToSirMapper()
    return mapper.validate_channel_mapping(case_id, channel_id)


def extract_case_id_from_channel_name(channel_name: str) -> Optional[str]:
    """
    Extracts AWS SIR case ID from Slack channel name.
    
    Args:
        channel_name (str): Slack channel name
    
    Returns:
        Optional[str]: Case ID if found, None otherwise
    """
    mapper = SlackToSirMapper()
    return mapper.map_channel_name_to_case_id(channel_name)


def format_slack_error_message(error: str, case_id: str = None) -> Dict[str, Any]:
    """
    Formats an error message for Slack display.
    
    Args:
        error (str): Error message
        case_id (str, optional): Associated case ID
    
    Returns:
        Dict[str, Any]: Slack message payload
    """
    mapper = SirToSlackMapper()
    return mapper.format_error_message(error, case_id)
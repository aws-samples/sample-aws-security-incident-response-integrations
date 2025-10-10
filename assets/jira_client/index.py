"""
Jira Client Lambda function for AWS Security Incident Response integration.
This module handles the creation and updating of Jira issues based on Security Incident Response cases.
"""

import json
import os
import re
import sys
import logging
import requests
import datetime
from typing import List, Dict, Optional, Any, Tuple, Union

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
event_client = boto3.client("events")
dynamodb = boto3.resource("dynamodb")

# tag for comments sourced from Security IR
UPDATE_TAG_TO_ADD = "[AWS Security Incident Response Update]"
UPDATE_TAG_TO_SKIP = "[JIRA Update]"

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from jira_sir_mapper import (
        map_case_status,
        map_fields_to_jira,
        map_closure_code,
    )
    from jira_wrapper import JiraClient
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..mappers.python.jira_sir_mapper import (
        Case,
        create_case_from_api_response,
        map_fields_to_jira,
        map_case_status,
    )
    from ..wrappers.python.jira_wrapper import JiraClient


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
            logger.error(f"Jira issue for Case#{case_id} not found in database")
            return None

    def update_mapping(self, case_id: str, jira_issue_id: str) -> bool:
        """Update the mapping between an IR case and a Jira issue.

        Args:
            case_id (str): The IR case ID
            jira_issue_id (str): The Jira issue ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression="set jiraIssueId = :j",
                ExpressionAttributeValues={":j": jira_issue_id},
                ReturnValues="UPDATED_NEW",
            )
            logger.info(f"IR case {case_id} mapped to Jira issue {jira_issue_id}")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error updating DynamoDB table: {error_code}")
            return False

    def update_issue_details(
        self, case_id: str, jira_issue_id: str, issue_details: Any
    ) -> bool:
        """Update Jira issue details in the database.

        Args:
            case_id (str): The IR case ID
            jira_issue_id (str): The Jira issue ID
            issue_details (Any): Jira issue details

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Extract serializable details from the Jira issue object
            serializable_details = extract_jira_issue_details(issue_details)

            # Update the database
            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression="set jiraIssueDetails = :j",
                ExpressionAttributeValues={":j": json.dumps(serializable_details)},
                ReturnValues="UPDATED_NEW",
            )

            logger.info(f"Updated Jira issue details in DynamoDB for case {case_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating Jira issue details in DynamoDB: {str(e)}")
            return False


class AttachmentService:
    """Class to handle attachment operations"""

    def __init__(self, jira_client: JiraClient):
        """Initialize the attachment service.

        Args:
            jira_client (JiraClient): JiraClient instance
        """
        self.jira_client = jira_client

    def check_if_exists(
        self, jira_attachments: List[Any], ir_attachment_name: str
    ) -> bool:
        """Check if an attachment exists in a Jira issue.

        Args:
            jira_attachments (List[Any]): List of Jira attachments
            ir_attachment_name (str): IR attachment name

        Returns:
            bool: True if the attachment exists, False otherwise
        """
        for jira_attachment in jira_attachments:
            if str(ir_attachment_name) == str(jira_attachment):
                return True
        return False

    def sync_attachments(
        self,
        jira_issue_id: str,
        ir_case_id: str,
        ir_attachments: List[Dict[str, Any]],
        jira_attachments: List[Any],
    ) -> None:
        """Sync attachments between IR case and Jira issue.

        Args:
            jira_issue_id (str): The Jira issue ID
            ir_case_id (str): The IR case ID
            ir_attachments (List[Dict[str, Any]]): List of IR attachments
            jira_attachments (List[Any]): List of Jira attachments
        """
        for ir_attachment in ir_attachments:
            logger.info(f"Attachment to be uploaded: {ir_attachment}")
            ir_attachment_id = ir_attachment["attachmentId"]
            ir_attachment_name = ir_attachment["fileName"]

            # Check if attachment already exists in Jira
            if not self.check_if_exists(jira_attachments, ir_attachment_name):
                try:
                    self._add_attachment(
                        jira_issue_id, ir_case_id, ir_attachment_id, ir_attachment_name
                    )
                except Exception as e:
                    logger.error(f"Error adding attachment to security IR case: {e}")

    def _add_attachment(
        self,
        jira_issue_id: str,
        ir_case_id: str,
        ir_attachment_id: str,
        ir_attachment_name: str,
    ) -> None:
        """Add an attachment to a Jira issue.

        Args:
            jira_issue_id (str): The Jira issue ID
            ir_case_id (str): The IR case ID
            ir_attachment_id (str): The IR attachment ID
            ir_attachment_name (str): The IR attachment name
        """
        download_path = f"/tmp/{ir_attachment_name}"
        try:
            # Get presigned URL
            ir_attachment_presigned_url = (
                security_incident_response_client.get_case_attachment_download_url(
                    caseId=ir_case_id, attachmentId=ir_attachment_id
                )
            )

            ir_attachment_presigned_url_str = ir_attachment_presigned_url[
                "attachmentPresignedUrl"
            ]

            # Download object to /tmp using the presigned URL
            response = requests.get(ir_attachment_presigned_url_str)
            with open(download_path, "wb") as f:
                f.write(response.content)

            # Upload from /tmp and add to Jira issue as attachment
            with open(download_path, "rb") as f:
                self.jira_client.add_attachment(jira_issue_id, f)

            logger.info(
                f"Added attachment {ir_attachment_name} to Jira issue {jira_issue_id}"
            )

            # Delete file from /tmp directory
            os.remove(download_path)

        except Exception as e:
            logger.error(f"Error trying to download IR attachment: {e}")
            # Clean up if file exists
            if os.path.exists(download_path):
                os.remove(download_path)


class CommentService:
    """Class to handle comment operations"""

    def __init__(self, jira_client: JiraClient):
        """Initialize the comment service.

        Args:
            jira_client (JiraClient): JiraClient instance
        """
        self.jira_client = jira_client

    def sync_comments(
        self,
        jira_issue_id: str,
        ir_comments: List[Dict[str, Any]],
        jira_comments: List[Any],
    ) -> None:
        """Sync comments between IR case and Jira issue.

        Args:
            jira_issue_id (str): The Jira issue ID
            ir_comments (List[Dict[str, Any]]): List of IR comments
            jira_comments (List[Any]): List of Jira comments
        """
        sir_comment_bodies = [comment["body"] for comment in ir_comments]
        jira_comment_bodies = [comment.body for comment in jira_comments]

        # iterate Security IR comments
        for sir_comment in sir_comment_bodies:
            add_comment = True

            if UPDATE_TAG_TO_SKIP in sir_comment:
                add_comment = False

            # iterate Jira comments
            for jira_comment in jira_comment_bodies:
                if str(jira_comment).strip() == str(sir_comment).strip():
                    add_comment = False

            if add_comment is True:
                logger.info(
                    "Adding comment '%s' to Jira issue %s", sir_comment, jira_issue_id
                )
                self.jira_client.add_comment(jira_issue_id, sir_comment)


class IncidentService:
    """Class to handle incident operations"""

    def __init__(self):
        """Initialize the incident service."""
        self.jira_client = JiraClient()
        self.db_service = DatabaseService()
        self.attachment_service = AttachmentService(self.jira_client)
        self.comment_service = CommentService(self.jira_client)

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

    def map_sir_fields_to_jira_(
        self,
        ir_case_detail: Dict[str, Any],
        ir_case_id: str,
        jira_project_key: str,
        jira_issue_type: str,
    ) -> Dict[str, Any]:
        """Prepare Jira fields from IR case details.

        Args:
            ir_case_detail (Dict[str, Any]): IR case details
            ir_case_id (str): IR case ID
            jira_project_key (str): Jira project key
            jira_issue_type (str): Jira issue type

        Returns:
            Dict[str, Any]: Dictionary of Jira fields
        """
        # Map fields from SIR to JIRA
        jira_fields = map_fields_to_jira(ir_case_detail)

        # Ensure base fields are set
        jira_fields["summary"] = (
            # f"{ir_case_detail.get('title', 'Security IR Case')} - AWS Security Incident Response Case#{ir_case_id}"
            f"{ir_case_detail.get('title', 'Security IR Case')}"
        )

        jira_fields["project"] = {"key": jira_project_key}  # Set project key
        jira_fields["issuetype"] = {"name": jira_issue_type}  # Set issue type

        return jira_fields

    def handle_case_creation(
        self,
        ir_case_detail: Dict[str, Any],
        ir_case_id: str,
        jira_fields: Dict[str, Any],
        jira_status: Optional[str],
        status_comment: Optional[str],
    ) -> Optional[str]:
        """Handle the creation of a new IR case.

        Args:
            ir_case_detail (Dict[str, Any]): IR case details
            ir_case_id (str): IR case ID
            jira_fields (Dict[str, Any]): Jira fields
            jira_status (Optional[str]): Target Jira status
            status_comment (Optional[str]): Status comment

        Returns:
            Optional[str]: Jira issue ID or None if creation fails
        """
        # Create new issue
        jira_issue = self.jira_client.create_issue(jira_fields)
        if not jira_issue:
            return None

        jira_issue_id = jira_issue.key

        # Update status as needed
        if jira_status:
            self.jira_client.update_status(jira_issue_id, jira_status, status_comment)

        self.db_service.update_mapping(ir_case_id, jira_issue_id)

        # Handle watchers if present
        if "watchers" in ir_case_detail and ir_case_detail["watchers"]:
            self.jira_client.add_watchers(jira_issue_id, ir_case_detail["watchers"])

        # Get issue details and update database
        jira_issue = self.jira_client.get_issue(jira_issue_id)
        if jira_issue:
            self.db_service.update_issue_details(ir_case_id, jira_issue_id, jira_issue)

        logger.info(f"Created Jira issue {jira_issue_id} for new IR case {ir_case_id}")
        return jira_issue_id

    def handle_case_update(
        self,
        ir_case_detail: Dict[str, Any],
        ir_case_id: str,
        jira_fields: Dict[str, Any],
        jira_status: Optional[str],
        status_comment: Optional[str],
    ) -> Optional[str]:
        """Handle the update of an existing IR case.

        Args:
            ir_case_detail (Dict[str, Any]): IR case details
            ir_case_id (str): IR case ID
            jira_fields (Dict[str, Any]): Jira fields
            jira_status (Optional[str]): Target Jira status
            status_comment (Optional[str]): Status comment

        Returns:
            Optional[str]: Jira issue ID or None if update fails
        """
        # Get case details from database
        case_from_ddb = self.db_service.get_case(ir_case_id)
        if not case_from_ddb or "Item" not in case_from_ddb:
            logger.error(f"No case found in database for IR case {ir_case_id}")
            return None

        # Get Jira issue ID
        jira_issue_id = case_from_ddb["Item"].get("jiraIssueId")

        # Create new issue if none exists
        if jira_issue_id is None:
            logger.info(
                f"No Jira issue found for IR case {ir_case_id} in database, creating Jira issue..."
            )
            return self.handle_case_creation(
                ir_case_detail, ir_case_id, jira_fields, jira_status, status_comment
            )

        # Update existing issue
        self.jira_client.update_issue(jira_issue_id, jira_fields)

        # Update status if needed
        if jira_status:
            self.jira_client.update_status(jira_issue_id, jira_status, status_comment)

        # Get Jira issue details
        jira_issue = self.jira_client.get_issue(jira_issue_id)
        if not jira_issue:
            return jira_issue_id

        # Process incident details
        self.process_incident_details(
            jira_issue, jira_issue_id, case_from_ddb, ir_case_id, ir_case_detail
        )

        # Update issue details in database
        self.db_service.update_issue_details(ir_case_id, jira_issue_id, jira_issue)

        logger.info(
            f"Updated Jira issue {jira_issue_id} for existing IR case {ir_case_id}"
        )
        return jira_issue_id

    def process_incident_details(
        self,
        jira_issue: Any,
        jira_issue_id: str,
        case_from_ddb: Dict[str, Any],
        ir_case_id: str,
        ir_case_detail: Dict[str, Any],
    ) -> None:
        """Process incident details for comments, attachments, and watchers.

        Args:
            jira_issue (Any): Jira issue object
            jira_issue_id (str): Jira issue ID
            case_from_ddb (Dict[str, Any]): Case details from database
            ir_case_id (str): IR case ID
            ir_case_detail (Dict[str, Any]): IR case details
        """
        try:
            # Get incident details
            incident_details = case_from_ddb["Item"]["incidentDetails"]
            incident_details_json = json.loads(incident_details)

            # Process comments
            ir_comments = incident_details_json.get("caseComments", [])
            if ir_comments:
                jira_comments = jira_issue.fields.comment.comments
                self.comment_service.sync_comments(
                    jira_issue_id, ir_comments, jira_comments
                )

            # Process attachments
            ir_attachments = incident_details_json.get("caseAttachments", [])
            if ir_attachments:
                jira_attachments = jira_issue.fields.attachment
                self.attachment_service.sync_attachments(
                    jira_issue_id, ir_case_id, ir_attachments, jira_attachments
                )

            # Sync watchers
            sir_watchers = ir_case_detail.get("watchers", [])
            self.jira_client.sync_watchers(jira_issue_id, sir_watchers)

        except Exception as e:
            logger.error(f"Error processing incident details: {e}")

    def create_or_update_issue(
        self, ir_case: Dict[str, Any], jira_project_key: str, jira_issue_type: str
    ) -> Optional[str]:
        """Create or update a Jira issue based on an IR case.

        Args:
            ir_case (Dict[str, Any]): IR case data
            jira_project_key (str): Jira project key
            jira_issue_type (str): Jira issue type

        Returns:
            Optional[str]: Jira issue ID or None if operation fails
        """
        try:
            # Extract case details
            ir_case_detail, ir_event_type, ir_case_id, sir_case_status = (
                self.extract_case_details(ir_case)
            )

            # Check if Jira client is available
            if not self.jira_client.client:
                logger.error("Failed to create Jira client")
                return None

            # Prepare Jira fields
            jira_fields = self.map_sir_fields_to_jira_(
                ir_case_detail, ir_case_id, jira_project_key, jira_issue_type
            )

            # Get status mapping
            jira_status = None
            status_comment = None
            if sir_case_status:
                jira_status, status_comment = map_case_status(sir_case_status)

            # Handle based on event type
            if ir_event_type == "CaseCreated":
                return self.handle_case_creation(
                    ir_case_detail, ir_case_id, jira_fields, jira_status, status_comment
                )
            elif ir_event_type == "CaseUpdated":
                return self.handle_case_update(
                    ir_case_detail, ir_case_id, jira_fields, jira_status, status_comment
                )
            else:
                logger.warning(f"Unhandled event type: {ir_event_type}")
                return None

        except Exception as e:
            logger.error(f"Error in create_or_update_issue: {str(e)}")
            return None


def extract_jira_issue_details(jira_issue: Any) -> Dict[str, Any]:
    """Extract relevant details from a Jira issue object into a serializable dictionary.

    Args:
        jira_issue (Any): Jira issue object

    Returns:
        Dict[str, Any]: Dictionary with serializable Jira issue details
    """
    try:
        # Extract only the fields we need
        issue_dict = {
            "id": jira_issue.id,
            "key": jira_issue.key,
            "summary": jira_issue.fields.summary,
            "status": jira_issue.fields.status.name,
            "updated": str(jira_issue.fields.updated)
            if hasattr(jira_issue.fields, "updated")
            else None,
            "created": str(jira_issue.fields.created)
            if hasattr(jira_issue.fields, "created")
            else None,
            "description": jira_issue.fields.description,
            "priority": jira_issue.fields.priority.name
            if hasattr(jira_issue.fields, "priority") and jira_issue.fields.priority
            else None,
            "assignee": jira_issue.fields.assignee.displayName
            if hasattr(jira_issue.fields, "assignee") and jira_issue.fields.assignee
            else None,
            "reporter": jira_issue.fields.reporter.displayName
            if hasattr(jira_issue.fields, "reporter") and jira_issue.fields.reporter
            else None,
            "comments": [
                {
                    "id": comment.id,
                    "body": comment.body,
                    "author": comment.author.displayName,
                }
                for comment in jira_issue.fields.comment.comments
            ]
            if hasattr(jira_issue.fields, "comment") and jira_issue.fields.comment
            else [],
            "attachments": [
                {"id": attachment.id, "filename": attachment.filename}
                for attachment in jira_issue.fields.attachment
            ]
            if hasattr(jira_issue.fields, "attachment") and jira_issue.fields.attachment
            else [],
            "issuelinks": [
                {
                    "id": issue_link.id,
                    "type": issue_link.type.name,
                    "inwardIssue": issue_link.inwardIssue,
                    "outwardIssue": issue_link.outwardIssue,
                }
                for issue_link in jira_issue.fields.issuelinks
            ]
            if hasattr(jira_issue.fields, "issuelinks") and jira_issue.fields.issuelinks
            else [],
            "issueType": jira_issue.fields.issuetype.name
            if hasattr(jira_issue.fields, "issuetype") and jira_issue.fields.issuetype
            else None,
            "project": jira_issue.fields.project.name
            if hasattr(jira_issue.fields, "project") and jira_issue.fields.project
            else None,
            "resolution": jira_issue.fields.resolution.name
            if hasattr(jira_issue.fields, "resolution") and jira_issue.fields.resolution
            else None,
        }
        return issue_dict
    except Exception as e:
        logger.error(f"Error extracting Jira issue details: {str(e)}")
        # Return minimal details if extraction fails
        return {
            "id": jira_issue.id if hasattr(jira_issue, "id") else None,
            "key": jira_issue.key if hasattr(jira_issue, "key") else None,
            "error": str(e),
        }


def json_datetime_encoder(obj: Any) -> str:
    """JSON encoder for datetime objects.

    Args:
        obj (Any): Object to encode

    Returns:
        str: String representation of datetime or raises TypeError
    """
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler to process security incidents.

    Args:
        event (Dict[str, Any]): Lambda event object
        context (Any): Lambda context object

    Returns:
        Dict[str, Any]: Dictionary containing response status and details
    """
    EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "security-ir")
    JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task")

    # Get the Jira project key from SSM parameter store
    try:
        ssm_client = boto3.client("ssm")
        JIRA_PROJECT_KEY = ssm_client.get_parameter(
            Name=os.environ.get("JIRA_PROJECT_KEY")
        )["Parameter"]["Value"]
    except Exception as e:
        logger.error(f"Error retrieving Jira project key from SSM: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps("Error retrieving Jira project key from SSM"),
        }

    # Only process events from Security Incident Response
    if event.get("source") == EVENT_SOURCE:
        incident_service = IncidentService()
        incident_service.create_or_update_issue(
            event, JIRA_PROJECT_KEY, JIRA_ISSUE_TYPE
        )
    else:
        logger.info(
            "Jira Client lambda will skip processing of this event as the event source is not security-ir"
        )

    return {
        "statusCode": 200,
        "body": json.dumps("Jira Client Lambda function execution complete"),
    }

"""
Jira Notifications Handler Lambda function for AWS Security Incident Response integration.
This module processes notifications from Jira and publishes events to EventBridge.
"""

import json
import html
import os
import datetime
import traceback
import logging
from typing import Dict, Any, Optional, List

from boto3 import client, resource
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from jira_wrapper import JiraClient
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..wrappers.python.jira_wrapper import JiraClient

# Constants
EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "jira")

# Initialize logger
logger = Logger()

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
events_client = client("events")
dynamodb = resource("dynamodb")


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""

    def default(self, obj):
        """Convert datetime objects to ISO format strings.

        Args:
            obj: Object to encode

        Returns:
            str: ISO formatted datetime string or default encoding
        """
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        return super().default(obj)


class BaseEvent:
    """Base class for domain events."""

    event_type = None
    event_source = EVENT_SOURCE

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the event
        """
        raise NotImplementedError("Subclasses must implement to_dict()")


class IssueCreatedEvent(BaseEvent):
    """Domain event for issue creation."""

    event_type = "IssueCreated"

    def __init__(self, issue: Dict[str, Any]):
        """Initialize an IssueCreatedEvent.

        Args:
            issue (Dict[str, Any]): The issue details dictionary
        """
        self.issue = issue

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            "id": self.issue.get("id", ""),
            "key": self.issue.get("key", ""),
            "summary": self.issue.get("summary", ""),
            "status": self.issue.get("status", ""),
            "updated": self.issue.get("updated", ""),
            "created": self.issue.get("created", ""),
            "description": self.issue.get("description", ""),
            "priority": self.issue.get("priority", ""),
            "assignee": self.issue.get("assignee", ""),
            "reporter": self.issue.get("reporter", ""),
            "comments": self.issue.get("comments", []),
            "attachments": self.issue.get("attachments", []),
            "issueType": self.issue.get("issuetype", ""),
            "project": self.issue.get("project", ""),
            "resolution": self.issue.get("resolution", ""),
            "securityLevel": self.issue.get("securityLevel", ""),
        }


class IssueUpdatedEvent(BaseEvent):
    """Domain event for issue update."""

    event_type = "IssueUpdated"

    def __init__(self, issue: Dict[str, Any]):
        """Initialize an IssueUpdatedEvent.

        Args:
            issue (Dict[str, Any]): The issue details dictionary
        """
        self.issue = issue

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            "id": self.issue.get("id", ""),
            "key": self.issue.get("key", ""),
            "summary": self.issue.get("summary", ""),
            "status": self.issue.get("status", ""),
            "updated": self.issue.get("updated", ""),
            "created": self.issue.get("created", ""),
            "description": self.issue.get("description", ""),
            "priority": self.issue.get("priority", ""),
            "assignee": self.issue.get("assignee", ""),
            "reporter": self.issue.get("reporter", ""),
            "comments": self.issue.get("comments", []),
            "attachments": self.issue.get("attachments", []),
            "issueLinks": self.issue.get("issuelinks", []),
            "issueType": self.issue.get("issuetype", ""),
            "project": self.issue.get("project", ""),
            "resolution": self.issue.get("resolution", ""),
        }


class IssueDeletedEvent(BaseEvent):
    """Domain event for issue deletion."""

    event_type = "IssueDeleted"

    def __init__(self, issue_id: str):
        """Initialize an IssueDeletedEvent.

        Args:
            issue_id (str): The ID of the issue that was deleted
        """
        self.issue_id = issue_id

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            "issueId": self.issue_id,
        }


class EventPublisherService:
    """Service for publishing events to EventBridge."""

    def __init__(self, event_bus_name: str):
        """Initialize an EventPublisherService.

        Args:
            event_bus_name (str): Name of the EventBridge event bus
        """
        logger.debug(
            f"Initializing EventPublisherService with event bus: {event_bus_name}"
        )
        self.events_client = events_client
        self.event_bus_name = event_bus_name

    def publish_event(self, event: BaseEvent) -> Dict[str, Any]:
        """Publish an event to the EventBridge event bus.

        Args:
            event (BaseEvent): The event to publish

        Returns:
            Dict[str, Any]: Response from EventBridge
        """
        logger.info(f"Publishing event: {event.event_type}")
        event_dict = event.to_dict()

        try:
            # Convert the dictionary to a JSON string
            event_json = json.dumps(event_dict, cls=DateTimeEncoder)

            response = self.events_client.put_events(
                Entries=[
                    {
                        "Source": EVENT_SOURCE,
                        "DetailType": event.event_type,
                        "Detail": event_json,
                        "EventBusName": self.event_bus_name,
                    }
                ]
            )
            logger.info(f"Event {event.event_type} published successfully")
            logger.debug(f"Event published successfully: {response}")
            return response
        except Exception as e:
            logger.error(f"Error publishing event: {str(e)}")
            logger.error(traceback.format_exc())
            raise


class DatabaseService:
    """Service for database operations."""

    def __init__(self):
        """Initialize the database service"""
        self.table_name = os.environ["INCIDENTS_TABLE_NAME"]
        self.table = dynamodb.Table(self.table_name)

    def get_issue_details(self, jira_issue_id: str) -> Optional[str]:
        """Get Jira issue details from the database.

        Args:
            jira_issue_id (str): The Jira issue ID

        Returns:
            Optional[str]: Jira issue details or None if not found
        """
        try:
            items = self.get_issue_by_id(jira_issue_id)
            if not items:
                logger.info(f"Issue details for {jira_issue_id} not found in database.")
                return None

            jira_issue_details = items[0]["jiraIssueDetails"]
            logger.info(f"Issue details for {jira_issue_id} found in database.")
            return jira_issue_details
        except Exception as e:
            logger.error(f"Error retrieving details from the DynamoDB table: {e}")
            return None

    def get_issue_by_id(self, jira_issue_id: str) -> List[Dict[str, Any]]:
        """Scan DynamoDB table for Jira issue ID.

        Args:
            jira_issue_id (str): The Jira issue ID

        Returns:
            List[Dict[str, Any]]: List of matching items
        """
        try:
            response = self.table.scan(
                FilterExpression=Attr("jiraIssueId").eq(jira_issue_id)
            )
            items = response["Items"]

            # Handle pagination if there are more items
            while "LastEvaluatedKey" in response:
                response = self.table.scan(
                    FilterExpression=Attr("jiraIssueId").eq(jira_issue_id),
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                items.extend(response["Items"])
            return items
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(
                f"Error retrieving details from the DynamoDB table: {error_code}"
            )
            return []
        except KeyError:
            logger.error(f"Jira issue for {jira_issue_id} not found in database")
            return []

    def add_issue_details(
        self, jira_issue_id: str, jira_issue_details: Dict[str, Any]
    ) -> bool:
        """Create a new entry with Jira issue details.

        Args:
            jira_issue_id (str): The Jira issue ID
            jira_issue_details (Dict[str, Any]): The Jira issue details

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Convert the issue details to a JSON string for storage
            jira_details_json = json.dumps(jira_issue_details)

            # Use a composite key pattern with a prefix to maintain data model integrity
            case_id = f"Jira#{jira_issue_id}"

            # Create a new entry with the Jira issue ID and details
            logger.info(
                f"Creating a new entry with CaseId {case_id} for Jira issue {jira_issue_id} in DynamoDb table"
            )
            self.table.put_item(
                Item={
                    "PK": case_id,
                    "SK": "latest",
                    "jiraIssueId": jira_issue_id,
                    "jiraIssueDetails": jira_details_json,
                }
            )

            logger.info(
                f"Successfully added details to DynamoDb table for Jira issue {jira_issue_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Error adding details to DynamoDb table for Jira issue {jira_issue_id}: {str(e)}"
            )
            return False


class JiraService:
    """Service for Jira operations."""

    def __init__(self):
        """Initialize the Jira service"""
        self.jira_client = JiraClient()

    def get_issue_details(self, jira_issue_id: str) -> Optional[Dict[str, Any]]:
        """Get issue details from Jira.

        Args:
            jira_issue_id (str): The Jira issue ID

        Returns:
            Optional[Dict[str, Any]]: Dictionary of issue details or None if retrieval fails
        """
        try:
            jira_issue = self.jira_client.get_issue(jira_issue_id)
            if not jira_issue:
                logger.error(f"Failed to get issue {jira_issue_id} from Jira")
                return None

            return self.extract_issue_details(jira_issue)
        except Exception as e:
            logger.error(f"Error getting issue details from Jira: {str(e)}")
            return None

    def extract_issue_details(self, jira_issue: Any) -> Dict[str, Any]:
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
                if hasattr(jira_issue.fields, "attachment")
                and jira_issue.fields.attachment
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
                if hasattr(jira_issue.fields, "issuelinks")
                and jira_issue.fields.issuelinks
                else [],
                "issuetype": jira_issue.fields.issuetype.name
                if hasattr(jira_issue.fields, "issuetype")
                and jira_issue.fields.issuetype
                else None,
                "project": jira_issue.fields.project.name
                if hasattr(jira_issue.fields, "project") and jira_issue.fields.project
                else None,
                "resolution": jira_issue.fields.resolution.name
                if hasattr(jira_issue.fields, "resolution")
                and jira_issue.fields.resolution
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


class SNSMessageProcessorService:
    """Class to handle SNS message processing."""

    def __init__(self):
        """Initialize the SNS message processor"""
        self.db_service = DatabaseService()
        self.jira_service = JiraService()

    def parse_message(self, message: str) -> Dict[str, Any]:
        """Parse a JSON string message from SNS.

        Args:
            message (str): The message string to parse

        Returns:
            Dict[str, Any]: Dictionary containing parsed message or empty dict if parsing fails
        """
        try:
            return json.loads(message)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SNS message: {str(e)}")
            return {}

    def extract_automation_data(
        self, message: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Extract automation data from parsed message.

        Args:
            message (Dict[str, Any]): Parsed message dictionary

        Returns:
            Optional[Dict[str, Any]]: Automation data if found, None otherwise
        """
        return message.get("automationData")

    def process_automation_data(
        self, automation_data: Dict[str, Any], event_bus_name: str = "default"
    ) -> bool:
        """Process the automation data.

        Args:
            automation_data (Dict[str, Any]): The automation data to process
            event_bus_name (str): Name of the EventBridge event bus

        Returns:
            bool: True if processing was successful, False otherwise
        """
        if not automation_data:
            logger.warning("No data received in Jira event")
            return False

        try:
            # Log the automation data (sanitized)
            logger.info(
                f"Processing automation data: {html.escape(json.dumps(automation_data))}"
            )

            # Create an EventPublisherService instance
            event_publisher = EventPublisherService(event_bus_name)

            # Get Jira issue ID from the automation data
            jira_issue_id = automation_data.get("IssueId")
            if not jira_issue_id:
                logger.error("No IssueId found in automation data")
                return False

            # Get Jira issue details from Jira first
            jira_issue_details = self.jira_service.get_issue_details(jira_issue_id)
            if not jira_issue_details:
                logger.error(
                    f"Failed to get issue details for {jira_issue_id} from Jira"
                )
                return False

            # Get Jira issue details from database
            jira_issue_details_ddb = self.db_service.get_issue_details(jira_issue_id)

            # If issue not found in database, publish created event and update the database
            if not jira_issue_details_ddb:
                logger.info(
                    f"Jira issue details for {jira_issue_id} not found in database"
                )
                # Update the database with the Jira issue ID and details
                try:
                    # Use a composite key pattern to maintain data model integrity
                    self.db_service.add_issue_details(jira_issue_id, jira_issue_details)
                    event_publisher.publish_event(IssueCreatedEvent(jira_issue_details))
                    return True
                except Exception as e:
                    logger.error(
                        f"Error updating database with Jira issue details: {str(e)}"
                    )
                    return False

            # Compare issue details to detect changes
            jira_details_json = json.dumps(jira_issue_details)
            if json.loads(jira_details_json) != json.loads(jira_issue_details_ddb):
                logger.info(f"Jira issue details for {jira_issue_id} have changed")
                event_publisher.publish_event(IssueUpdatedEvent(jira_issue_details))
                return True

            logger.info(f"No changes detected for issue {jira_issue_id}")
            return True

        except Exception as e:
            logger.error(f"Error processing automation data: {str(e)}")
            logger.error(traceback.format_exc())
            return False


class ResponseBuilderService:
    """Class to handle response building."""

    @staticmethod
    def build_success_response(message: str) -> Dict[str, Any]:
        """Build a success response.

        Args:
            message (str): Success message

        Returns:
            Dict[str, Any]: API Gateway compatible response
        """
        return {"statusCode": 200, "body": json.dumps({"message": message})}

    @staticmethod
    def build_error_response(error: str) -> Dict[str, Any]:
        """Build an error response.

        Args:
            error (str): Error message

        Returns:
            Dict[str, Any]: API Gateway compatible response
        """
        return {"statusCode": 500, "body": json.dumps({"error": error})}


@logger.inject_lambda_context
def handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """Lambda handler for processing SNS notifications.

    Args:
        event (Dict[str, Any]): The Lambda event
        context (LambdaContext): The Lambda context

    Returns:
        Dict[str, Any]: API Gateway compatible response
    """
    try:
        # Log incoming event
        logger.info(f"Received event: {json.dumps(event)}")

        # Validate event structure
        if not isinstance(event, dict):
            raise ValueError(f"Expected dict event, got {type(event)}")

        # Get records from the event
        records = event.get("Records", [])

        if not records:
            logger.info("No records found in event")
            return ResponseBuilderService.build_success_response(
                "No records to process"
            )

        # Create processor
        processor = SNSMessageProcessorService()
        processed_count = 0

        # Parse the SNS topic message
        message = processor.parse_message(records[0]["Sns"]["Message"])

        # Extract the automation data from the SNS topic parsed message
        automation_data = processor.extract_automation_data(message)

        # Process automation data
        event_bus_name = os.environ.get("EVENT_BUS_NAME", "default")
        success = processor.process_automation_data(automation_data, event_bus_name)

        if success:
            processed_count += 1

        return ResponseBuilderService.build_success_response(
            f"Successfully processed {processed_count} records"
        )

    except Exception as e:
        logger.error(f"Error in Lambda handler: {str(e)}")
        logger.error(traceback.format_exc())
        return ResponseBuilderService.build_error_response(str(e))

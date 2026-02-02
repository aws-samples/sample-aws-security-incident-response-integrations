"""Security IR Poller Lambda function for AWS Security Incident Response integration.

This module polls AWS Security Incident Response for case updates and publishes
events to EventBridge. It implements adaptive polling based on the number of
active incidents and stores case data in DynamoDB for tracking changes.

Key Features:
- Polls Security IR API for case updates
- Publishes CaseCreated/CaseUpdated events to EventBridge
- Adaptive polling frequency based on active incident count
- Stores case data in DynamoDB for change detection
- Handles pagination for large case lists
"""

import datetime
import json
import boto3
import os
import logging
import traceback

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


# Import types
from typing import List, Dict, Optional, Any

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from models import Case, create_case_from_api_response
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..domain.python.models import create_case_from_api_response

# Constants
DEFAULT_MAX_RESULTS = 25
SCHEDULE_EXPRESSIONS = {
    "FAST_POLLING": "rate(1 minute)",
    "NORMAL_POLLING": "rate(5 minutes)",
}
EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "security-ir")

# Initialize AWS clients
logger.debug("Initializing boto3 clients")
dynamodb_client = boto3.client("dynamodb")
security_ir_client = boto3.client("security-ir")
events_client = boto3.client("events")
lambda_client = boto3.client("lambda")


# Domain events
class CaseCreatedEvent:
    """Domain event for case creation."""

    event_type = "CaseCreated"
    event_source = EVENT_SOURCE

    def __init__(self, case):
        """Initialize a CaseCreatedEvent.

        Args:
            case (Case): The case that was created
        """
        self.case = case

    def to_dict(self):
        """Convert the event to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the event
        """
        case_dict = self.case.to_dict()
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            # 'case': case_dict,
            "title": case_dict.get("title", ""),
            "caseId": case_dict.get("caseId", ""),
            "caseArn": case_dict.get("caseArn", ""),
            "description": case_dict.get("description", ""),
            "caseStatus": case_dict.get("status", ""),
            "engagementType": case_dict.get("engagementType", ""),
            "reportedIncidentStartDate": case_dict.get("reportedIncidentStartDate", ""),
            "impactedAwsRegions": case_dict.get("impactedAwsRegions", []),
            "threatActorIpAddresses": case_dict.get("threatActorIpAddresses", []),
            "pendingAction": case_dict.get("pendingAction", ""),
            "impactedAccounts": case_dict.get("impactedAccounts", []),
            "watchers": case_dict.get("watchers", []),
            "createdDate": case_dict.get("createdAt", ""),
            "lastUpdatedDate": case_dict.get("updatedAt", ""),
            "resolverType": case_dict.get("resolverType", ""),
            "impactedServices": case_dict.get("impactedServices", []),
            "caseAttachments": case_dict.get("caseAttachments", []),
            "caseComments": case_dict.get("caseComments", []),
        }


class CaseUpdatedEvent:
    """Domain event for case update."""

    event_type = "CaseUpdated"
    event_source = EVENT_SOURCE

    def __init__(self, case):
        """Initialize a CaseUpdatedEvent.

        Args:
            case (Case): The case that was updated
        """
        self.case = case
        # self.updated_fields = updated_fields

    def to_dict(self):
        """Convert the event to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the event
        """
        case_dict = self.case.to_dict()
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            #'case': case_dict,
            "title": case_dict.get("title", ""),
            "caseId": case_dict.get("caseId", ""),
            "caseArn": case_dict.get("caseArn", ""),
            "description": case_dict.get("description", ""),
            "caseStatus": case_dict.get("status", ""),
            "engagementType": case_dict.get("engagementType", ""),
            "reportedIncidentStartDate": case_dict.get("reportedIncidentStartDate", ""),
            "impactedAwsRegions": case_dict.get("impactedAwsRegions", []),
            "threatActorIpAddresses": case_dict.get("threatActorIpAddresses", []),
            "pendingAction": case_dict.get("pendingAction", ""),
            "impactedAccounts": case_dict.get("impactedAccounts", []),
            "watchers": case_dict.get("watchers", []),
            "createdDate": case_dict.get("createdAt", ""),
            "lastUpdatedDate": case_dict.get("updatedAt", ""),
            "resolverType": case_dict.get("resolverType", ""),
            "impactedServices": case_dict.get("impactedServices", []),
            "caseAttachments": case_dict.get("caseAttachments", []),
            "caseComments": case_dict.get("caseComments", []),
            # 'updatedFields': self.updated_fields
        }


class CaseDeletedEvent:
    """Domain event for case deletion."""

    event_type = "CaseDeleted"
    event_source = EVENT_SOURCE

    def __init__(self, case_id):
        """Initialize a CaseDeletedEvent.

        Args:
            case_id (str): The ID of the case that was deleted
        """
        self.case_id = case_id

    def to_dict(self):
        """Convert the event to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the event
        """
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            "caseId": self.case_id,
        }


class EventPublisher:
    """Service for publishing events to EventBridge."""

    def __init__(self, event_bus_name):
        """Initialize an EventPublisher.

        Args:
            event_bus_name (str): Name of the EventBridge event bus
        """
        logger.debug(f"Initializing EventPublisher with event bus: {event_bus_name}")
        self.events_client = (
            events_client  # Use module-level client instead of creating a new one
        )
        self.event_bus_name = event_bus_name

    def publish_event(self, event):
        """Publish an event to the EventBridge event bus.

        Args:
            event: The event to publish

        Returns:
            Dict[str, Any]: Response from EventBridge
        """
        logger.info(f"Publishing event: {event.event_type}")
        logger.debug(f"Publishing event of type: {event.event_type}")
        event_dict = self._convert_event_to_dict(event)

        try:
            response = self.events_client.put_events(
                Entries=[
                    {
                        "Source": EVENT_SOURCE,
                        "DetailType": event.event_type,
                        "Detail": json.dumps(event_dict, cls=DateTimeEncoder),
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

    def _convert_event_to_dict(self, event) -> dict:
        """Convert an event object to a dictionary.

        Args:
            event: The event to convert

        Returns:
            dict: Dictionary representation of the event
        """
        return event.to_dict()


# Utility functions
class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects."""

    def default(self, obj):
        """Convert datetime objects to ISO format strings.

        Args:
            obj: Object to encode

        Returns:
            str: ISO formatted datetime string or default encoding
        """
        if isinstance(obj, (datetime.datetime,)):  # Note the comma to create a tuple
            return obj.strftime("%Y-%m-%dT%H:%M:%SZ")
        return super().default(obj)


def json_datetime_encoder(obj: Any) -> str:
    """
    Custom JSON encoder for datetime objects.

    Args:
        obj (Any): Object to encode

    Returns:
        str: ISO formatted datetime string

    Raises:
        TypeError: If object is not JSON serializable
    """
    if isinstance(obj, datetime.datetime):
        return obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def get_incidents_from_security_ir() -> Optional[List[Dict[str, Any]]]:
    """Fetch all incidents from Security Incident Response with pagination support.

    Returns:
        Optional[List[Dict[str, Any]]]: List of incidents or None if error occurs
    """
    pagination_token = None
    incidents = []

    try:
        while True:
            request_kwargs = {"maxResults": DEFAULT_MAX_RESULTS}
            if pagination_token:
                request_kwargs["nextToken"] = pagination_token

            response = security_ir_client.list_cases(**request_kwargs)

            if "items" in response:
                incidents.extend(response["items"])

            if "nextToken" not in response:
                break
            pagination_token = response["nextToken"]

        return incidents
    except Exception as e:
        print(f"Error retrieving incidents from Security Incident Response: {e}")
        return None


def get_number_of_active_incidents(incidents: List[Dict[str, Any]]) -> Optional[int]:
    """
    Count number of active (non-closed) incidents.

    Args:
        incidents (List[Dict[str, Any]]): List of incidents to check

    Returns:
        Optional[int]: Count of active incidents or None if error occurs
    """
    try:
        active_incidents = [
            incident for incident in incidents if incident["caseStatus"] != "Closed"
        ]
        return len(active_incidents)
    except Exception as e:
        print(f"Error retrieving the number of active incidents: {e}")
        return None


def update_polling_schedule_rate(rule_name: str, schedule_rate: str) -> Dict[str, Any]:
    """
    Update EventBridge rule schedule rate.

    Args:
        rule_name (str): Name of the EventBridge rule
        schedule_rate (str): New schedule rate expression

    Returns:
        Dict[str, Any]: Response from EventBridge put_rule API
    """
    try:
        return events_client.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_rate,
        )
    except Exception as e:
        print(f"Error updating polling schedule rate: {str(e)}")
        raise


def get_incident_details(case_id: str) -> Dict[str, Any]:
    """
    Get detailed information for a specific incident.

    Args:
        case_id (str): ID of the case to retrieve

    Returns:
        Dict[str, Any]: Dictionary containing case details and comments
    """
    incident_request_kwargs = {"caseId": case_id}
    case_details = security_ir_client.get_case(**incident_request_kwargs)
    case_comments = security_ir_client.list_comments(**incident_request_kwargs)

    return {**case_details, "caseComments": case_comments.get("items", [])}


def remove_keys(data: Any, keys_to_exclude: List[str]) -> Any:
    """Remove specified keys from nested data structures.

    Args:
        data (Any): Data structure to process (dict, list, or other)
        keys_to_exclude (List[str]): Keys to exclude from dictionaries

    Returns:
        Any: Processed data structure with specified keys removed
    """
    if isinstance(data, dict):
        return {
            k: remove_keys(v, keys_to_exclude)
            for k, v in data.items()
            if k not in keys_to_exclude
        }
    elif isinstance(data, list):
        return [remove_keys(item, keys_to_exclude) for item in data]
    else:
        return data


def is_slack_originated_update(case_id: str, table_name: str) -> bool:
    """
    Check if a case update originated from Slack to prevent notification loops.
    
    Args:
        case_id (str): Case ID to check
        table_name (str): DynamoDB table name
        
    Returns:
        bool: True if update originated from Slack, False otherwise
    """
    try:
        response = dynamodb_client.get_item(
            TableName=table_name,
            Key={"PK": {"S": f"Case#{case_id}"}, "SK": {"S": "slack_update_flag"}}
        )
        
        if "Item" in response:
            # Flag exists, delete it and return True
            dynamodb_client.delete_item(
                TableName=table_name,
                Key={"PK": {"S": f"Case#{case_id}"}, "SK": {"S": "slack_update_flag"}}
            )
            logger.info(f"Detected Slack-originated update for case {case_id}, skipping notification")
            return True
            
        return False
    except Exception as e:
        logger.warning(f"Error checking Slack update flag for case {case_id}: {str(e)}")
        return False


def store_incidents_in_dynamodb(
    incidents: List[Dict[str, Any]], table_name: str, event_bus_name: str = "default"
) -> bool:
    """
    Store or update incidents in DynamoDB.

    Args:
        incidents (List[Dict[str, Any]]): List of incidents to store
        table_name (str): Name of the DynamoDB table
        event_bus_name (str): Name of the EventBridge event bus

    Returns:
        bool: Boolean indicating success or failure
    """
    # Create an EventPublisher instance
    event_publisher = EventPublisher(event_bus_name)

    if not incidents or not table_name:
        logger.warning("No incidents or table name provided")
        return False

    try:
        for incident in incidents:
            case_id = incident["caseId"]
            case_status = incident["caseStatus"]

            if case_status != "Closed":
                # skip closed incidents
                print(f"Processing incident id: {case_id}")

                # Check if incident exists in DynamoDB
                existing_incident = dynamodb_client.get_item(
                    TableName=table_name,
                    Key={"PK": {"S": f"Case#{case_id}"}, "SK": {"S": "latest"}},
                ).get("Item", {})

                # Get full incident details
                incident_details = get_incident_details(case_id)

                # Convert to domain models
                logger.debug(f"Converting case {case_id} to domain models")
                case = create_case_from_api_response(incident_details)

                if existing_incident:
                    # Update existing incident if details have changed
                    existing_details = json.loads(
                        existing_incident.get("incidentDetails", {}).get("S", "{}")
                    )
                    logger.info(f"Existing case details from DDB: {existing_details}")
                    logger.info(f"Latest case details from SIR: {incident_details}")

                    # Exclude keys that may be ignored while comparing the existing case details in DDB and in SIR
                    keys_to_ignore_for_comparison = [
                        "RequestId",
                        "date",
                        "x-amzn-requestid",
                        "x-amz-apigw-id",
                        "x-amzn-trace-id",
                        "reportedIncidentStartDate",
                        "createdDate",
                        "lastUpdatedDate",
                    ]
                    existing_details_for_comparison = remove_keys(
                        existing_details, keys_to_ignore_for_comparison
                    )
                    incident_details_for_comparison = remove_keys(
                        incident_details, keys_to_ignore_for_comparison
                    )
                    logger.info(
                        f"Existing case details from DDB with fields excluded for comparison: {existing_details_for_comparison}"
                    )
                    logger.info(
                        f"Latest case details from SIR with fields excluded for comparison: {incident_details_for_comparison}"
                    )

                    # Compare if the case details from SIR are the same as the existing details in DDB
                    if (
                        existing_details_for_comparison
                        != incident_details_for_comparison
                    ):
                        dynamodb_client.update_item(
                            TableName=table_name,
                            Key={"PK": {"S": f"Case#{case_id}"}, "SK": {"S": "latest"}},
                            UpdateExpression="SET incidentDetails = :incidentDetails",
                            ExpressionAttributeValues={
                                ":incidentDetails": {
                                    "S": json.dumps(
                                        incident_details, default=json_datetime_encoder
                                    )
                                }
                            },
                        )

                        # Check if this update originated from Slack to prevent notification loops
                        if not is_slack_originated_update(case_id, table_name):
                            logger.info(f"Publishing CaseUpdatedEvent for: {case_id}")
                            event_publisher.publish_event(CaseUpdatedEvent(case))
                        else:
                            logger.info(f"Skipping CaseUpdatedEvent for Slack-originated update: {case_id}")
                else:
                    # Create new incident
                    dynamodb_client.put_item(
                        TableName=table_name,
                        Item={
                            "PK": {"S": f"Case#{case_id}"},
                            "SK": {"S": "latest"},
                            "incidentDetails": {
                                "S": json.dumps(
                                    incident_details, default=json_datetime_encoder
                                )
                            },
                        },
                    )
                    logger.info(f"Publishing CaseCreatedEvent for: {case_id}")
                    event_publisher.publish_event(CaseCreatedEvent(case))

        return True
    except Exception as e:
        logger.error(f"Error storing incidents in DynamoDB: {str(e)}")
        logger.error(traceback.format_exc())
        return False


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler to process security incidents.

    Polls Security IR for incidents, stores them in DynamoDB, and publishes events.
    Adjusts polling frequency based on number of active incidents.

    Args:
        event (Dict[str, Any]): Lambda event object containing EventBridge rule information
        context (Any): Lambda context object

    Returns:
        Dict[str, Any]: Dictionary containing response status and details
    """
    # Get configuration
    table_name = os.environ.get("INCIDENTS_TABLE_NAME")
    rule_name = event["resources"][0].split("/")[-1]
    event_bus_name = os.environ.get("EVENT_BUS_NAME", "default")

    print(f"Processing incidents for rule: {rule_name}")

    # Get and process incidents
    incidents = get_incidents_from_security_ir()
    if not incidents:
        print("No incidents retrieved")
        update_polling_schedule_rate(rule_name, SCHEDULE_EXPRESSIONS["NORMAL_POLLING"])
        return {
            "statusCode": 200,
            "body": {"message": "No incidents to process", "count": 0},
        }

    # Update polling schedule based on active incidents
    active_count = get_number_of_active_incidents(incidents)
    if active_count and active_count > 0:
        update_polling_schedule_rate(rule_name, SCHEDULE_EXPRESSIONS["FAST_POLLING"])
    else:
        update_polling_schedule_rate(rule_name, SCHEDULE_EXPRESSIONS["NORMAL_POLLING"])

    # Store incidents
    if not store_incidents_in_dynamodb(incidents, table_name, event_bus_name):
        raise Exception("Failed to store incidents")

    return {
        "statusCode": 200,
        "body": {
            "message": "Successfully processed incidents",
            "count": len(incidents),
        },
    }

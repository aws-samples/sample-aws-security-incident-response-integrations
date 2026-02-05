"""
ServiceNow Notifications Handler Lambda function for AWS Security Incident Response integration.
This module processes notifications from ServiceNow and publishes events to EventBridge.
"""

import json
import os
import datetime
import time
import traceback
import logging
from typing import Dict, Any, Optional, List
import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from aws_lambda_powertools.utilities.typing import LambdaContext

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from service_now_wrapper import ServiceNowClient
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..wrappers.python.service_now_wrapper import ServiceNowClient

# Constants
EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "service-now")

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Set to INFO first

# Get log level from environment variable
log_level = os.environ.get("LOG_LEVEL", "info").lower()
print(f"LOG_LEVEL environment variable: {log_level}")  # Debug print
if log_level == "debug":
    logger.setLevel(logging.DEBUG)
elif log_level == "info":
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

print(f"Logger level set to: {logger.level}")  # Debug print

# Initialize AWS clients
events_client = boto3.client("events")
dynamodb = boto3.resource("dynamodb")


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


class IncidentCreatedEvent(BaseEvent):
    """Domain event for incident creation."""

    event_type = "IncidentCreated"

    def __init__(self, incident: Dict[str, Any]):
        """Initialize an IncidentCreatedEvent.

        Args:
            incident (Dict[str, Any]): The incident details dictionary
        """
        self.incident = incident

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            "sys_id": self.incident.get("sys_id", ""),
            "number": self.incident.get("number", ""),
            "short_description": self.incident.get("short_description", ""),
            "description": self.incident.get("description", ""),
            "sys_created_on": self.incident.get("sys_created_on", ""),
            "sys_created_by": self.incident.get("sys_created_by", ""),
            "resolved_by": self.incident.get("resolved_by", ""),
            "resolved_at": self.incident.get("resolved_at", ""),
            "opened_at": self.incident.get("opened_at", ""),
            "closed_at": self.incident.get("closed_at", ""),
            "state": self.incident.get("state", ""),
            "impact": self.incident.get("impact", ""),
            "active": self.incident.get("active", ""),
            "priority": self.incident.get("priority", ""),
            "caller_id": self.incident.get("caller_id", ""),
            "urgency": self.incident.get("urgency", ""),
            "severity": self.incident.get("severity", ""),
            "comments": self.incident.get("comments", ""),
            "work_notes": self.incident.get("work_notes", ""),
            "comments_and_work_notes": self.incident.get("comments_and_work_notes", ""),
            "close_code": self.incident.get("close_code", ""),
            "close_notes": self.incident.get("close_notes", ""),
            "closed_by": self.incident.get("closed_by", ""),
            "reopened_by": self.incident.get("reopened_by", ""),
            "assigned_to": self.incident.get("assigned_to", ""),
            "due_date": self.incident.get("due_date", ""),
            "sys_tags": self.incident.get("sys_tags", ""),
            "category": self.incident.get("category", ""),
            "subcategory": self.incident.get("subcategory", ""),
            "attachments": self.incident.get("attachments", []),
        }


class IncidentUpdatedEvent(BaseEvent):
    """Domain event for incident update."""

    event_type = "IncidentUpdated"

    def __init__(self, incident: Dict[str, Any]):
        """Initialize an IncidentUpdatedEvent.

        Args:
            incident (Dict[str, Any]): The incident details dictionary
        """
        self.incident = incident

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            "sys_id": self.incident.get("sys_id", ""),
            "number": self.incident.get("number", ""),
            "short_description": self.incident.get("short_description", ""),
            "description": self.incident.get("description", ""),
            "sys_created_on": self.incident.get("sys_created_on", ""),
            "sys_created_by": self.incident.get("sys_created_by", ""),
            "resolved_by": self.incident.get("resolved_by", ""),
            "resolved_at": self.incident.get("resolved_at", ""),
            "opened_at": self.incident.get("opened_at", ""),
            "closed_at": self.incident.get("closed_at", ""),
            "state": self.incident.get("state", ""),
            "impact": self.incident.get("impact", ""),
            "active": self.incident.get("active", ""),
            "priority": self.incident.get("priority", ""),
            "caller_id": self.incident.get("caller_id", ""),
            "urgency": self.incident.get("urgency", ""),
            "severity": self.incident.get("severity", ""),
            "comments": self.incident.get("comments", ""),
            "work_notes": self.incident.get("work_notes", ""),
            "comments_and_work_notes": self.incident.get("comments_and_work_notes", ""),
            "close_code": self.incident.get("close_code", ""),
            "close_notes": self.incident.get("close_notes", ""),
            "closed_by": self.incident.get("closed_by", ""),
            "reopened_by": self.incident.get("reopened_by", ""),
            "assigned_to": self.incident.get("assigned_to", ""),
            "due_date": self.incident.get("due_date", ""),
            "sys_tags": self.incident.get("sys_tags", ""),
            "category": self.incident.get("category", ""),
            "subcategory": self.incident.get("subcategory", ""),
            "attachments": self.incident.get("attachments", []),
        }


class IncidentDeletedEvent(BaseEvent):
    """Domain event for incident deletion."""

    event_type = "IncidentDeleted"

    def __init__(self, incident_id: str):
        """Initialize an IncidentDeletedEvent.

        Args:
            incident_id (str): The ID of the incident that was deleted
        """
        self.incident_id = incident_id

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            "eventType": self.event_type,
            "eventSource": self.event_source,
            "incidentId": self.incident_id,
        }


class ParameterService:
    """Class to handle parameter operations."""

    def __init__(self):
        """Initialize the parameter service."""
        self.ssm_client = boto3.client("ssm")

    def _get_parameter(self, parameter_name: str) -> Optional[str]:
        """Get a parameter from SSM Parameter Store.

        Args:
            parameter_name (str): The name of the parameter to retrieve

        Returns:
            Optional[str]: Parameter value or None if retrieval fails
        """
        if not parameter_name:
            logger.error("Parameter name is empty or None")
            return None

        try:
            logger.info(f"Retrieving parameter: {parameter_name}")
            response = self.ssm_client.get_parameter(
                Name=parameter_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            if error_code == "AccessDeniedException":
                logger.error(
                    f"Access denied when retrieving parameter {parameter_name}. Check IAM permissions for this Lambda function."
                )
            elif error_code == "ParameterNotFound":
                logger.error(
                    f"Parameter {parameter_name} not found. Verify the parameter exists in SSM Parameter Store."
                )
            else:
                logger.error(
                    f"Error retrieving parameter {parameter_name}: {error_code} - {error_message}"
                )
            return None
        except Exception as e:
            logger.error(
                f"Unexpected error retrieving parameter {parameter_name}: {str(e)}"
            )
            return None


class EventPublisherService:
    """Service for publishing events to EventBridge."""

    def __init__(self, event_bus_name: str):
        """
        Initialize an EventPublisherService

        Args:
            event_bus_name: Name of the EventBridge event bus
        """
        logger.debug(
            f"Initializing EventPublisherService with event bus: {event_bus_name}"
        )
        self.events_client = events_client
        self.event_bus_name = event_bus_name

    def _publish_event(self, event: BaseEvent) -> Dict[str, Any]:
        """
        Publish an event to the EventBridge event bus

        Args:
            event: The event to publish

        Returns:
            Response from EventBridge
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
            raise


class DatabaseService:
    """Service for database operations."""

    def __init__(self, table_name):
        """Initialize the database service"""
        self.table = dynamodb.Table(table_name)

    def __should_retry(self, attempt: int, max_retries: int, wait_time: int) -> bool:
        """
        Check if should retry and handle wait time

        Args:
            attempt: Current attempt number
            max_retries: Maximum number of retries
            wait_time: Current wait time

        Returns:
            True if should retry, False otherwise
        """

        if attempt < max_retries - 1:
            logger.info(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)
            return True
        else:
            logger.error(f"All {max_retries} attempts failed")
            return False

    def __get_incident_by_id(
        self, service_now_incident_id: str, skip_retry: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Scan DynamoDB table for ServiceNow incident ID with optional retry logic

        Args:
            service_now_incident_id: The ServiceNow incident ID
            skip_retry: If True, perform a single lookup without retries (for IncidentCreated events)

        Returns:
            List of matching items or None if not found
        """
        max_retries = 1 if skip_retry else 5
        wait_time = 0 if skip_retry else 30
        
        if wait_time > 0:
            time.sleep(wait_time)

        for attempt in range(max_retries):
            try:
                # TODO: Use GSIs and replace the following scan queries to use the service-now index instead (see https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210189285892844?focus=true)
                
                response = self.table.scan(
                    FilterExpression="serviceNowIncidentId = :service_now_incident_id",
                    ExpressionAttributeValues={":service_now_incident_id": service_now_incident_id}
                )
                
                items = response.get("Items", [])
                
                # Handle pagination if there are more items
                while "LastEvaluatedKey" in response:
                    response = self.table.scan(
                        FilterExpression="serviceNowIncidentId = :service_now_incident_id",
                        ExpressionAttributeValues={":service_now_incident_id": service_now_incident_id},
                        ExclusiveStartKey=response["LastEvaluatedKey"],
                    )
                    items.extend(response.get("Items", []))

                if not items:
                    if skip_retry:
                        logger.info(
                            f"ServiceNow incident for {service_now_incident_id} not found in database (new incident)"
                        )
                        return None
                    logger.info(
                        f"ServiceNow incident for {service_now_incident_id} not found in database on attempt {attempt + 1}"
                    )
                    if not self.__should_retry(attempt, max_retries, wait_time):
                        return None
                    wait_time = max(5, wait_time - 5)  # Decrease by 5s, minimum 5s
                    continue

                # Loop through all items to find one with serviceNowIncidentDetails
                for item in items:
                    if "serviceNowIncidentDetails" in item:
                        logger.info(
                            f"ServiceNow incident for {service_now_incident_id} found in database. Extracting incident details."
                        )
                        return item["serviceNowIncidentDetails"]

                # If no item has serviceNowIncidentDetails, retry (unless skip_retry)
                if skip_retry:
                    logger.info(
                        f"ServiceNow incident for {service_now_incident_id} exists but missing serviceNowIncidentDetails (new incident)"
                    )
                    return None
                logger.info(
                    f"ServiceNow incident for {service_now_incident_id} missing serviceNowIncidentDetails key in database on attempt {attempt + 1}"
                )
                if not self.__should_retry(attempt, max_retries, wait_time):
                    return None
                wait_time = max(5, wait_time - 5)  # Decrease by 5s, minimum 5s
                continue
            except Exception as e:
                logger.info(
                    f"ServiceNow incident for {service_now_incident_id} not found in database on attempt {attempt + 1}. Error encountered: str{e}"
                )
                if skip_retry:
                    return None
                if not self.__should_retry(attempt, max_retries, wait_time):
                    return []
                wait_time = max(5, wait_time - 5)  # Decrease by 5s, minimum 5s
                continue
        return None

    def _get_incident_details(self, service_now_incident_id: str, skip_retry: bool = False) -> Optional[str]:
        """
        Get ServiceNow incident details from the database

        Args:
            service_now_incident_id: The ServiceNow incident ID
            skip_retry: If True, perform a single lookup without retries

        Returns:
            ServiceNow incident details or None if not found
        """
        try:
            service_now_incident_details = self.__get_incident_by_id(
                service_now_incident_id, skip_retry=skip_retry
            )
            if not service_now_incident_details:
                if skip_retry:
                    logger.info(
                        f"Incident details for {service_now_incident_id} not found in database (quick check)."
                    )
                else:
                    logger.info(
                        f"All retries completed. Incident details for {service_now_incident_id} not found in database."
                    )
                return None

            logger.info(
                f"Incident details for {service_now_incident_id} found in database."
            )
            return service_now_incident_details
        except Exception as e:
            logger.error(f"Error retrieving details from the DynamoDB table: {e}")
            return None

    def _add_incident_details(
        self, service_now_incident_id: str, service_now_incident_details: Dict[str, Any]
    ) -> bool:
        """
        Create a new entry with ServiceNow incident details

        Args:
            service_now_incident_id: The ServiceNow incident ID
            service_now_incident_details: The ServiceNow incident details

        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert the incident details to a JSON string for storage
            service_now_details_json = json.dumps(service_now_incident_details)

            # Use a composite key pattern with a prefix to maintain data model integrity
            case_id = f"ServiceNow#{service_now_incident_id}"

            # Create a new entry with the ServiceNow incident ID and details
            logger.info(
                f"Creating a new entry with CaseId {case_id} for ServiceNow incident {service_now_incident_id} in DynamoDb table"
            )
            self.table.put_item(
                Item={
                    "PK": case_id,
                    "SK": "latest",
                    "serviceNowIncidentId": service_now_incident_id,
                    "serviceNowIncidentDetails": service_now_details_json,
                }
            )

            logger.info(
                f"Successfully added details to DynamoDb table for ServiceNow incident {service_now_incident_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Error adding details to DynamoDb table for ServiceNow incident {service_now_incident_id}: {str(e)}"
            )
            return False

    def _update_incident_details(
        self, service_now_incident_id: str, service_now_incident_details: Dict[str, Any]
    ) -> bool:
        """
        Update an existing entry with ServiceNow incident details

        Args:
            service_now_incident_id: The ServiceNow incident ID
            service_now_incident_details: The ServiceNow incident details

        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert the incident details to a JSON string for storage
            service_now_details_json = json.dumps(service_now_incident_details)

            # Use a composite key pattern with a prefix to maintain data model integrity
            case_id = f"ServiceNow#{service_now_incident_id}"

            # Update the existing entry with the ServiceNow incident ID and details
            logger.info(
                f"Updating entry with CaseId {case_id} for ServiceNow incident {service_now_incident_id} in DynamoDb table"
            )
            self.table.update_item(
                Key={"PK": f"{case_id}", "SK": "latest"},
                UpdateExpression="set serviceNowIncidentDetails = :s",
                ExpressionAttributeValues={":s": service_now_details_json},
                ReturnValues="UPDATED_NEW",
            )

            logger.info(
                f"Successfully updated details in DynamoDb table for ServiceNow incident {service_now_incident_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Error updating details in DynamoDb table for ServiceNow incident {service_now_incident_id}: {str(e)}"
            )
            return False


class ServiceNowService:
    """Service for ServiceNow operations."""

    def __init__(self, instance_id, **kwargs):
        """Initialize the ServiceNow service
        
        Args:
            instance_id (str): ServiceNow instance ID
            **kwargs: OAuth configuration parameters
        """
        self.service_now_client = ServiceNowClient(instance_id, **kwargs)

    def _get_incident_details(
        self, service_now_incident_id: str, max_retries: int = 5, initial_delay: float = 2.0
    ) -> Optional[Dict[str, Any]]:
        """
        Get incident details from ServiceNow with retry logic.
        
        Retries are needed because the business rule fires during the insert transaction,
        and the incident may not be committed yet when the webhook is received.

        Args:
            service_now_incident_id: The ServiceNow incident ID
            max_retries: Maximum number of retry attempts (default: 5)
            initial_delay: Initial delay in seconds between retries (default: 2.0)

        Returns:
            Dictionary of incident details or None if retrieval fails
        """
        try:
            
            integration_module = os.environ.get("INTEGRATION_MODULE", "itsm")
            
            logger.info(f"Integration module: {integration_module}")
            
            if not self.service_now_client:
                logger.info("Service Now Client failed to initialize")
            
            # Add initial delay to allow transaction to commit
            logger.info(f"Waiting {initial_delay}s before first query to allow transaction commit")
            time.sleep(initial_delay)
            
            # Retry logic to handle race condition where business rule fires before transaction commits
            service_now_incident = None
            delay = initial_delay
            
            for attempt in range(max_retries):
                service_now_incident = self.service_now_client.get_incident_with_display_values(
                    service_now_incident_id, integration_module
                )
                
                if service_now_incident:
                    if attempt > 0:
                        logger.info(f"Successfully retrieved incident {service_now_incident_id} on attempt {attempt + 1}")
                    break
                    
                if attempt < max_retries - 1:
                    logger.info(
                        f"Incident {service_now_incident_id} not found on attempt {attempt + 1}, "
                        f"retrying in {delay}s (transaction may not be committed yet)"
                    )
                    time.sleep(delay)
                    delay = min(delay * 1.5, 5.0)  # Exponential backoff, max 5 seconds
            
            if not service_now_incident:
                logger.error(
                    f"Failed to get incident {service_now_incident_id} from ServiceNow after {max_retries} attempts"
                )
                return None

            service_now_incident_attachments = self.service_now_client.get_incident_attachments_details(
                service_now_incident_id, integration_module
            )

            return self.service_now_client.extract_incident_details(
                service_now_incident, service_now_incident_attachments
            )

        except Exception as e:
            logger.error(f"Error getting incident details from ServiceNow: {str(e)}")
            return None


class ServiceNowMessageProcessorService:
    """Class to handle ServiceNow message processing."""

    def __init__(self, instance_id, table_name, event_bus_name, **kwargs):
        """Initialize the message processor
        
        Args:
            instance_id (str): ServiceNow instance ID
            table_name (str): DynamoDB table name
            event_bus_name (str): EventBridge event bus name
            **kwargs: OAuth configuration parameters
        """
        self.db_service = DatabaseService(table_name)
        self.service_now_service = ServiceNowService(instance_id, **kwargs)
        self.event_publisher_service = EventPublisherService(event_bus_name)

    def _extract_event_body(self, event):
        """
        Extract the request body from the event

        Args:
            event: The event payload

        Returns:
            Request body from the event payload
        """
        try:
            # Extract the request body from API Gateway event
            body = event.get("body", "{}")

            # Handle base64 encoded body
            if event.get("isBase64Encoded", False):
                import base64

                body = base64.b64decode(body).decode("utf-8")
                logger.info("Decoded base64 body")

            # If body is already a dict, return it as is
            if isinstance(body, dict):
                return json.dumps(body)

            # If body is a string but not JSON, try to parse it as form data
            if isinstance(body, str) and not body.strip().startswith("{"):
                if "=" in body:
                    # Simple form data parsing
                    form_data = {}
                    for pair in body.split("&"):
                        if "=" in pair:
                            key, value = pair.split("=", 1)
                            form_data[key] = value
                    logger.debug(f"Parsed form data: {form_data}")
                    return json.dumps(form_data)

            return body
        except Exception as e:
            logger.error(f"Failed to extract event body: {str(e)}")
            logger.error(traceback.format_exc())
            return "{}"

    def _parse_message(self, message: str) -> Dict[str, Any]:
        """
        Parse a JSON string message

        Args:
            message: The message string to parse

        Returns:
            Dictionary containing parsed message or empty dict if parsing fails
        """
        try:
            # If message is already a dict, return it
            if isinstance(message, dict):
                return message

            # Try to parse as JSON
            if isinstance(message, str):
                # Handle empty or whitespace-only strings
                if not message.strip():
                    logger.warning("Empty message received")
                    return {}

                # Try to parse as JSON
                try:
                    return json.loads(message)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse as JSON: {str(e)}")

                    # If not JSON, try to parse as URL-encoded form data
                    if "=" in message:
                        form_data = {}
                        for pair in message.split("&"):
                            if "=" in pair:
                                key, value = pair.split("=", 1)
                                form_data[key] = value
                        logger.info(f"Parsed as form data: {form_data}")
                        return form_data

                    # If it's a single value, try to use it as incident_number
                    if message.strip().isalnum():
                        logger.info(f"Using message as incident_number: {message}")
                        return {"incident_number": message.strip()}

            logger.error(f"Unable to parse message: {message}")
            return {}
        except Exception as e:
            logger.error(f"Error parsing message: {str(e)}")
            logger.error(traceback.format_exc())
            return {}

    def _process_webhook_payload(self, payload: Dict[str, Any]) -> bool:
        """
        Process webhook payload from ServiceNow

        Args:
            payload: The parsed webhook payload

        Returns:
            True if processing was successful, False otherwise
        """
        # Log the full payload for debugging
        logger.info(f"Processing webhook payload: {json.dumps(payload)}")

        # Try different field names that might contain the incident number
        incident_number = None
        possible_fields = [
            "incident_number",
            "number",
            "sys_id",
            "id",
            "incident_id",
            "incidentNumber",
        ]

        for field in possible_fields:
            if field in payload and payload[field]:
                incident_number = payload[field]
                logger.info(
                    f"Found incident number in field '{field}': {incident_number}"
                )
                break

        # If we still don't have an incident number, check if there's a nested structure
        if (
            not incident_number
            and "incident" in payload
            and isinstance(payload["incident"], dict)
        ):
            incident = payload["incident"]
            for field in possible_fields:
                if field in incident and incident[field]:
                    incident_number = incident[field]
                    logger.info(
                        f"Found incident number in nested field 'incident.{field}': {incident_number}"
                    )
                    break

        # If we still don't have an incident number, check if there's a result field
        if (
            not incident_number
            and "result" in payload
            and isinstance(payload["result"], dict)
        ):
            result = payload["result"]
            for field in possible_fields:
                if field in result and result[field]:
                    incident_number = result[field]
                    logger.info(
                        f"Found incident number in nested field 'result.{field}': {incident_number}"
                    )
                    break

        if not incident_number:
            logger.error("No incident number found in payload")
            return False

        event_type = payload.get("event_type", "unknown")
        logger.info(
            f"Processing incident: {incident_number} with event_type: {event_type}"
        )

        # Get incident details and process based on event type
        return self.__process_incident(incident_number, event_type)

    def __process_incident(self, incident_number: str, event_type: str) -> bool:
        """
        Process a ServiceNow incident

        Args:
            incident_number: The ServiceNow incident number
            event_type: The ServiceNow incident event type i.e. IncidentUpdated or IncidentCreated

        Returns:
            True if processing was successful, False otherwise
        """
        try:
            logger.info("Get incident details from SNOW")
            # Get ServiceNow incident details
            service_now_incident_details = self.service_now_service._get_incident_details(
                incident_number
            )
            if not service_now_incident_details:
                logger.error(
                    f"Failed to get incident details for {incident_number} from ServiceNow"
                )
                return False

            # For IncidentCreated events, do a quick check without retries
            # This handles the case where ServiceNow creates the incident first (not from AWS SIR)
            # For IncidentUpdated events, use retries to wait for the record to be populated
            skip_retry = (event_type == "IncidentCreated")
            
            # Get existing incident details from database
            service_now_incident_details_ddb = self.db_service._get_incident_details(
                incident_number, skip_retry=skip_retry
            )

            # Skip processing if event_type is IncidentCreated and incident already exists in DDB
            if event_type == "IncidentCreated" and service_now_incident_details_ddb:
                logger.info(f"Skipping IncidentCreated event for existing incident {incident_number}")
                return True

            # Process based on whether the incident exists in the database
            if not service_now_incident_details_ddb:
                result = self.__handle_new_incident(
                    incident_number, service_now_incident_details
                )
            else:
                result = self.__handle_existing_incident(
                    incident_number,
                    service_now_incident_details,
                    service_now_incident_details_ddb,
                )
    
            return result
            
        except Exception as e:
            logger.error(f"Error processing incident {incident_number}: {str(e)}")
            return False

    def __handle_new_incident(
        self, incident_number: str, incident_details: Dict[str, Any]
    ) -> bool:
        """
        Handle a new incident that doesn't exist in the database

        Args:
            incident_number: The ServiceNow incident number
            incident_details: The incident details from ServiceNow

        Returns:
            True if processing was successful, False otherwise
        """
        try:
            logger.info(
                f"Publishing IncidentCreatedEvent for ServiceNow incident {incident_number}"
            )
            db_success = self.db_service._add_incident_details(incident_number, incident_details)
            if db_success:
                event = IncidentCreatedEvent(incident_details)
                self.event_publisher_service._publish_event(event)
            return db_success
        except Exception as e:
            logger.error(f"Error handling new incident {incident_number}: {str(e)}")
            return False

    def __handle_existing_incident(
        self,
        incident_number: str,
        incident_details: Dict[str, Any],
        existing_details: str,
    ) -> bool:
        """
        Handle an existing incident that's already in the database

        Args:
            incident_number: The ServiceNow incident number
            incident_details: The incident details from ServiceNow
            existing_details: The existing incident details from the database

        Returns:
            True if processing was successful, False otherwise
        """
        try:
            # Compare incident details to detect changes (memory efficient)
            existing_dict = json.loads(existing_details)
            has_changes = incident_details != existing_dict
            
            if has_changes:
                logger.info(
                    f"Publishing IncidentUpdatedEvent for ServiceNow incident {incident_number}"
                )
                db_success = self.db_service._update_incident_details(
                    incident_number, incident_details
                )
                if db_success:
                    event = IncidentUpdatedEvent(incident_details)
                    self.event_publisher_service._publish_event(event)
                return db_success
            else:
                logger.info(f"No changes detected for incident {incident_number}")
            return True
        except Exception as e:
            logger.error(
                f"Error handling existing incident {incident_number}: {str(e)}"
            )
            return False


class ResponseBuilderService:
    """Class to handle response building."""

    @staticmethod
    def _build_success_response(message: str) -> Dict[str, Any]:
        """
        Build a success response

        Args:
            message: Success message

        Returns:
            API Gateway compatible response
        """
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Methods": "POST,OPTIONS",
            },
            "body": json.dumps({"message": message}),
        }

    @staticmethod
    def _build_error_response(error: str) -> Dict[str, Any]:
        """
        Build an error response

        Args:
            error: Error message

        Returns:
            API Gateway compatible response
        """
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Methods": "POST,OPTIONS",
            },
            "body": json.dumps({"error": error}),
        }


# @logger.inject_lambda_context
def handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Lambda handler for processing API Gateway webhook events from ServiceNow

    Args:
        event: The Lambda event from API Gateway
        context: The Lambda context

    Returns:
        API Gateway compatible response
    """
    try:
        
        logger.info("Received event from Service Now")

        # Handle OPTIONS request for CORS
        if event.get("httpMethod") == "OPTIONS":
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "Content-Type,Authorization",
                    "Access-Control-Allow-Methods": "POST,OPTIONS",
                },
                "body": "",
            }

        # Validate event structure
        if not isinstance(event, dict):
            raise ValueError(f"Expected dict event, got {type(event)}")

        # Get environment variables
        try:
            table_name = os.environ["INCIDENTS_TABLE_NAME"]
            event_bus_name = os.environ.get("EVENT_BUS_NAME", "default")
            logger.info(f"Using table: {table_name}, event bus: {event_bus_name}")
        except KeyError as e:
            logger.error(f"Missing required environment variable: {str(e)}")
            return ResponseBuilderService._build_error_response(
                f"Configuration error: Missing {str(e)}"
            )

        # Get credentials from SSM
        try:
            parameter_service = ParameterService()
            instance_id_param = os.environ.get("SERVICE_NOW_INSTANCE_ID")
            client_id_param_name = os.environ.get("SERVICE_NOW_CLIENT_ID")
            client_secret_arn = os.environ.get("SERVICE_NOW_CLIENT_SECRET_ARN")
            user_id_param_name = os.environ.get("SERVICE_NOW_USER_ID")
            private_key_asset_bucket_param_name = os.environ.get("PRIVATE_KEY_ASSET_BUCKET")
            private_key_asset_key_param_name = os.environ.get("PRIVATE_KEY_ASSET_KEY")

            logger.info(
                "Getting ServiceNow configuration parameters from SSM"
            )

            instance_id = parameter_service._get_parameter(instance_id_param)

            if not all([instance_id, client_id_param_name, client_secret_arn, user_id_param_name, private_key_asset_bucket_param_name, private_key_asset_key_param_name]):
                logger.error("Failed to retrieve ServiceNow credentials from SSM")
                return ResponseBuilderService._build_error_response(
                    "Failed to retrieve ServiceNow credentials"
                )
        except Exception as e:
            logger.error(f"Error retrieving parameters: {str(e)}")
            return ResponseBuilderService._build_error_response(
                f"Parameter retrieval error: {str(e)}"
            )

        try:
            processor = ServiceNowMessageProcessorService(
                instance_id,
                table_name,
                event_bus_name,
                client_id_param_name=client_id_param_name,
                client_secret_arn=client_secret_arn,
                user_id_param_name=user_id_param_name,
                private_key_asset_bucket_param_name=private_key_asset_bucket_param_name,
                private_key_asset_key_param_name=private_key_asset_key_param_name
            )
        except Exception as e:
            logger.error(f"Failed to create ServiceNowMessageProcessorService: {str(e)}")
            return ResponseBuilderService._build_error_response(
                f"Failed to initialize processor: {str(e)}"
            )
        
        try:
            body = processor._extract_event_body(event)
            
            if body is None or body == "{}":
                return ResponseBuilderService._build_error_response(
                    "Empty or invalid request body"
                )

            payload = processor._parse_message(body)

            if not payload or "incident_number" not in payload:
                return ResponseBuilderService._build_error_response(
                    "Missing required fields in payload"
                )

            success = processor._process_webhook_payload(payload)
            
            if not success:
                return ResponseBuilderService._build_error_response(
                    "Failed to process ServiceNow webhook payload"
                )

            return ResponseBuilderService._build_success_response(
                "Successfully processed 1 record"
            )
            
        except Exception as e:
            logger.error(f"Error during event processing: {str(e)}")
            return ResponseBuilderService._build_error_response(
                f"Event processing error: {str(e)}"
            )

    except Exception as e:
        logger.error(f"Error in Lambda handler: {str(e)}")
        logger.error(traceback.format_exc())
        return ResponseBuilderService._build_error_response(
            f"Internal server error: {str(e)}"
        )

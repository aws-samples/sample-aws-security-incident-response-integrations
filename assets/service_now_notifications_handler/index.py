"""
ServiceNow Notifications Handler Lambda function for AWS Security Incident Response integration.
This module processes notifications from ServiceNow and publishes events to EventBridge.
"""

import json
import html
import os
import sys
import datetime
import re
import traceback
import logging
from typing import Dict, Any, Optional, List, Union
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
EVENT_SOURCE = os.environ.get('EVENT_SOURCE', 'service-now')

# Configure logging
logger = logging.getLogger()

# Get log level from environment variable
log_level = os.environ.get('LOG_LEVEL', 'error').lower()
if log_level == 'debug':
    logger.setLevel(logging.DEBUG)
elif log_level == 'info':
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

# Initialize AWS clients
events_client = boto3.client("events")
dynamodb = boto3.resource("dynamodb")

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects"""
    
    def default(self, obj):
        """Convert datetime objects to ISO format strings"""
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        return super().default(obj)


class BaseEvent:
    """Base class for domain events"""
    
    event_type = None
    event_source = EVENT_SOURCE
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary"""
        raise NotImplementedError("Subclasses must implement to_dict()")


class IncidentCreatedEvent(BaseEvent):
    """Domain event for incident creation"""
    
    event_type = 'IncidentCreated'
    
    def __init__(self, incident: Dict[str, Any]):
        """
        Initialize an IncidentCreatedEvent
        
        Args:
            incident: The incident details dictionary
        """
        self.incident = incident
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary
        
        Returns:
            Dictionary representation of the event
        """
        return {
            'eventType': self.event_type,
            'eventSource': self.event_source,
            'id': self.incident.get('id', ''),
            'key': self.incident.get('key', ''),
            'summary': self.incident.get('summary', ''),
            'status': self.incident.get('status', ''),
            'updated': self.incident.get('updated', ''),
            'created': self.incident.get('created', ''),
            'description': self.incident.get('description', ''),
            'priority': self.incident.get('priority', ''),
            'assignee': self.incident.get('assignee', ''),
            'reporter': self.incident.get('reporter', ''),
            'comments': self.incident.get('comments', []),
            'attachments': self.incident.get('attachments', []),
            'incidentType': self.incident.get('incidenttype', ''),
            'project': self.incident.get('project', ''),
            'resolution': self.incident.get('resolution', ''),
            'securityLevel': self.incident.get('securityLevel', '')
        }


class IncidentUpdatedEvent(BaseEvent):
    """Domain event for incident update"""
    
    event_type = 'IncidentUpdated'
    
    def __init__(self, incident: Dict[str, Any]):
        """
        Initialize an IncidentUpdatedEvent
        
        Args:
            incident: The incident details dictionary
        """
        self.incident = incident
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary
        
        Returns:
            Dictionary representation of the event
        """
        return {
            'eventType': self.event_type,
            'eventSource': self.event_source,
            'id': self.incident.get('id', ''),
            'key': self.incident.get('key', ''),
            'summary': self.incident.get('summary', ''),
            'status': self.incident.get('status', ''),
            'updated': self.incident.get('updated', ''),
            'created': self.incident.get('created', ''),
            'description': self.incident.get('description', ''),
            'priority': self.incident.get('priority', ''),
            'assignee': self.incident.get('assignee', ''),
            'reporter': self.incident.get('reporter', ''),
            'comments': self.incident.get('comments', []),
            'attachments': self.incident.get('attachments', []),
            'incidentLinks': self.incident.get('incidentlinks', []),
            'incidentType': self.incident.get('incidenttype', ''),
            'project': self.incident.get('project', ''),
            'resolution': self.incident.get('resolution', ''),
        }


class IncidentDeletedEvent(BaseEvent):
    """Domain event for incident deletion"""
    
    event_type = 'IncidentDeleted'
    
    def __init__(self, incident_id: str):
        """
        Initialize an IncidentDeletedEvent
        
        Args:
            incident_id: The ID of the incident that was deleted
        """
        self.incident_id = incident_id
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary
        
        Returns:
            Dictionary representation of the event
        """
        return {
            'eventType': self.event_type,
            'eventSource': self.event_source,
            'incidentId': self.incident_id
        }

class ParameterService:
    """Class to handle parameter operations"""

    def __init__(self):
        """Initialize the parameter service"""
        self.ssm_client = boto3.client("ssm")

    def get_parameter(self, parameter_name: str) -> Optional[str]:
        """
        Get a parameter from SSM Parameter Store

        Args:
            parameter_name: The name of the parameter to retrieve

        Returns:
            Parameter value or None if retrieval fails
        """
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )
            return response['Parameter']['Value']
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving parameter {parameter_name}: {error_code}")
            return None

class EventPublisherService:
    """Service for publishing events to EventBridge"""
    
    def __init__(self, event_bus_name: str):
        """
        Initialize an EventPublisherService
        
        Args:
            event_bus_name: Name of the EventBridge event bus
        """
        logger.debug(f"Initializing EventPublisherService with event bus: {event_bus_name}")
        self.events_client = events_client
        self.event_bus_name = event_bus_name
    
    def publish_event(self, event: BaseEvent) -> Dict[str, Any]:
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
                        'Source': EVENT_SOURCE,
                        'DetailType': event.event_type,
                        'Detail': event_json,
                        'EventBusName': self.event_bus_name
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
    """Service for database operations"""
    
    def __init__(self, table_name):
        """Initialize the database service"""
        self.table = dynamodb.Table(table_name)
    
    def get_incident_details(self, service_now_incident_id: str) -> Optional[str]:
        """
        Get ServiceNow incident details from the database
        
        Args:
            service_now_incident_id: The ServiceNow incident ID
            
        Returns:
            ServiceNow incident details or None if not found
        """
        try:
            items = self.scan_for_incident_id(service_now_incident_id)
            if not items:
                logger.info(f"Incident details for {service_now_incident_id} not found in database.")
                return None
                
            service_now_incident_details = items[0]["serviceNowIncidentDetails"]
            logger.info(f"Incident details for {service_now_incident_id} found in database.")
            return service_now_incident_details
        except Exception as e:
            logger.error(f"Error retrieving details from the DynamoDB table: {e}")
            return None
    
    def scan_for_incident_id(self, service_now_incident_id: str) -> List[Dict[str, Any]]:
        """
        Scan DynamoDB table for ServiceNow incident ID
        
        Args:
            service_now_incident_id: The ServiceNow incident ID
            
        Returns:
            List of matching items
        """
        try:
            response = self.table.scan(
                FilterExpression=Attr('serviceNowIncidentId').eq(service_now_incident_id)
            )
            items = response['Items']
            
            # Handle pagination if there are more items
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(
                    FilterExpression=Attr('serviceNowIncidentId').eq(service_now_incident_id),
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response['Items'])
            return items
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving details from the DynamoDB table: {error_code}")
            return []
        except KeyError:
            logger.error(f"ServiceNow incident for {service_now_incident_id} not found in database")
            return []
        
    def add_incident_details(self, service_now_incident_id: str, service_now_incident_details: Dict[str, Any]) -> bool:
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
            logger.info(f"Creating a new entry with CaseId {case_id} for ServiceNow incident {service_now_incident_id} in DynamoDb table")
            self.table.put_item(
                Item={
                    'PK': case_id,
                    'SK': 'latest',
                    'serviceNowIncidentId': service_now_incident_id,
                    'serviceNowIncidentDetails': service_now_details_json,
                }
            )
            
            logger.info(f"Successfully added details to DynamoDb table for ServiceNow incident {service_now_incident_id}")
            return True
        except Exception as e:
            logger.error(f"Error adding details to DynamoDb table for ServiceNow incident {service_now_incident_id}: {str(e)}")
            return False
    
    def update_incident_details(self, service_now_incident_id: str, service_now_incident_details: Dict[str, Any]) -> bool:
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
            logger.info(f"Updating entry with CaseId {case_id} for ServiceNow incident {service_now_incident_id} in DynamoDb table")
            self.table.update_item(
                Key={"PK": f"{case_id}", "SK": "latest"},
                UpdateExpression="set serviceNowIncidentDetails = :s",
                ExpressionAttributeValues={":s": service_now_details_json},
                ReturnValues="UPDATED_NEW",
            )

            logger.info(f"Successfully updated details in DynamoDb table for ServiceNow incident {service_now_incident_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating details in DynamoDb table for ServiceNow incident {service_now_incident_id}: {str(e)}")
            return False
        
class ServiceNowService:
    """Service for ServiceNow operations"""
    
    def __init__(self, instance_id, username, password_param_name):
        """Initialize the ServiceNow service"""
        self.service_now_client = ServiceNowClient(instance_id, username, password_param_name)
    
    def get_incident_details(self, service_now_incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Get incident details from ServiceNow
        
        Args:
            service_now_incident_id: The ServiceNow incident ID
            
        Returns:
            Dictionary of incident details or None if retrieval fails
        """
        try:
            service_now_incident = self.service_now_client.get_incident(service_now_incident_id)
            if not service_now_incident:
                logger.error(f"Failed to get incident {service_now_incident_id} from ServiceNow")
                return None
                
            return self.extract_incident_details(service_now_incident)
        except Exception as e:
            logger.error(f"Error getting incident details from ServiceNow: {str(e)}")
            return None
    
    def extract_incident_details(self, service_now_incident: Any) -> Dict[str, Any]:
        """
        Extract relevant details from a ServiceNow incident object into a serializable dictionary
        
        Args:
            service_now_incident: ServiceNow incident object
            
        Returns:
            Dictionary with serializable ServiceNow incident details
        """
        try:
            incident_dict = {
                "sys_id": service_now_incident.sys_id,
                "number": service_now_incident.number,
                "short_description": service_now_incident.short_description,
                "description": service_now_incident.description,
                "sys_updated_on": service_now_incident.sys_updated_on.get_display_value(),
                "sys_created_on": service_now_incident.sys_created_on.get_display_value(),
                "sys_created_by": service_now_incident.sys_created_by.get_display_value(),
                "resolved_by" : service_now_incident.resolved_by.get_display_value(),
                "resolved_at": service_now_incident.resolved_at.get_display_value(),
                "opened_at": service_now_incident.opened_at.get_display_value(),
                "closed_at": service_now_incident.closed_at.get_display_value(),
                "state": service_now_incident.state.get_display_value(),
                "impact": service_now_incident.impact.get_display_value(),
                "active": service_now_incident.active.get_display_value(),
                "priority": service_now_incident.priority.get_display_value(),
                "caller_id": service_now_incident.caller_id.get_display_value(),
                "incident_state": service_now_incident.incident_state.get_display_value(),
                "urgency": service_now_incident.urgency.get_display_value(),
                "severity": service_now_incident.severity.get_display_value(),
                "comments_and_work_notes": service_now_incident.comments_and_work_notes.get_display_value(),
                "close_code": service_now_incident.close_code.get_display_value(),
                "close_notes": service_now_incident.close_notes.get_display_value(),
                "closed_by": service_now_incident.closed_by.get_display_value(),
                "reopened_by": service_now_incident.reopened_by.get_display_value(),
                "assigned_to": service_now_incident.assigned_to.get_display_value(),
                "due_date": service_now_incident.due_date.get_display_value(),
                "sys_tags": service_now_incident.sys_tags.get_display_value(),
                "category": service_now_incident.subcategory.get_display_value(),
                "subcategory": service_now_incident.subcategory.get_display_value(),
            }
            return incident_dict
        except Exception as e:
            logger.error(f"Error extracting ServiceNow incident details: {str(e)}")
            # Return minimal details if extraction fails
            return {
                "id": service_now_incident.id if hasattr(service_now_incident, 'id') else None,
                "key": service_now_incident.key if hasattr(service_now_incident, 'key') else None,
                "error": str(e)
            }

class SNSMessageProcessorService:
    """Class to handle SNS message processing"""
    
    def __init__(self, instance_id, username, password_param_name, table_name):
        """Initialize the SNS message processor"""
        self.db_service = DatabaseService(table_name)
        self.service_now_service = ServiceNowService(instance_id, username, password_param_name)
    
    def parse_message(self, message: str) -> Dict[str, Any]:
        """
        Parse a JSON string message from SNS
        
        Args:
            message: The message string to parse
            
        Returns:
            Dictionary containing parsed message or empty dict if parsing fails
        """
        try:
            return json.loads(message)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse SNS message: {str(e)}")
            return {}
    
    def extract_automation_data(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract automation data from parsed message
        
        Args:
            message: Parsed message dictionary
            
        Returns:
            Automation data if found, None otherwise
        """
        return message.get("automationData")
    
    def process_automation_data(self, automation_data: Dict[str, Any], event_bus_name: str = 'default') -> bool:
        """
        Process the automation data
        
        Args:
            automation_data: The automation data to process
            event_bus_name: Name of the EventBridge event bus
            
        Returns:
            True if processing was successful, False otherwise
        """
        if not automation_data:
            logger.warning("No data received in ServiceNow event")
            return False
        
        try:
            # Log the automation data (sanitized)
            logger.info(f"Processing automation data: {html.escape(json.dumps(automation_data))}")
            
            # Create an EventPublisherService instance
            event_publisher = EventPublisherService(event_bus_name)
            
            # Get ServiceNow incident ID from the automation data
            service_now_incident_id = automation_data.get("IncidentId")
            if not service_now_incident_id:
                logger.error("No IncidentId found in automation data")
                return False
            
            # Get ServiceNow incident details from ServiceNow first
            service_now_incident_details = self.service_now_service.get_incident_details(service_now_incident_id)
            if not service_now_incident_details:
                logger.error(f"Failed to get incident details for {service_now_incident_id} from ServiceNow")
                return False
            
            # Get ServiceNow incident details from database
            service_now_incident_details_ddb = self.db_service.get_incident_details(service_now_incident_id)
                
            # If incident not found in database, publish created event and update the database
            if not service_now_incident_details_ddb:
                logger.info(f"ServiceNow incident details for {service_now_incident_id} not found in database")
                # Update the database with the ServiceNow incident ID and details
                try:
                    logger.info(f"Publishing IncidentCreatedEvent for ServiceNow incident {service_now_incident_id}")
                    event_publisher.publish_event(IncidentCreatedEvent(service_now_incident_details))
                    # Use a composite key pattern to maintain data model integrity
                    logger.info(f"Adding ServiceNow incident details for {service_now_incident_id} to database")
                    self.db_service.add_incident_details(service_now_incident_id, service_now_incident_details)
                    return True
                except Exception as e:
                    logger.error(f"Error updating database with ServiceNow incident details: {str(e)}")
                    return False
            
            logger.info(f"ServiceNow incident details for {service_now_incident_id} found in database. Comparing it with the incident details from ServiceNow")
            # Compare incident details to detect changes
            service_now_details_json = json.dumps(service_now_incident_details)
            if json.loads(service_now_details_json) != json.loads(service_now_incident_details_ddb):
                logger.info(f"ServiceNow incident details for {service_now_incident_id} have changed. Publishing IncidentUpdatedEvent")
                event_publisher.publish_event(IncidentUpdatedEvent(service_now_incident_details))
                logger.info(f"Storing the updated incident details for ServiceNow incident {service_now_incident_id} in the database")
                self.db_service.update_incident_details(service_now_incident_id, service_now_incident_details)
                return True
            
            logger.info(f"No changes detected for incident {service_now_incident_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error processing automation data: {str(e)}")
            logger.error(traceback.format_exc())
            return False


class ResponseBuilderService:
    """Class to handle response building"""
    
    @staticmethod
    def build_success_response(message: str) -> Dict[str, Any]:
        """
        Build a success response
        
        Args:
            message: Success message
            
        Returns:
            API Gateway compatible response
        """
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': message
            })
        }
    
    @staticmethod
    def build_error_response(error: str) -> Dict[str, Any]:
        """
        Build an error response
        
        Args:
            error: Error message
            
        Returns:
            API Gateway compatible response
        """
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': error
            })
        }

@logger.inject_lambda_context
def handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Lambda handler for processing SNS notifications
    
    Args:
        event: The Lambda event
        context: The Lambda context
        
    Returns:
        API Gateway compatible response
    """
    try:
        # Log incoming event
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Validate event structure
        if not isinstance(event, dict):
            raise ValueError(f"Expected dict event, got {type(event)}")
        
        parameter_service = ParameterService()
        # Get credentials from SSM
        instance_id = parameter_service.get_parameter(os.environ.get("SERVICE_NOW_INSTANCE_ID"))
        username = parameter_service.get_parameter(os.environ.get("SERVICE_NOW_USER"))
        password_param_name = parameter_service.get_parameter(os.environ.get("SERVICE_NOW_PASSWORD_PARAM"))
        # Get table_name from lambda variable
        table_name = os.environ["INCIDENTS_TABLE_NAME"]
            
        # Create processor
        processor = SNSMessageProcessorService(instance_id, username, password_param_name, table_name)
        processed_count = 0
        
        # Parse the event message
        message = processor.parse_message(event)
        
        # Extract the automation data from the SNS topic parsed message
        automation_data = processor.extract_automation_data(message)
        
        # Process automation data
        event_bus_name = os.environ.get('EVENT_BUS_NAME', 'default')
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
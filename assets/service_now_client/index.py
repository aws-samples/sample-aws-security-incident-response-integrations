"""
ServiceNow Client Lambda function for AWS Security Incident Response integration.
This module handles the creation and updating of ServiceNow incidents based on Security Incident Response cases.
"""

import json
import os
import re
import logging
from typing import Dict, Optional, Any, Tuple

import boto3
from botocore.exceptions import ClientError

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
security_ir_client = boto3.client("security-ir")
dynamodb = boto3.resource("dynamodb")

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from service_now_wrapper import ServiceNowClient
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..wrappers.python.service_now_wrapper import ServiceNowClient

class DatabaseService:
    """Class to handle database operations"""

    def __init__(self):
        """Initialize the database service"""
        self.table_name = os.environ["INCIDENTS_TABLE_NAME"]
        self.table = dynamodb.Table(self.table_name)

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a case from the database
        
        Args:
            case_id: The IR case ID
            
        Returns:
            Case data or None if retrieval fails
        """
        try:
            response = self.table.get_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"}
            )
            return response
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving details from the DynamoDB table: {error_code}")
            return None
        except KeyError:
            logger.error(f"ServiceNow incident for Case#{case_id} not found in database")
            return None

class IncidentService:
    """Class to handle incident operations"""

    def __init__(self):
        """Initialize the incident service"""
        self.service_now_client = ServiceNowClient()
        self.db_service = DatabaseService()

    def extract_case_details(self, ir_case: Dict[str, Any]) -> Tuple[Dict[str, Any], str, str, str]:
        """
        Extract case details from an IR case
        
        Args:
            ir_case: IR case data
            
        Returns:
            Tuple of (ir_case_detail, ir_event_type, ir_case_id, sir_case_status)
        """
        ir_case_detail = ir_case["detail"]
        ir_event_type = ir_case_detail["eventType"]
        ir_case_arn = ir_case_detail["caseArn"]
        
        try:
            ir_case_id = re.search(r"/(\d+)$", ir_case_arn).group(1)
        except (AttributeError, IndexError):
            logger.error(f"Failed to extract case ID from ARN: {ir_case_arn}")
            raise ValueError(f"Invalid case ARN format: {ir_case_arn}")
            
        sir_case_status = ir_case_detail.get("caseStatus", "")
        
        return ir_case_detail, ir_event_type, ir_case_id, sir_case_status

    def process_security_incident(self, ir_case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a security incident event
        
        Args:
            ir_case: IR case data
            
        Returns:
            ServiceNow incident or None if processing fails
        """
        try:
            # Extract case details
            ir_case_detail, ir_event_type, ir_case_id, sir_case_status = self.extract_case_details(ir_case)
            
            # Check if ServiceNow client is available
            if not self.service_now_client.client:
                logger.error("Failed to create ServiceNow client")
                return None
            
            # TODO: add CaseCreated, CaseUpdated and CaseDeleted events while implementing the Event Processing task for service-now-client
                
        except Exception as e:
            logger.error(f"Error in process_security_incident: {str(e)}")
            return None

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler to process security incidents
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Dictionary containing response status and details
    """
    try:
        # Only process events from Security Incident Response
        EVENT_SOURCE = os.environ.get('EVENT_SOURCE', 'security-ir')
        if event.get("source") == EVENT_SOURCE:
            incident_service = IncidentService()
            incident_service.process_security_incident(event)
        else:
            logger.info(
                "ServiceNow Client lambda will skip processing of this event as the event source is not security-ir"
            )
    except Exception as e:
        logger.error(f"Error in handler: {str(e)}")
        
    return {
        "statusCode": 200,
        "body": json.dumps("ServiceNow Client Lambda function execution complete"),
    }
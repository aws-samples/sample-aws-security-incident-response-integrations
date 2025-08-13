"""
ServiceNow Client Lambda function for AWS Security Incident Response integration.
This module handles the creation and updating of ServiceNow incidents based on Security Incident Response cases.
"""

import json
import os
import re
import logging
import requests
from typing import Dict, Optional, Any, Tuple
import boto3
from botocore.exceptions import ClientError

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from service_now_wrapper import ServiceNowClient
    from service_now_sir_mapper import (
        map_sir_fields_to_service_now,
        map_case_status,
        map_sir_case_comments_to_service_now_incident,
        convert_unmapped_fields_to_string_for_snow_comments,
    )
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..wrappers.python.service_now_wrapper import ServiceNowClient
    from ..mappers.python.service_now_sir_mapper import (
        map_sir_fields_to_service_now,
        map_case_status,
        map_sir_case_comments_to_service_now_incident,
        convert_unmapped_fields_to_string_for_snow_comments,
    )

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# # Configure logging
# logger = logging.getLogger()

# # Get log level from environment variable
# log_level = os.environ.get("LOG_LEVEL", "error").lower()
# if log_level == "debug":
#     logger.setLevel(logging.DEBUG)
# elif log_level == "info":
#     logger.setLevel(logging.INFO)
# else:
#     # Default to ERROR level
#     logger.setLevel(logging.ERROR)

# Initialize AWS clients
security_incident_response_client = boto3.client("security-ir")
dynamodb = boto3.resource("dynamodb")


class ParameterService:
    """Class to handle parameter operations"""

    def __init__(self):
        """Initialize the parameter service."""
        self.ssm_client = boto3.client("ssm")

    def get_parameter(self, parameter_name: str) -> Optional[str]:
        """
        Get a parameter from SSM Parameter Store.

        Args:
            parameter_name (str): The name of the parameter to retrieve

        Returns:
            Optional[str]: Parameter value or None if retrieval fails
        """
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving parameter {parameter_name}: {error_code}")
            return None


class DatabaseService:
    """Class to handle database operations"""

    def __init__(self, table_name):
        """
        Initialize the database service.

        Args:
            table_name (str): Name of the DynamoDB table
        """
        self.table = dynamodb.Table(table_name)

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a case from the database.

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
            logger.error(
                f"ServiceNow incident for Case#{case_id} not found in database"
            )
            return None

    def update_mapping(self, case_id: str, service_now_incident_id: str) -> bool:
        """
        Update the mapping between an IR case and a ServiceNow incident.

        Args:
            case_id (str): The IR case ID
            service_now_incident_id (str): The ServiceNow incident ID

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression="set serviceNowIncidentId = :j",
                ExpressionAttributeValues={":j": service_now_incident_id},
                ReturnValues="UPDATED_NEW",
            )
            logger.info(
                f"Security IR case {case_id} mapped to ServiceNow incident {service_now_incident_id}"
            )
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error updating DynamoDB table: {error_code}")
            return False

    def update_incident_details(
        self, case_id: str, service_now_incident_id: str, incident_details: Any
    ) -> bool:
        """
        Update ServiceNow incident details in the database.

        Args:
            case_id (str): The Security IR case ID
            service_now_incident_id (str): The ServiceNow incident ID
            incident_details (Any): ServiceNow incident details

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Update the database
            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression="set serviceNowIncidentDetails = :j",
                ExpressionAttributeValues={":j": json.dumps(incident_details)},
                ReturnValues="UPDATED_NEW",
            )

            logger.info(
                f"Updated ServiceNow incident details in DynamoDB for Security IR case {case_id}"
            )
            return True
        except Exception as e:
            logger.error(
                f"Error updating ServiceNow incident details in DynamoDB: {str(e)}"
            )
            return False


class ServiceNowService:
    """Service for ServiceNow operations"""

    def __init__(self, instance_id, username, password_param_name):
        """
        Initialize the ServiceNow service.

        Args:
            instance_id (str): ServiceNow instance ID
            username (str): ServiceNow username
            password_param_name (str): SSM parameter name containing password
        """
        self.service_now_client = ServiceNowClient(
            instance_id, username, password_param_name
        )

    def get_incident(self, service_now_incident_id: str) -> Optional[Dict[str, Any]]:
        """Get incident details from ServiceNow.

        Args:
            service_now_incident_id (str): The ServiceNow incident ID

        Returns:
            Optional[Dict[str, Any]]: Dictionary of incident details or None if retrieval fails
        """
        try:
            service_now_incident = self.service_now_client.get_incident(
                service_now_incident_id
            )
            if not service_now_incident:
                logger.error(
                    f"Failed to get incident {service_now_incident_id} from ServiceNow"
                )
                return None

            service_now_incident_attachments = (
                self.service_now_client.get_incident_attachments(service_now_incident)
            )

            return self.extract_incident_details(
                service_now_incident, service_now_incident_attachments
            )
        except Exception as e:
            logger.error(f"Error getting incident details from ServiceNow: {str(e)}")
            return None

    def create_incident(self, service_now_fields: Dict[str, Any]) -> Optional[str]:
        """Create incident in ServiceNow.

        Args:
            service_now_fields (Dict[str, Any]): The ServiceNow incident fields

        Returns:
            Optional[str]: Incident number of the created incident or None if creation fails
        """
        try:
            service_now_incident_number = self.service_now_client.create_incident(
                service_now_fields
            )
            if not service_now_incident_number:
                logger.error("Failed to create incident in ServiceNow")
                return None
            logger.info(
                f"Created incident in ServiceNow: {service_now_incident_number}"
            )
            return service_now_incident_number
        except Exception as e:
            logger.error(f"Error getting incident details from ServiceNow: {str(e)}")
            return None

    def update_incident(
        self, service_now_incident_number: str, service_now_fields: Dict[str, Any]
    ) -> Optional[Any]:
        """Update incident in ServiceNow.

        Args:
            service_now_incident_number (str): Incident number in ServiceNow to be updated
            service_now_fields (Dict[str, Any]): Dictionary of incident fields

        Returns:
            Optional[Any]: Updated ServiceNow incident or None if update fails
        """
        try:
            service_now_incident = self.service_now_client.update_incident(
                service_now_incident_number, service_now_fields
            )
            if not service_now_incident:
                logger.error("Failed to update incident in ServiceNow")
                return None
            logger.info(
                f"Updated incident in ServiceNow for: {service_now_incident_number}"
            )
            return service_now_incident
        except Exception as e:
            logger.error(f"Error updating incident details from ServiceNow: {str(e)}")
            return None

    def extract_incident_details(
        self, service_now_incident: Any, service_now_incident_attachments: Any
    ) -> Dict[str, Any]:
        """Extract relevant details from a ServiceNow incident object into a serializable dictionary.

        Args:
            service_now_incident (Any): ServiceNow incident object
            service_now_incident_attachments (Any): ServiceNow incident attachments

        Returns:
            Dict[str, Any]: Dictionary with serializable ServiceNow incident details
        """
        try:
            attachments_list = [
                {
                    "filename": attachment.file_name,
                    "content_type": attachment.content_type,
                }
                for attachment in service_now_incident_attachments
            ]

            incident_dict = {
                "sys_id": service_now_incident.sys_id.get_display_value(),
                "number": service_now_incident.number.get_display_value(),
                "short_description": service_now_incident.short_description.get_display_value(),
                "description": service_now_incident.description.get_display_value(),
                "sys_created_on": service_now_incident.sys_created_on.get_display_value(),
                "sys_created_by": service_now_incident.sys_created_by.get_display_value(),
                "resolved_by": service_now_incident.resolved_by.get_display_value(),
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
                "comments": service_now_incident.comments.get_display_value(),
                "work_notes": service_now_incident.work_notes.get_display_value(),
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
                "attachments": attachments_list,
            }
            return incident_dict
        except Exception as e:
            logger.error(f"Error extracting ServiceNow incident details: {str(e)}")
            # Return minimal details if extraction fails
            return {
                "id": (
                    service_now_incident.id
                    if hasattr(service_now_incident, "id")
                    else None
                ),
                "key": (
                    service_now_incident.key
                    if hasattr(service_now_incident, "key")
                    else None
                ),
                "error": str(e),
            }


class IncidentService:
    """Class to handle incident operations"""

    def __init__(self, instance_id, username, password_param_name, table_name):
        """Initialize the incident service.

        Args:
            instance_id (str): ServiceNow instance ID
            username (str): ServiceNow username
            password_param_name (str): SSM parameter name containing password
            table_name (str): Name of the DynamoDB table
        """
        self.db_service = DatabaseService(table_name)
        self.service_now_service = ServiceNowService(
            instance_id, username, password_param_name
        )

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

        ir_case_status = ir_case_detail.get("caseStatus", "")
        ir_case_comments = ir_case_detail.get("caseComments", "")
        ir_case_attachments = ir_case_detail.get("caseAttachments", "")

        return (
            ir_case_detail,
            ir_event_type,
            ir_case_id,
            ir_case_status,
            ir_case_comments,
            ir_case_attachments,
        )

    def map_sir_case_to_snow_incident(
        self, ir_case_detail: Dict[str, Any], ir_case_id: str
    ) -> Dict[str, Any]:
        """Prepare ServiceNow fields from IR case details.

        Args:
            ir_case_detail (Dict[str, Any]): IR case details
            ir_case_id (str): IR case ID

        Returns:
            Dict[str, Any]: Dictionary of ServiceNow fields
        """
        # Map fields from SIR to ServiceNow
        service_now_fields = map_sir_fields_to_service_now(ir_case_detail)

        return service_now_fields

    def process_security_incident(
        self, ir_case: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Process a security incident event.

        Args:v
            ir_case (Dict[str, Any]): IR case data

        Returns:
            Optional[Dict[str, Any]]: ServiceNow incident or None if processing fails
        """
        try:
            service_now_incident_id = None
            comments_list = []
            # Extract case details
            (
                ir_case_detail,
                ir_event_type,
                ir_case_id,
                sir_case_status,
                sir_case_comments,
                sir_case_attachments,
            ) = self.extract_case_details(ir_case)

            # Check if ServiceNow client is available
            if (
                not self.service_now_service
                or not self.service_now_service.service_now_client
            ):
                logger.error("Failed to create ServiceNow client")
                return None

            # Map Security IR case fields to ServiceNow incident
            service_now_fields = self.map_sir_case_to_snow_incident(
                ir_case_detail, ir_case_id
            )

            # Ensure base fields are set
            # Map Security IR case status to ServiceNow incident
            service_now_status = None
            status_comment = None
            if sir_case_status:
                service_now_status, status_comment = map_case_status(sir_case_status)

            if service_now_status:
                service_now_fields["state"] = service_now_status

            if status_comment:
                # If the status of Security IR case does not map to any status in ServiceNow incident, add the status as a comment for user visibility
                comments_list.append(status_comment)

            # Map Security IR case comments to ServiceNow incident
            if sir_case_comments:
                comments_to_be_added = map_sir_case_comments_to_service_now_incident(
                    sir_case_comments, service_now_comments
                )
                if comments_to_be_added:
                    comments_list.extend(comments_to_be_added)

            # Get short description mapping
            service_now_short_description = f"{ir_case_detail.get('title', 'SIR Case')} - AWS Security Incident Response Case#{ir_case_id}"

            # Get unmapped fields comments
            unmapped_sir_fields_comment = (
                convert_unmapped_fields_to_string_for_snow_comments(ir_case_detail)
            )

            # Handle based on event type
            if ir_event_type == "CaseCreated":
                service_now_incident_id = self.handle_case_creation(
                    ir_case_id,
                    service_now_fields,
                    comments_list,
                    service_now_short_description,
                    unmapped_sir_fields_comment,
                )
            elif ir_event_type == "CaseUpdated":
                service_now_incident_id = self.handle_case_update(
                    ir_case_detail,
                    ir_case_id,
                    service_now_fields,
                    comments_list,
                    unmapped_sir_fields_comment,
                    service_now_short_description,
                )
            else:
                logger.warning(f"Unhandled event type: {ir_event_type}")
                return None

            # Map Security IR case attachments to ServiceNow incident
            if sir_case_attachments:
                logger.info(
                    "Uploading Security IR case attachments to ServiceNow incident"
                )
                for sir_case_attachment in sir_case_attachments:
                    logger.info(f"Attachment to be uploaded: {ir_attachment}")
                    sir_case_attachment_id = sir_case_attachment["attachmentId"]
                    sir_case_attachment_name = sir_case_attachment["fileName"]
                    self.upload_attachment_to_service_now_incident(
                        service_now_incident_id,
                        ir_case_id,
                        sir_case_attachment_id,
                        sir_case_attachment_name,
                    )

            return service_now_incident_id

        except Exception as e:
            logger.error(f"Error in process_security_incident: {str(e)}")
            return None

    def handle_case_creation(
        self,
        ir_case_id: str,
        service_now_fields: Dict[str, Any],
        comments_list: List[str],
        short_description: str,
        unmapped_sir_fields_comment: str,
    ) -> Optional[str]:
        """Handle the creation of a new IR case.

        Args:
            ir_case_id (str): IR case ID
            service_now_fields (Dict[str, Any]): ServiceNow fields
            short_description (str): Short description for the incident
            unmapped_sir_fields_comment (str): Comments containing unmapped SIR fields

        Returns:
            Optional[str]: ServiceNow incident ID or None if creation fails
        """
        # Ensure base fields are set for incident creation in ServiceNow
        service_now_fields["short_description"] = short_description
        # Create new incident in ServiceNow
        service_now_incident_number = self.service_now_service.create_incident(
            service_now_fields
        )
        if not service_now_incident_number:
            return None

        # Update comments in the newly created incident
        # Add unmapped fields to the comment list if they exist
        if unmapped_sir_fields_comment:
            comments_list.append(unmapped_sir_fields_comment)

        if comments_list:
            for comment in comments_list:
                service_now_fields["work_notes"] = comment
                self.service_now_service.update_incident(
                    service_now_incident_number, service_now_fields
                )

        # Create mapping between Security IR case id and ServiceNow incident id in the database
        self.db_service.update_mapping(ir_case_id, service_now_incident_number)

        # Get incident details after creation and update database
        service_now_incident = self.service_now_service.get_incident(
            service_now_incident_number
        )
        if service_now_incident:
            self.db_service.update_incident_details(
                ir_case_id, service_now_incident_number, service_now_incident
            )

        logger.info(
            f"Created ServiceNow incident {service_now_incident_number} for new IR case {ir_case_id}"
        )
        return service_now_incident_number

    def handle_case_update(
        self,
        ir_case_detail: Dict[str, Any],
        ir_case_id: str,
        service_now_fields: Dict[str, Any],
        comments_list: List[str],
        unmapped_fields_comment: Optional[str],
        service_now_short_description: Optional[str],
    ) -> Optional[str]:
        """Handle the update of an existing IR case.

        Args:
            ir_case_detail (Dict[str, Any]): IR case details
            ir_case_id (str): IR case ID
            service_now_fields (Dict[str, Any]): ServiceNow fields
            unmapped_fields_comment (Optional[str]): Comments containing additional info for unmapped SIR fields
            service_now_short_description (Optional[str]): Short description containing the AWS Security Incident Response Case Id

        Returns:
            Optional[str]: ServiceNow incident ID or None if update fails
        """
        # Get case details from database
        case_from_ddb = self.db_service.get_case(ir_case_id)
        if not case_from_ddb and "Item" not in case_from_ddb:
            logger.error(
                f"No Security IR case found in database for IR case {ir_case_id}"
            )
            return None

        # Get ServiceNow incident ID
        service_now_incident_id = case_from_ddb["Item"].get("serviceNowIncidentId")

        # Create new incident in ServiceNow if none exists
        if service_now_incident_id is None:
            logger.info(
                f"No ServiceNow incident found for IR case {ir_case_id} in database, creating ServiceNow incident..."
            )
            return self.handle_case_creation(
                ir_case_id,
                service_now_fields,
                comments_list,
                service_now_short_description,
                unmapped_fields_comment,
            )
        else:
            # Update existing incident in ServiceNow
            logger.info(
                f"ServiceNow incident {service_now_incident_id} found for IR case {ir_case_id} in database, updating ServiceNow incident..."
            )
            if comments_list:
                for comment in comments_list:
                    service_now_fields["work_notes"] = comment
                    self.service_now_service.update_incident(
                        service_now_incident_id, service_now_fields
                    )
            else:
                self.service_now_service.update_incident(
                    service_now_incident_id, service_now_fields
                )

        # Get ServiceNow incident latest details post update
        service_now_incident = self.service_now_service.get_incident(
            service_now_incident_id
        )
        if not service_now_incident:
            return service_now_incident_id

        # Update ServiceNow incident latest details in database
        self.db_service.update_incident_details(
            ir_case_id, service_now_incident_id, service_now_incident
        )

        logger.info(
            f"Updated ServiceNow incident {service_now_incident_id} for existing IR case {ir_case_id}"
        )
        return service_now_incident_id

    def upload_attachment_to_service_now_incident(
        self, service_now_incident_id, ir_case_id, ir_attachment_id, ir_attachment_name
    ):
        # Upload the file to the fetched incident
        # Replace 'path/to/your/file.txt'
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

            # Upload from /tmp and add to ServiceNow issue as attachment
            self.service_now_service.service_now_client.upload_incident_attachment(
                service_now_incident_id, download_path
            )

            logger.info(
                f"Added attachment {ir_attachment_name} to ServiceNow issue {service_now_incident_id}"
            )

            # Delete file from /tmp directory
            os.remove(download_path)

        except Exception as e:
            logger.error(f"Error trying to download IR attachment: {e}")
            # Clean up if file exists
            if os.path.exists(download_path):
                os.remove(download_path)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler to process security incidents.

    Processes Security IR events and creates/updates corresponding ServiceNow incidents.

    Args:
        event (Dict[str, Any]): Lambda event object containing Security IR case data
        context (Any): Lambda context object

    Returns:
        Dict[str, Any]: Dictionary containing response status and details
    """
    try:
        # Only process events from Security Incident Response
        EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "security-ir")
        if event.get("source") == EVENT_SOURCE:
            parameter_service = ParameterService()
            # Get credentials from SSM
            instance_id = parameter_service.get_parameter(
                os.environ.get("SERVICE_NOW_INSTANCE_ID")
            )
            username = parameter_service.get_parameter(
                os.environ.get("SERVICE_NOW_USER")
            )
            password_param_name = os.environ.get("SERVICE_NOW_PASSWORD_PARAM")
            table_name = os.environ["INCIDENTS_TABLE_NAME"]

            incident_service = IncidentService(
                instance_id, username, password_param_name, table_name
            )
            # Process event
            incident_id = incident_service.process_security_incident(event)
            if incident_id is None:
                logger.error(
                    "Event processing failed. Incident not created in Service Now."
                )
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

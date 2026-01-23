"""
ServiceNow Client Lambda function for AWS Security Incident Response integration.
This module handles the creation and updating of ServiceNow incidents based on Security Incident Response cases.
"""

import json
import os
import re
import logging
import requests
from typing import Dict, Optional, Any, Tuple, List
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
logger.setLevel(logging.INFO)  # Set to INFO first

# Debug: Print all environment variables
print(f"All environment variables: {dict(os.environ)}")

# Get log level from environment variable
log_level = os.environ.get("LOG_LEVEL", "error").lower()
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
security_incident_response_client = boto3.client("security-ir")
dynamodb = boto3.resource("dynamodb")


class ParameterService:
    """Class to handle parameter operations."""

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
    """Class to handle database operations."""

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
    """Service for ServiceNow operations."""

    def __init__(self, instance_id, **kwargs):
        """
        Initialize the ServiceNow service.

        Args:
            instance_id (str): ServiceNow instance ID
            **kwargs: OAuth configuration parameters including:
                - client_id_param_name (str): SSM parameter name containing OAuth client ID
                - client_secret_param_name (str): SSM parameter name containing OAuth client secret
                - user_id_param_name (str): SSM parameter name containing ServiceNow user ID
                - private_key_asset_bucket_param_name (str): SSM parameter name containing S3 bucket for private key asset
                - private_key_asset_key_param_name (str): SSM parameter name containing S3 object key for private key asset
        """
        self.service_now_client = ServiceNowClient(instance_id, **kwargs)

    def get_incident(
        self, service_now_incident_id: str, integration_module: str = "itsm"
    ) -> Optional[Dict[str, Any]]:
        """Get incident details from ServiceNow.

        Args:
            service_now_incident_id (str): The ServiceNow incident ID
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[Dict[str, Any]]: Dictionary of incident details or None if retrieval fails
        """
        try:
            service_now_incident_with_display_values = (
                self.service_now_client.get_incident_with_display_values(
                    service_now_incident_id, integration_module
                )
            )
            if not service_now_incident_with_display_values:
                logger.error(
                    f"Failed to get incident {service_now_incident_id} from ServiceNow"
                )
                return None

            service_now_incident_attachments = (
                self.service_now_client.get_incident_attachments_details(
                    service_now_incident_id, integration_module
                )
            )

            return self.service_now_client.extract_incident_details(
                service_now_incident_with_display_values,
                service_now_incident_attachments,
            )
        except Exception as e:
            logger.error(f"Error getting incident details from ServiceNow: {str(e)}")
            return None

    def create_incident(
        self, service_now_fields: Dict[str, Any], integration_module: str = "itsm"
    ) -> Optional[str]:
        """Create incident in ServiceNow.

        Args:
            service_now_fields (Dict[str, Any]): The ServiceNow incident fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[str]: Incident number of the created incident or None if creation fails
        """
        try:
            service_now_incident_number = self.service_now_client.create_incident(
                service_now_fields, integration_module
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
        self,
        service_now_incident_number: str,
        service_now_fields: Dict[str, Any],
        integration_module: str = "itsm",
    ) -> Optional[Any]:
        """Update incident in ServiceNow.

        Args:
            service_now_incident_number (str): Incident number in ServiceNow to be updated
            service_now_fields (Dict[str, Any]): Dictionary of incident fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[Any]: Updated ServiceNow incident or None if update fails
        """
        try:
            service_now_fields_state = service_now_fields["state"]
            # Default status if no mapping exists
            if integration_module == "ir":
                service_now_incident = self.get_incident(
                    service_now_incident_number, integration_module
                )
                service_now_incident_state = service_now_incident["state"]
                if (
                    # If mapped service_now_fields contains the state as 18/Contain, verify the existing state of the ServiceNow incident, and if its either Contain-18/Eradicate-19/Recover-20, then keep as-is
                    (
                        service_now_incident_state
                        in ["Contain", "Eradicate", "Recover", "18", "19", "20"]
                        and service_now_fields_state == "18"
                    )
                    # If mapped service_now_fields contains the state as 10/Draft, check if the existing state of the ServiceNow incident is also 10/Draft. If not, it means that map_case_status performed the default mapping to 10/Draft for ServiceNow incident since there was no mapping found for the respective AWS SIR case. In such a case, keep the ServiceNow incident status as-is, instead of mapping to the default status, as that will be incorrect
                    or (
                        service_now_incident_state
                        not in ["Draft", "10"]
                        and service_now_fields_state == "10"
                    )
                ):
                    service_now_fields["state"] = service_now_incident_state
                    
            elif integration_module == "itsm":
                service_now_incident = self.get_incident(
                    service_now_incident_number, integration_module
                )
                service_now_incident_state = service_now_incident["state"]
                # If mapped service_now_fields contains the state as 1/New, check if the existing state of the ServiceNow incident is also 1/New. If not, it means that map_case_status performed the default mapping to 1/New for ServiceNow incident since there was no mapping found for the respective AWS SIR case. In such a case, keep the ServiceNow incident status as-is, instead of mapping to the default status, as that will be incorrect
                if (
                    service_now_incident_state
                    not in ["New", "1"]
                    and service_now_fields_state == "1"
                ):
                    service_now_fields["state"] = service_now_incident_state

            service_now_incident = self.service_now_client.update_incident(
                service_now_incident_number, service_now_fields, integration_module
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

    def add_incident_comment(
        self,
        service_now_incident_number: str,
        service_now_incident_comment: str,
        integration_module: str = "itsm",
    ) -> Optional[Any]:
        """Add comment to incident in ServiceNow.

        Args:
            service_now_incident_number (str): Incident number in ServiceNow to be updated
            service_now_incident_comment (str): Comment to add to the incident
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[Any]: Updated ServiceNow incident or None if update fails
        """
        try:
            service_now_incident = self.service_now_client.add_incident_comment(
                service_now_incident_number,
                service_now_incident_comment,
                integration_module,
            )
            if not service_now_incident:
                logger.error(
                    f"Failed to add comment {service_now_incident_comment} to incident {service_now_incident_number} in ServiceNow"
                )
                return None
            logger.info(
                f"Added comment {service_now_incident_comment} to incident {service_now_incident_number}"
            )
            return service_now_incident
        except Exception as e:
            logger.error(
                f"Error adding {service_now_incident_comment} comment to incident {service_now_incident_number} in ServiceNow: {str(e)}"
            )
            return None


class IncidentService:
    """Class to handle incident operations."""

    def __init__(self, instance_id, table_name, **kwargs):
        """Initialize the incident service.

        Args:
            instance_id (str): ServiceNow instance ID
            table_name (str): Name of the DynamoDB table
            **kwargs: OAuth configuration parameters
        """
        self.db_service = DatabaseService(table_name)
        self.service_now_service = ServiceNowService(instance_id, **kwargs)

    def extract_case_details(
        self, ir_case: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], str, str, str, str, str]:
        """Extract case details from an IR case.

        Args:
            ir_case (Dict[str, Any]): IR case data

        Returns:
            Tuple[Dict[str, Any], str, str, str, str, str]: Tuple of (ir_case_detail, ir_event_type, ir_case_id, ir_case_status, ir_case_comments, ir_case_attachments)
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
        self,
        ir_case_detail: Dict[str, Any],
        ir_case_id: str,
        integration_module: str = "itsm",
    ) -> Dict[str, Any]:
        """Prepare ServiceNow fields from IR case details.

        Args:
            ir_case_detail (Dict[str, Any]): IR case details
            ir_case_id (str): IR case ID
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Dict[str, Any]: Dictionary of ServiceNow fields
        """
        # Map fields from SIR to ServiceNow
        service_now_fields = map_sir_fields_to_service_now(
            ir_case_detail, integration_module
        )

        # Map Security IR case status to ServiceNow incident state
        sir_case_status = ir_case_detail.get("caseStatus")
        if sir_case_status:
            service_now_status, status_comment = map_case_status(
                sir_case_status, integration_module
            )
            if service_now_status:
                service_now_fields["state"] = service_now_status

        return service_now_fields
    
    def get_service_now_incident_id_ddb(self, ir_case_id: str) -> Optional[str]:
        """Check if ServiceNow incident exists for the given IR case.

        Args:
            ir_case_id (str): IR case ID

        Returns:
            Optional[str]: ServiceNow incident ID if exists, None otherwise
        """
        case_from_ddb = self.db_service.get_case(ir_case_id)
        if not case_from_ddb or "Item" not in case_from_ddb:
            logger.error(
                f"No Security IR case found in database for IR case {ir_case_id}"
            )
            return None
        return case_from_ddb["Item"].get("serviceNowIncidentId")

    def process_security_incident(
        self, ir_case: Dict[str, Any], integration_module: str = "itsm"
    ) -> Optional[Dict[str, Any]]:
        """Process a security incident event.

        Args:
            ir_case (Dict[str, Any]): IR case data
            integration_module (str): Integration module type ('itsm' or 'ir')

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
                ir_case_detail, ir_case_id, integration_module
            )

            # Get unmapped fields comments
            unmapped_sir_fields_comment = (
                convert_unmapped_fields_to_string_for_snow_comments(ir_case_detail)
            )

            # Handle based on event type
            if ir_event_type == "CaseCreated":
                service_now_incident_id = self.get_service_now_incident_id_ddb(ir_case_id)
                if service_now_incident_id is None:
                    logger.info(
                        f"No ServiceNow incident found for IR case {ir_case_id} in database, creating ServiceNow incident..."
                    )
                    service_now_incident_id = self.handle_case_creation(
                        ir_case_id,
                        service_now_fields,
                        integration_module,
                    )
                # Only add unmapped SIR fields comment to the ServiceNow comment_list for the first time when Incident is created
                comments_list.append(unmapped_sir_fields_comment)
            elif ir_event_type == "CaseUpdated":
                service_now_incident_id, incident_created = self.handle_case_update(
                    ir_case_detail,
                    ir_case_id,
                    service_now_fields,
                    integration_module,
                )
                # If incident did not exist, and needed to be created for CaseUpdated event, add the unmapped fields comment to the list
                if incident_created:
                    comments_list.append(unmapped_sir_fields_comment)
            else:
                logger.warning(f"Unhandled event type: {ir_event_type}")
                return None

            # Get ServiceNow incident latest details before further updates
            service_now_incident = self.service_now_service.get_incident(
                service_now_incident_id, integration_module
            )

            logger.info(f"ServiceNow incident details: {service_now_incident}")

            # Map Security IR case comments to ServiceNow incident
            service_now_incident_comments = ""
            if service_now_incident:
                comments = service_now_incident.get("comments", "")
                work_notes = service_now_incident.get("work_notes", "")
                
                if comments:
                    service_now_incident_comments += comments
                if work_notes:
                    if service_now_incident_comments:
                        service_now_incident_comments += "\n"
                    service_now_incident_comments += work_notes

            if sir_case_comments:
                comments_to_be_added = map_sir_case_comments_to_service_now_incident(
                    sir_case_comments, service_now_incident_comments
                )
                if comments_to_be_added:
                    comments_list.extend(comments_to_be_added)
            for comment in comments_list:
                logger.info("Updating ServiceNow comment")
                # Update Service Now incident with the latest comments
                self.service_now_service.add_incident_comment(
                    service_now_incident_id, comment, integration_module
                )

            # Map Security IR case attachments to ServiceNow incident
            service_now_incident_attachments = (
                service_now_incident.get("attachments")
                if service_now_incident
                else None
            )
            logger.info(f"ServiceNow incident existing attachments: {service_now_incident_attachments}")
            
            if sir_case_attachments:
                logger.info(
                    "Uploading Security IR case attachments to ServiceNow incident"
                )
                for sir_case_attachment in sir_case_attachments:
                    logger.info(f"Attachment to be uploaded: {sir_case_attachment}")
                    sir_case_attachment_id = sir_case_attachment["attachmentId"]
                    sir_case_attachment_name = sir_case_attachment["fileName"]
                    if not self.check_if_attachment_exists_in_service_now_incident(
                        service_now_incident_attachments, sir_case_attachment_name
                    ):
                        self.upload_attachment_to_service_now_incident(
                            service_now_incident_id,
                            ir_case_id,
                            sir_case_attachment_id,
                            sir_case_attachment_name,
                            service_now_incident_comments,
                            integration_module,
                        )

            # Get ServiceNow incident latest details post all the updates and store it in DDB
            service_now_incident_latest = self.service_now_service.get_incident(
                service_now_incident_id, integration_module
            )
            if not service_now_incident_latest:
                return service_now_incident_id

            # Update ServiceNow incident latest details in database
            self.db_service.update_incident_details(
                ir_case_id, service_now_incident_id, service_now_incident_latest
            )

            logger.info(
                f"Updated ServiceNow incident {service_now_incident_id} for existing IR case {ir_case_id}"
            )

            return service_now_incident_id

        except Exception as e:
            logger.error(f"Error in process_security_incident: {str(e)}")
            return None
        
    def handle_case_creation(
        self,
        ir_case_id: str,
        service_now_fields: Dict[str, Any],
        integration_module: str = "itsm",
        # short_description: str,
    ) -> Optional[str]:
        """Handle the creation of a new IR case.

        Args:
            ir_case_id (str): IR case ID
            service_now_fields (Dict[str, Any]): ServiceNow fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[str]: ServiceNow incident ID or None if creation fails
        """

        # Create new incident in ServiceNow
        service_now_incident_number = self.service_now_service.create_incident(
            service_now_fields, integration_module
        )

        if not service_now_incident_number:
            return None

        # Create mapping between Security IR case id and ServiceNow incident id in the database
        self.db_service.update_mapping(ir_case_id, service_now_incident_number)

        logger.info(
            f"Created ServiceNow incident {service_now_incident_number} for new IR case {ir_case_id}"
        )
        return service_now_incident_number

    def handle_case_update(
        self,
        ir_case_detail: Dict[str, Any],
        ir_case_id: str,
        service_now_fields: Dict[str, Any],
        integration_module: str = "itsm",
    ) -> Tuple[Optional[str], bool]:
        """Handle the update of an existing IR case.

        Args:
            ir_case_detail (Dict[str, Any]): IR case details
            ir_case_id (str): IR case ID
            service_now_fields (Dict[str, Any]): ServiceNow fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Tuple[Optional[str], bool]: Tuple of (ServiceNow incident ID, incident_created flag)
        """
        incident_created = False
        service_now_incident_id = self.get_service_now_incident_id_ddb(ir_case_id)

        if service_now_incident_id is None:
            logger.info(
                f"No ServiceNow incident found for IR case {ir_case_id} in database, creating ServiceNow incident..."
            )
            service_now_incident_id = self.handle_case_creation(
                ir_case_id,
                service_now_fields,
                integration_module,
            )
            incident_created = True
        else:
            logger.info(
                f"ServiceNow incident {service_now_incident_id} found for IR case {ir_case_id} in database, updating ServiceNow incident..."
            )
            logger.info(f"Updating with fields: {service_now_fields}")
            logger.info(
                f"State field value: {service_now_fields.get('state', 'NOT SET')}"
            )
            self.service_now_service.update_incident(
                service_now_incident_id, service_now_fields, integration_module
            )

        return service_now_incident_id, incident_created

    def check_if_attachment_exists_in_service_now_incident(
        self, service_now_incident_attachments: List[Any], sir_case_attachment_name: str
    ) -> bool:
        """Check if an attachment exists in a ServiceNow incident.

        Args:
            service_now_incident_attachments (List[Any]): List of ServiceNow incident attachments
            sir_case_attachment_name (str): Security IR case attachment name

        Returns:
            bool: True if the attachment exists, False otherwise
        """
        for service_now_incident_attachment in service_now_incident_attachments:
            # Compare with the filename property of the attachment
            attachment_filename = service_now_incident_attachment.get("filename", "")
            if str(sir_case_attachment_name) == str(attachment_filename):
                logger.info(
                    f"Attachment {sir_case_attachment_name} already exists in ServiceNow incident"
                )
                return True
        logger.info(
            f"Attachment {sir_case_attachment_name} does not exist in ServiceNow incident, will upload"
        )
        return False

    def upload_attachment_to_service_now_incident(
        self,
        service_now_incident_id: str,
        ir_case_id: str,
        ir_attachment_id: str,
        ir_attachment_name: str,
        service_now_incident_comments: str,
        integration_module: str = "itsm",
    ) -> None:
        """Upload attachment to ServiceNow incident with size and error handling.

        Args:
            service_now_incident_id (str): ServiceNow incident ID
            ir_case_id (str): Security IR case ID
            ir_attachment_id (str): Security IR attachment ID
            ir_attachment_name (str): Security IR attachment name
            service_now_incident_comments (str): Existing ServiceNow incident comments
            integration_module (str): Integration module type ('itsm' or 'ir')
        """
        # Check file size limit (5MB) to avoid 414 Request-URI Too Large error
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
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

            # Check file size before processing
            if len(response.content) > MAX_FILE_SIZE:
                logger.warning(
                    f"Attachment {ir_attachment_name} ({len(response.content)} bytes) exceeds size limit. Adding comment instead."
                )
                comment = f"[AWS Security Incident Response Update] Large attachment '{ir_attachment_name}' ({len(response.content)} bytes) could not be uploaded due to size limits. Please download from the Security IR case."
                # Check if comment already exists before adding
                if (
                    not service_now_incident_comments
                    or comment not in service_now_incident_comments
                ):
                    self.service_now_service.add_incident_comment(
                        service_now_incident_id, comment, integration_module
                    )
                return

            with open(download_path, "wb") as f:
                f.write(response.content)

            # Upload from /tmp and add to ServiceNow issue as attachment
            self.service_now_service.service_now_client.upload_incident_attachment(
                service_now_incident_id,
                ir_attachment_name,
                download_path,
                integration_module,
            )

            logger.info(
                f"Added attachment {ir_attachment_name} to ServiceNow issue {service_now_incident_id}"
            )

            # Delete file from /tmp directory
            os.remove(download_path)

        except Exception as e:
            logger.error(f"Error trying to upload IR attachment: {e}")
            # Add comment about failed attachment upload
            comment = f"[AWS Security Incident Response Update] Failed to upload attachment '{ir_attachment_name}'. Please download from the Security IR case."
            try:
                # Check if comment already exists before adding
                if (
                    not service_now_incident_comments
                    or comment not in service_now_incident_comments
                ):
                    self.service_now_service.add_incident_comment(
                        service_now_incident_id, comment, integration_module
                    )
            except Exception as comment_error:
                logger.error(
                    f"Failed to add attachment failure comment: {comment_error}"
                )

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
            # Get integration module once
            integration_module = os.environ.get("INTEGRATION_MODULE", "itsm")

            parameter_service = ParameterService()
            # Get credentials from SSM
            instance_id = parameter_service.get_parameter(
                os.environ.get("SERVICE_NOW_INSTANCE_ID")
            )
            client_id_param_name = os.environ.get("SERVICE_NOW_CLIENT_ID")
            client_secret_param_name = os.environ.get("SERVICE_NOW_CLIENT_SECRET_PARAM")
            user_id_param_name = os.environ.get("SERVICE_NOW_USER_ID")
            private_key_asset_bucket_param_name = os.environ.get("PRIVATE_KEY_ASSET_BUCKET")
            private_key_asset_key_param_name = os.environ.get("PRIVATE_KEY_ASSET_KEY")
            table_name = os.environ["INCIDENTS_TABLE_NAME"]

            incident_service = IncidentService(
                instance_id,
                table_name,
                client_id_param_name=client_id_param_name,
                client_secret_param_name=client_secret_param_name,
                user_id_param_name=user_id_param_name,
                private_key_asset_bucket_param_name=private_key_asset_bucket_param_name,
                private_key_asset_key_param_name=private_key_asset_key_param_name
            )
            # Process event
            incident_id = incident_service.process_security_incident(
                event, integration_module
            )
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

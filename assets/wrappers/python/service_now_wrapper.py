"""
ServiceNow API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the ServiceNow API for use in the Security Incident Response integration.
"""

import logging
import boto3
from typing import Dict, Optional, Any, List
from pysnc import ServiceNowClient as SnowClient, GlideRecord
import mimetypes
import requests
from base64 import b64encode

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ssm_client = boto3.client("ssm")


# TODO: Consider refactoring the micro-service implementation in the solution to use the Singleton or Factory method design pattern. See https://refactoring.guru/design-patterns/python
class ServiceNowClient:
    """Class to handle ServiceNow API interactions"""

    def __init__(self, instance_id, username, password_param_name):
        """
        Initialize the ServiceNow client.

        Args:
            instance_id (str): ServiceNow instance ID
            username (str): ServiceNow username
            password_param_name (str): SSM parameter name containing ServiceNow password
        """
        self.instance_id = instance_id
        self.username = username
        self.password_param_name = password_param_name
        self.client = self.__create_client()

    def __create_client(self) -> Optional[SnowClient]:
        """Create a ServiceNow client instance.

        Returns:
            Optional[SnowClient]: PySNC ServiceNow client or None if creation fails
        """
        try:
            # Use provided parameters or fetch from SSM
            instance = self.instance_id
            username = self.username
            password = self.__get_password()

            if not instance:
                logger.error("No ServiceNow instance id provided")
                return None
            elif not username:
                logger.error("No ServiceNow username provided")
                return None

            return SnowClient(instance, (username, password))

        except Exception as e:
            logger.error(f"Error creating ServiceNow client: {str(e)}")
            return None

    def __get_password(self) -> Optional[str]:
        """Fetch the ServiceNow password from SSM Parameter Store.

        Returns:
            Optional[str]: Password or None if retrieval fails
        """
        try:
            if not self.password_param_name:
                logger.error("No ServiceNow password param name provided")
                return None

            password_param_name = self.password_param_name
            response = ssm_client.get_parameter(
                Name=password_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving ServiceNow password from SSM: {str(e)}")
            return None

    def __get_glide_record(self, record_type: str) -> Optional[GlideRecord]:
        """Prepare a Glide Record using ServiceNowClient for querying.

        Args:
            record_type (str): Type of ServiceNow record (e.g., 'incident')

        Returns:
            Optional[GlideRecord]: GlideRecord instance or None if retrieval fails
        """
        try:
            glide_record = self.client.GlideRecord(record_type)
            return glide_record
        except Exception as e:
            logger.error(f"Error preparing GlideRecord: {str(e)}")
            return None

    def __prepare_service_now_incident(
        self, glide_record: GlideRecord, integration_module: str, fields: Dict[str, Any]
    ) -> GlideRecord:
        """Prepare ServiceNow Glide Record for incident creation.

        Args:
            glide_record (GlideRecord): ServiceNow Glide Record
            fields (Dict[str, Any]): ServiceNow mapped fields

        Returns:
            GlideRecord: Glide record for Incident creation with added fields
        """
        # Validate that fields is a dictionary
        if not isinstance(fields, dict):
            logger.error(
                f"Fields parameter must be a dictionary, got {type(fields)}: {fields}"
            )
            return glide_record

        glide_record.short_description = fields.get("short_description", "")
        glide_record.description = fields.get("description", "")
        if "state" in fields:
            glide_record.state = fields["state"]
        if integration_module == "itsm":
            glide_record.impact = fields.get("impact", "2")
            glide_record.priority = fields.get("priority", "3")
            glide_record.urgency = fields.get("urgency", "2")
            glide_record.severity = fields.get("severity", "1")
        elif integration_module == "ir":
            glide_record.impact = fields.get("impact", "3")
            glide_record.priority = fields.get("priority", "4")
            glide_record.urgency = fields.get("urgency", "3")
        glide_record.comments_and_work_notes = fields.get("comments_and_work_notes", "")
        glide_record.comments = fields.get("comments", "")
        glide_record.category = fields.get("category", "inquiry")
        glide_record.subcategory = fields.get("subcategory", "internal application")
        # if "incident_state" in fields:
        #     glide_record.incident_state = fields["incident_state"]
        return glide_record

    def get_incident_with_display_values(
        self, incident_number: str, integration_module: str = "itsm"
    ) -> Optional[Dict[str, Any]]:
        """Get a ServiceNow incident by incident_number.

        Args:
            incident_number (str): The ServiceNow incident number
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[Dict[str, Any]]: Incident record dictionary or None if retrieval fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                logger.info(
                    f"Incident details for {incident_number} from ServiceNow {table_name}: {glide_record}"
                )
                logger.info(
                    f"Getting DisplayValue for the Incident {incident_number} GlideRecord from ServiceNow"
                )
                glide_record_with_display_values = glide_record.serialize(
                    display_value=True
                )
                logger.info(
                    f"Display values for incident details for {incident_number} from ServiceNow {table_name}: {glide_record_with_display_values}"
                )
                return glide_record_with_display_values
        except Exception as e:
            logger.error(
                f"Error getting incident details for {incident_number} from ServiceNow: {str(e)}"
            )
            return None

    def get_incident(
        self, incident_number: str, integration_module: str = "itsm"
    ) -> GlideRecord:
        """Get a ServiceNow incident by incident_number.

        Args:
            incident_number (str): The ServiceNow incident number
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[Dict[str, Any]]: Incident record dictionary or None if retrieval fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                logger.info(
                    f"Incident details for {incident_number} from ServiceNow {table_name}: {glide_record}"
                )
                return glide_record
        except Exception as e:
            logger.error(
                f"Error getting incident details for {incident_number} from ServiceNow: {str(e)}"
            )
            return None

    def get_incident_attachments_details(
        self, service_now_incident_id: str, integration_module: str = "itsm"
    ) -> Optional[List[Dict[str, str]]]:
        """Get attachments for a ServiceNow incident.

        Args:
            service_now_incident_id (str): ServiceNow incident ID
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[List[Dict[str, str]]]: List of attachment details dictionaries or None if retrieval fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", service_now_incident_id)
            glide_record.query()
            if glide_record.next():
                attachments_list = []
                attachments = glide_record.get_attachments()
                for attachment in attachments:
                    attachment_details = {
                        "filename": attachment.file_name,
                        "content_type": attachment.content_type,
                    }
                    logger.info(
                        f"Incident attachment details for incident {glide_record.number}: {attachment_details}"
                    )
                    attachments_list.append(attachment_details)
                return attachments_list
            else:
                logger.error(
                    f"Incident {service_now_incident_id} not found in {table_name}"
                )
                return None
        except Exception as e:
            logger.error(
                f"Error getting attachments for incident {service_now_incident_id} from ServiceNow: {str(e)}"
            )
            return None

    def get_incident_attachment_data(
        self, glide_record: GlideRecord, attachment_name: str
    ) -> Optional[Dict[str, Any]]:
        """Get attachment data for a ServiceNow incident.

        Args:
            glide_record (GlideRecord): ServiceNow Glide Record
            attachment_name (str): Name of the attachment to retrieve

        Returns:
            Optional[Dict[str, Any]]: Dictionary containing attachment content, content type, and content size, or None if retrieval fails
        """
        try:
            attachments = glide_record.get_attachments()
            for attachment in attachments:
                if attachment.file_name == attachment_name:
                    # Temporary path to download the attachment
                    temp_path = f"/tmp/{attachment_name}"
                    attachment.write_to(temp_path)

                    # Read attachment content in binary mode
                    with open(temp_path, "rb") as f:
                        attachment_content = f.read()

                        # Return the complete temp path as attachment_url
                        attachment_content_type = attachment.content_type
                        attachment_content_length = attachment.size_bytes
                        attachment_data = {
                            "attachment_content": attachment_content,
                            "attachment_content_type": attachment_content_type,
                            "attachment_content_length": attachment_content_length,
                        }
                        return attachment_data
        except Exception as e:
            logger.error(
                f"Error getting attachment data for incident {glide_record.number} from ServiceNow: {str(e)}"
            )
            return None

    def create_incident(
        self, fields: Dict[str, Any], integration_module: str = "itsm"
    ) -> Optional[str]:
        """Create a new ServiceNow incident.

        Args:
            fields (Dict[str, Any]): Dictionary of incident fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[str]: Created ServiceNow incident number or None if creation fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.initialize()
            glide_record = self.__prepare_service_now_incident(
                glide_record, integration_module, fields
            )
            incident_sys_id = (
                glide_record.insert()
            )  # Insert the record and get the sys_id
            logger.info(
                f"Incident created with sys_id: {incident_sys_id} in {table_name}"
            )
            incident_number = glide_record.number
            logger.info(f"Newly created Incident Number: {incident_number}")
            return incident_number
        except Exception as e:
            logger.error(f"Incident creation failed with error: {e}")
            return None

    def update_incident(
        self,
        incident_number: str,
        fields: Dict[str, Any],
        integration_module: str = "itsm",
    ) -> Optional[GlideRecord]:
        """Update an existing ServiceNow incident.

        Args:
            incident_number (str): Incident number in ServiceNow to be updated
            fields (Dict[str, Any]): Dictionary of incident fields
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[GlideRecord]: Updated ServiceNow incident record or None if update fails
        """
        try:
            # Validate that fields is a dictionary
            if not isinstance(fields, dict):
                logger.error(
                    f"Fields parameter must be a dictionary, got {type(fields)}: {fields}"
                )
                return None

            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                glide_record = self.__prepare_service_now_incident(
                    glide_record, integration_module, fields
                )
                glide_record.update()
                logger.info(
                    f"Incident {incident_number} updated successfully in {table_name}"
                )
                return glide_record
            else:
                logger.error(f"Incident {incident_number} not found")
                return None
        except Exception as e:
            logger.error(f"Incident update failed with error: {e}")
            return None

    def add_incident_comment(
        self,
        incident_number: str,
        incident_comment: str,
        integration_module: str = "itsm",
    ) -> Optional[GlideRecord]:
        """Add a comment to an existing ServiceNow incident.

        Args:
            incident_number (str): Incident number in ServiceNow to be updated
            incident_comment (str): Comment to add to the incident
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[GlideRecord]: Updated ServiceNow incident record or None if update fails
        """
        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                glide_record.comments = incident_comment
                glide_record.update()
                logger.info(
                    f"Incident {incident_number} with comment {incident_comment} updated successfully in {table_name}"
                )
                return glide_record
            else:
                logger.error(f"Incident {incident_number} not found in {table_name}")
                return None
        except Exception as e:
            logger.error(f"Incident comment update failed with error: {e}")
            return None

    def upload_incident_attachment(
        self,
        incident_number: str,
        attachment_name: str,
        attachment_path: str,
        integration_module: str = "itsm",
    ) -> Optional[bool]:
        """Upload an attachment to a ServiceNow incident using REST API.

        Args:
            incident_number (str): The ServiceNow incident number
            attachment_name (str): Name of the attachment
            attachment_path (str): Path to the attachment file
            integration_module (str): Integration module type ('itsm' or 'ir')

        Returns:
            Optional[bool]: True if upload successful, None if upload fails
        """

        try:
            if integration_module == "itsm":
                table_name = "incident"
            elif integration_module == "ir":
                table_name = "sn_si_incident"
            else:
                logger.error(f"Invalid integration module: {integration_module}")
                return None

            # Get the incident record first
            glide_record = self.__get_glide_record(table_name)
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                # Use REST API instead of AttachmentAPI to avoid 414 errors
                password = self.__get_password()
                auth = b64encode(f"{self.username}:{password}".encode()).decode()

                # Determine content type
                content_type = (
                    mimetypes.guess_type(attachment_name)[0]
                    or "application/octet-stream"
                )

                headers = {
                    "Authorization": f"Basic {auth}",
                    "Content-Type": content_type,
                }

                # Upload via REST API
                url = f"https://{self.instance_id}.service-now.com/api/now/attachment/file"
                params = {
                    "table_name": table_name,
                    "table_sys_id": glide_record.sys_id.get_display_value(),
                    "file_name": attachment_name,
                }

                with open(attachment_path, "rb") as f:
                    file_content = f.read()
                    response = requests.post(
                        url,
                        headers=headers,
                        params=params,
                        data=file_content,
                        timeout=30,
                    )

                if response.status_code == 201:
                    logger.info(
                        f"Uploaded attachment {attachment_name} to ServiceNow incident {incident_number} in {table_name}"
                    )
                    return True
                else:
                    logger.error(
                        f"Upload failed with status {response.status_code}: {response.text}"
                    )
                    return None
            else:
                logger.error(f"Incident {incident_number} not found in {table_name}")
                return None
        except Exception as e:
            logger.error(f"Attachment upload failed with error: {e}")
            return None

    def extract_incident_details(
        self,
        service_now_incident: Dict[str, Any],
        service_now_incident_attachments: Any,
    ) -> Dict[str, Any]:
        """Extract relevant details from a ServiceNow incident dictionary into a serializable dictionary.

        Args:
            service_now_incident (Dict[str, Any]): ServiceNow incident dictionary
            service_now_incident_attachments (Any): ServiceNow incident attachments

        Returns:
            Dict[str, Any]: Dictionary with serializable ServiceNow incident details
        """
        try:
            incident_dict = {
                "sys_id": service_now_incident.get("sys_id"),
                "number": service_now_incident.get("number"),
                "short_description": service_now_incident.get("short_description"),
                "description": service_now_incident.get("description"),
                "sys_created_on": service_now_incident.get("sys_created_on"),
                "sys_created_by": service_now_incident.get("sys_created_by"),
                "resolved_by": service_now_incident.get("resolved_by"),
                "resolved_at": service_now_incident.get("resolved_at"),
                "opened_at": service_now_incident.get("opened_at"),
                "closed_at": service_now_incident.get("closed_at"),
                "state": service_now_incident.get("state"),
                "impact": service_now_incident.get("impact"),
                "active": service_now_incident.get("active"),
                "priority": service_now_incident.get("priority"),
                "caller_id": service_now_incident.get("caller_id"),
                "urgency": service_now_incident.get("urgency"),
                "severity": service_now_incident.get("severity"),
                "comments": service_now_incident.get("comments"),
                "work_notes": service_now_incident.get("work_notes"),
                "comments_and_work_notes": service_now_incident.get(
                    "comments_and_work_notes"
                ),
                "close_code": service_now_incident.get("close_code"),
                "close_notes": service_now_incident.get("close_notes"),
                "closed_by": service_now_incident.get("closed_by"),
                "reopened_by": service_now_incident.get("reopened_by"),
                "assigned_to": service_now_incident.get("assigned_to"),
                "due_date": service_now_incident.get("due_date"),
                "sys_tags": service_now_incident.get("sys_tags"),
                "category": service_now_incident.get("category"),
                "subcategory": service_now_incident.get("subcategory"),
                "attachments": service_now_incident_attachments,
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

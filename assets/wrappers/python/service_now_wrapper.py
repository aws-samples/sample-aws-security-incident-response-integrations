"""
ServiceNow API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the ServiceNow API for use in the Security Incident Response integration.
"""

import os
import logging
import boto3
from typing import Dict, Optional, Any, List
from pysnc import ServiceNowClient as SnowClient, GlideRecord, Attachment

# Import mappers with fallbacks for different environments
try:
    # This import works for lambda function and imports the lambda layer at runtime
    from service_now_sir_mapper import map_fields_to_service_now, map_case_status
except ImportError:
    # This import works for local development and imports locally from the file system
    from mappers.python.service_now_sir_mapper import (
        map_fields_to_service_now,
        map_case_status,
    )

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
        """
        Create a ServiceNow client instance.

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
        """
        Fetch the ServiceNow password from SSM Parameter Store.

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

    def __get_glide_record(self, record_type) -> GlideRecord:
        """
        Prepare a Glide Record using ServiceNowClient for querying.

        Args:
            record_type (str): Type of ServiceNow record (e.g., 'incident')

        Returns:
            GlideRecord: GlideRecord instance or None if retrieval fails
        """
        try:
            glide_record = self.client.GlideRecord(record_type)
            return glide_record
        except Exception as e:
            logger.error(f"Error preparing GlideRecord: {str(e)}")
            return None

    def __prepare_service_now_incident(
        self, glide_record: GlideRecord, fields: Dict[str, Any]
    ):
        """
        Prepare ServiceNow Glide Record for incident creation.

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
        glide_record.state = fields.get("state", "1")
        glide_record.impact = fields.get("impact", "2")
        glide_record.priority = fields.get("priority", "3")
        glide_record.incident_state = fields.get("incident_state", "1")
        glide_record.urgency = fields.get("urgency", "2")
        glide_record.severity = fields.get("severity", "1")
        glide_record.comments_and_work_notes = fields.get("comments_and_work_notes", "")
        glide_record.category = fields.get("category", "inquiry")
        glide_record.subcategory = fields.get("subcategory", "internal application")

        return glide_record

    def get_incident(self, incident_number: str) -> GlideRecord:
        """
        Get a ServiceNow incident by incident_number.

        Args:
            incident_number (str): The ServiceNow incident number

        Returns:
            GlideRecord: Incident record or None if retrieval fails
        """
        try:
            glide_record = self.__get_glide_record("incident")
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                logger.info(
                    f"Incident details for {incident_number} from ServiceNow: {glide_record}"
                )
                return glide_record
        except Exception as e:
            logger.error(
                f"Error getting incident details for {incident_number} from ServiceNow: {str(e)}"
            )
            return None

    def get_incident_attachments(self, glide_record: GlideRecord) -> List[Attachment]:
        """
        Get attachments for a ServiceNow incident.

        Args:
            glide_record (GlideRecord): ServiceNow Glide Record

        Returns:
            List[Attachment]: List of attachments or None if retrieval fails
        """
        try:
            attachments = []
            for attachment in glide_record.get_attachments():
                attachments.append(attachment)
            return attachments
        except Exception as e:
            logger.error(
                f"Error getting attachments for incident {glide_record.number} from ServiceNow: {str(e)}"
            )
            return None

    def create_incident(self, fields: Dict[str, Any]) -> Optional[Any]:
        """
        Create a new ServiceNow incident.

        Args:
            fields (Dict[str, Any]): Dictionary of incident fields

        Returns:
            Optional[Any]: Created ServiceNow incident number or None if creation fails
        """
        try:
            glide_record = self.__get_glide_record("incident")
            glide_record.initialize()
            glide_record = self.__prepare_service_now_incident(glide_record, fields)
            incident_sys_id = (
                glide_record.insert()
            )  # Insert the record and get the sys_id
            logger.info(f"Incident created with sys_id: {incident_sys_id}")
            incident_number = glide_record.number
            logger.info(f"Newly created Incident Number: {incident_number}")
            return incident_number
        except Exception as e:
            logger.error(f"Incident creation failed with error: {e}")
            return None

    def update_incident(self, incident_number, fields: Dict[str, Any]) -> Optional[Any]:
        """
        Update an existing ServiceNow incident.

        Args:
            incident_number (str): Incident number in ServiceNow to be updated
            fields (Dict[str, Any]): Dictionary of incident fields

        Returns:
            Optional[Any]: Updated ServiceNow incident record or None if update fails
        """
        try:
            # Validate that fields is a dictionary
            if not isinstance(fields, dict):
                logger.error(
                    f"Fields parameter must be a dictionary, got {type(fields)}: {fields}"
                )
                return None

            glide_record = self.__get_glide_record("incident")
            glide_record.add_query("number", incident_number)
            glide_record.query()
            if glide_record.next():
                glide_record = self.__prepare_service_now_incident(glide_record, fields)
                glide_record.update()
                logger.info(f"Incident {incident_number} updated successfully")
                return glide_record
            else:
                logger.error(f"Incident {incident_number} not found")
                return None
        except Exception as e:
            logger.error(f"Incident update failed with error: {e}")
            return None

    def upload_incident_attachment(
        self, incident_number: str, attachment_path: str
    ) -> Optional[Any]:
        """Upload an attachment to a ServiceNow incident.

        Args:
            incident_number (str): The ServiceNow incident number
            attachment_path (str): Path to the attachment file

        Returns:
            Optional[Any]: Upload result or None if upload fails
        """
        try:
            # Get a resource object for the incident table
            incidents = self.client.resource(api_path="/table/incident")
            # Fetch the incident record by number
            incident = incidents.get(query={"number": incident_number})
            incident.upload(file_path=attachment_path)
            logger.info(f"Uploaded attachment to ServiceNow incident {incident_number}")
        except Exception as e:
            logger.error(f"Attachment upload failed with error: {e}")
            return None

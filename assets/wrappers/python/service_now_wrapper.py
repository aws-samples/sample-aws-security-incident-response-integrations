"""
ServiceNow API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the ServiceNow API for use in the Security Incident Response integration.
"""

import os
import logging
import boto3
from typing import Dict, Optional, Any
from pysnc import ServiceNowClient as SnowClient
from flask import session

# Import mappers with fallbacks for different environments
try:
    # This import works for lambda function and imports the lambda layer at runtime
    from service_now_sir_mapper import map_fields_to_service_now, map_case_status
except ImportError:
    # This import works for local development and imports locally from the file system
    from mappers.python.service_now_sir_mapper import map_fields_to_service_now, map_case_status

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ssm_client = boto3.client("ssm")

class ServiceNowClient:
    """Class to handle ServiceNow API interactions"""

    def __init__(self, instance_id, username, password_param_name):
        """
        Initialize the ServiceNow client
        
        Args:
            instance_id: ServiceNow instance ID
            username: ServiceNow username
            password: ServiceNow password
        """
        self.instance_id = instance_id
        self.username = username
        self.password_param_name = password_param_name
        self.client = self._create_client()

    def _create_client(self) -> Optional[SnowClient]:
        """
        Create a ServiceNow client instance
        
        Returns:
            PySNCClient or None if creation fails
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
        Fetch the ServiceNow password from SSM Parameter Store
        
        Returns:
            Password or None if retrieval fails
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
        
    def __get_glide_record(self, record_type):
        """
        Prepare a Glide Record using ServiceNowClient for querying
        
        Returns:
            GlideRecord or None if retrieval fails
        """
        try:
            glide_record = self.client.GlideRecord(record_type)
            return glide_record
        except Exception as e:
            logger.error(f"Error preparing GlideRecord: {str(e)}")
            return None

    def __prepare_service_now_incident(self, glide_record: Any, fields: Dict[str, Any]):
        """
        Prepare ServiceNow Glide Record for incident creation
        
        Args:
            glide_record: ServiceNow Glide Record
            fields: ServiceNow mapped fields
            
        Returns:
            Glide record for Incident creation with added fields
        """
        glide_record.short_description = fields["short_description"]
        glide_record.description = fields["description"]
        glide_record.state = fields["state"]
        glide_record.impact = fields["impact"]
        glide_record.priority = fields["priority"]
        glide_record.incident_state = fields["incident_state"]
        glide_record.urgency = fields["urgency"]
        glide_record.severity = fields["severity"]
        glide_record.comments_and_work_notes = fields["comments_and_work_notes"]
        glide_record.category = fields["category"]
        glide_record.subcategory = fields["subcategory"]
        
        return glide_record

    def get_incident(self, incident_number: str) -> Optional[Dict[str, Any]]:
        """
        Get a ServiceNow incident by incident_number
        
        Args:
            incident_number: The ServiceNow incident_number
            
        Returns:
            Incident or None if retrieval fails
        """
        try:
            glide_record = self.__get_glide_record('incident')
            glide_record.add_query('number', incident_number)
            glide_record.query()
            if glide_record.next():
                logger.info(f"Incident details for {incident_number} from ServiceNow: {glide_record}")
                return glide_record
            
        except Exception as e:
            logger.error(f"Error getting incident details for {incident_number} from ServiceNow: {str(e)}")
            return None
    
    def create_incident(self, fields: Dict[str, Any]) -> Optional[Any]:
        """
        Create a new ServiceNow incident
        
        Args:
            fields: Dictionary of incident fields
            
        Returns:
            Created ServiceNow incident or None if creation fails
        """
        try:
            glide_record = self.__get_glide_record('incident')
            glide_record.initialize()
            glide_record = self.__prepare_service_now_incident(glide_record, fields)
            incident_sys_id = glide_record.insert() # Insert the record and get the sys_id
            logger.info(f"Incident created with sys_id: {incident_sys_id}")
            incident_number = glide_record.number
            logger.info(f"Newly created Incident Number: {incident_number}")
            return incident_number
        except Exception as e:
            logger.error(f"Incident creation failed with error: {e}")
            return None
        
    def update_incident(self, incident_number, fields: Dict[str, Any]) -> Optional[Any]:
        """
        Update an existing ServiceNow incident
        
        Args:
            incident_number: Incident number in ServiceNow to be updated
            fields: Dictionary of incident fields
            
        Returns:
            Updated ServiceNow incident or None if update fails
        """
        try:
            glide_record = self.__get_glide_record('incident')
            glide_record.add_query('number', incident_number)
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

"""
ServiceNow API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the ServiceNow API for use in the Security Incident Response integration.
"""

import os
import logging
from typing import Dict, Optional, Any

import boto3
from pysnc import ServiceNowClient

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ssm_client = boto3.client("ssm")


class ServiceNowClient:
    """Class to handle ServiceNow API interactions"""

    def __init__(self):
        """Initialize the ServiceNow client"""
        self.client = self._create_client()

    def _create_client(self) -> Optional[ServiceNowClient]:
        """
        Create a ServiceNow client instance
        
        Returns:
            ServiceNowClient or None if creation fails
        """
        try:
            instance_id = ssm_client.get_parameter(Name=os.environ["SERVICE_NOW_INSTANCE_ID"])["Parameter"]["Value"]
            username = ssm_client.get_parameter(Name=os.environ["SERVICE_NOW_USER"])["Parameter"]["Value"]
            password = self._get_password()

            if not password:
                logger.error("Failed to retrieve ServiceNow password")
                return None

            return ServiceNowClient(
                instance=instance_id,
                username=username,
                password=password
            )
        except Exception as e:
            logger.error(f"Error creating ServiceNow client: {str(e)}")
            return None

    def _get_password(self) -> Optional[str]:
        """
        Fetch the ServiceNow password from SSM Parameter Store
        
        Returns:
            Password or None if retrieval fails
        """
        try:
            password_param_name = os.environ["SERVICE_NOW_PASSWORD_PARAM"]
            response = ssm_client.get_parameter(
                Name=password_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving ServiceNow password from SSM: {str(e)}")
            return None

    def get_incident(self, incident_number: str) -> Optional[Dict[str, Any]]:
        """
        Get a ServiceNow incident by sys_id
        
        Args:
            sys_id: The ServiceNow incident sys_id
            
        Returns:
            Incident or None if retrieval fails
        """
        #TODO: This is a sample code for get_incident from Service Now using pysnc. The implementation for service_now_client event processing will cover this in detail.
        try:
            glide_record = self.client.GlideRecord('incident')
            return glide_record.get(incident_number)
        except Exception as e:
            logger.error(f"Error getting incident {incident_number} from ServiceNow API: {str(e)}")
            return None

# For backward compatibility
def get_service_now_client():
    """
    Create and return a ServiceNow client using credentials from SSM (legacy function)
    """
    client = ServiceNowClient()
    return client.client
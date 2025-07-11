"""
Service Now Field Mapper for AWS Security Incident Response Integration

This module provides mapping functionality between AWS Security Incident Response
and Service Now fields, statuses, watchers, and closure codes.
"""
import logging
from typing import Dict, List, Tuple, Any, Optional

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration-based field mappings
STATUS_MAPPING = {
    'Detection and Analysis': 'In Progress',
    'Containment, Eradication and Recovery': 'In Progress',
    'Post-Incident Activity': 'In Review',
    'Closed': 'Resolved'
}

# Default status if no mapping exists
DEFAULT_SERVICE_NOW_STATUS = 'To Do'

# Custom field mappings (Service Now field name to AWS Security Incident Response field)
FIELD_MAPPING = {
    'summary': 'title',
    'description': 'description',
    # Add additional field mappings based on Service Now instance configuration
    # Example: 'customfield_10001': 'severity',
}

# TODO: update the models/fields during the mapping implementation of Security Incident Response to Service Now fields
# TODO: see https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210466353172377?focus=true


def map_fields_to_service_now(sir_case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps AWS Security Incident Response case fields to ServiceNow fields
    
    Args:
        sir_case: Dictionary containing AWS Security Incident Response case data
        
    Returns:
        Dictionary with mapped fields for ServiceNow
    """
    service_now_fields = {}
    
    return service_now_fields

def map_case_status(sir_case_status: str) -> Tuple[str, Optional[str]]:
    """
    Maps AWS Security Incident Response case status to ServiceNow workflow status
    
    Args:
        sir_case_status: Status from AWS Security Incident Response case
        
    Returns:
        Tuple containing:
        - ServiceNow status
        - Comment to add if the mapping is not direct (None if direct mapping)
    """
    service_now_status = STATUS_MAPPING.get(sir_case_status, DEFAULT_SERVICE_NOW_STATUS)
    
    # If the mapping is not direct (i.e., multiple AWS Security Incident Response statuses map to the same ServiceNow status),
    # provide a comment for additional context
    if sir_case_status in STATUS_MAPPING and list(STATUS_MAPPING.values()).count(service_now_status) > 1:
        comment = f"AWS Security Incident Response case status updated to '{sir_case_status}' (mapped to ServiceNow status '{service_now_status}')"
        return service_now_status, comment
    
    return service_now_status, None
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
    'Detection and Analysis': '2', # For 'In Progress' state in Service Now
    'Containment, Eradication and Recovery': '2', # For 'In Progress' state in Service Now
    'Post-Incident Activity': '2', # For 'In Progress' state in Service Now
    'Closed': '7' # For 'Closed' state in Service Now
}

# Default status if no mapping exists
DEFAULT_SERVICE_NOW_STATUS = '1' # For 'New' state in Service Now

# Custom field mappings (Service Now field name to AWS Security Incident Response field)
FIELD_MAPPING = {
    'short_description': 'title',
    'description': 'description',
    'comments_and_work_notes': 'caseComments',
    # Add additional field mappings based on Service Now instance configuration
    # Example: 'u_severity': 'severity',
}

# Mandatory fields required by ServiceNow data policy
# Based on the error, Resolution code is mandatory even for new incidents
MANDATORY_FIELDS = {
    'close_code': '',  # Empty resolution code for new incidents - will be populated when closed
    'caller_id': 'System Administrator',  # Default caller - adjust based on your ServiceNow setup
    'category': 'inquiry',  # Default category
    'subcategory': 'internal application',
    'impact': '2',  # Default impact (1=High, 2=Medium, 3=Low)
    'urgency': '2',  # Default urgency (1=High, 2=Medium, 3=Low)
    'priority': '3',  # Default priority (calculated from impact/urgency)
    'state': '1',  # Default state (1=New)
    'incident_state': '1',  # Default incident state (1=New)
    'severity': '1',  # Default severity (1=High)
    # 'comments_and_work_notes': '',  # Empty comments field required by ServiceNow
}

# Resolution fields for closed incidents
RESOLUTION_FIELDS = {
    # Standard ServiceNow resolution code field
    'close_code': 'Solved (Work Around)',
    # Standard ServiceNow close notes field
    'close_notes': 'Incident resolved through AWS Security Incident Response integration',
}

# Closure code mapping
# Adjust based on actual Service Now configuration

CLOSURE_CODE_FIELD = 'u_closure_code'
DEFAULT_CLOSURE_CODE = 'Other'

# Closure code values mapping
CLOSURE_CODE_MAPPING = {
    'false_positive': 'False Positive',
    'resolved': 'Resolved',
    'duplicate': 'Duplicate',
    'benign': 'Benign',
    'expected_activity': 'Expected Activity',
    # Add other mappings as needed
}


def map_case_status(sir_case_status: str) -> Tuple[str, Optional[str]]:
    """
    Maps AWS Security Incident Response case status to Service Now workflow status

    Args:
        sir_case_status: Status from AWS Security Incident Response case

    Returns:
        Tuple containing:
        - Service Now status
        - Comment to add if the mapping is not direct (None if direct mapping)
    """
    service_now_status = STATUS_MAPPING.get(
        sir_case_status, DEFAULT_SERVICE_NOW_STATUS)

    # If the mapping is not direct (i.e., multiple AWS Security Incident Response statuses map to the same Service Now status),
    # provide a comment for additional context
    if sir_case_status in STATUS_MAPPING and list(STATUS_MAPPING.values()).count(service_now_status) > 1:
        comment = f"AWS Security Incident Response case status updated to '{sir_case_status}' (mapped to Service Now status '{service_now_status}')"
        return service_now_status, comment

    return service_now_status, None


def map_fields_to_service_now(sir_case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps AWS Security Incident Response case fields to Service Now fields

    Args:
        sir_case: Dictionary containing AWS Security Incident Response case data

    Returns:
        Dictionary with mapped fields for Service Now
    """
    service_now_fields = {}
    unmapped_fields = {}

    # Add mandatory fields required by ServiceNow data policy
    service_now_fields.update(MANDATORY_FIELDS)

    # Map fields according to configuration
    for service_now_field, sir_field in FIELD_MAPPING.items():
        if sir_field in sir_case:
            service_now_fields[service_now_field] = sir_case[sir_field]

    # Collect unmapped fields to include in description
    for key, value in sir_case.items():
        if key not in FIELD_MAPPING.values():
            # Skip complex objects, empty lists, and None values
            if value and not (isinstance(value, list) and len(value) == 0):
                if isinstance(value, (str, int, float, bool)) or (isinstance(value, list) and all(isinstance(x, (str, int, float, bool)) for x in value)):
                    unmapped_fields[key] = value

    # Handle special case for description - append unmapped fields
    if 'description' in service_now_fields and unmapped_fields:
        service_now_fields['description'] += "\n\n--- Additional AWS Security Incident Response Information ---\n"

        # Format specific fields with proper capitalization and formatting
        field_display_names = {
            'caseArn': 'Case ARN',
            'incidentStartDate': 'Incident Start Date',
            'impactedAccounts': 'Impacted Accounts',
            'impactedRegions': 'Impacted regions',
            'createdDate': 'Created Date',
            'lastUpdated': 'Last Updated',
            # Add other field mappings as needed
        }

        # Process fields in a specific order if they exist
        priority_fields = ['caseArn', 'incidentStartDate', 'impactedAccounts',
                           'impactedRegions', 'createdDate', 'lastUpdated']

        # First add priority fields in order
        for field in priority_fields:
            if field in unmapped_fields:
                display_name = field_display_names.get(
                    field, field.capitalize())
                service_now_fields['description'] += f"\n{display_name}: {unmapped_fields[field]}"
                # Remove from unmapped_fields to avoid duplication
                del unmapped_fields[field]

        # Then add any remaining unmapped fields
        for key, value in unmapped_fields.items():
            display_name = field_display_names.get(key, key.capitalize())
            service_now_fields['description'] += f"\n{display_name}: {value}"

    # Handle closure code if present
    if 'closureCode' in sir_case and sir_case.get('caseStatus') == 'Closed':
        closure_code = map_closure_code(sir_case['closureCode'])
        service_now_fields[CLOSURE_CODE_FIELD] = closure_code

    # Add resolution fields only when incident is being closed/resolved
    case_status = sir_case.get('caseStatus', '')
    mapped_state = service_now_fields.get('state', '')

    # Check if this is a closed/resolved incident
    if (case_status in ['Closed', 'Resolved'] or
            # 6=Resolved, 7=Closed in ServiceNow
            mapped_state in ['Resolved', 'Closed', '6', '7']):
        service_now_fields.update(RESOLUTION_FIELDS)

    return service_now_fields


def map_service_now_fields_to_sir(service_now_incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps Service Now fields to AWS Security Incident Response case fields

    Args:
        service_now_incident: Dictionary containing Service Now incident data

    Returns:
        Dictionary with mapped fields for AWS Security Incident Response
    """
    sir_fields = {}

    # Reverse mapping
    reverse_mapping = {
        sir_field: service_now_field for service_now_field, sir_field in FIELD_MAPPING.items()}

    for sir_field, service_now_field in reverse_mapping.items():
        if service_now_field in service_now_incident:
            sir_fields[sir_field] = service_now_incident[service_now_field]

    # Extract closure code if available
    if CLOSURE_CODE_FIELD in service_now_incident:
        service_now_closure = service_now_incident[CLOSURE_CODE_FIELD]
        sir_closure = reverse_map_closure_code(service_now_closure)
        if sir_closure:
            sir_fields['closureCode'] = sir_closure

    return sir_fields

def convert_service_now_comments_to_list(comments: str) -> List[str]:
    """
    Converts ServiceNow comments to a list of strings

    Args:
        comments (str)

    Returns:
        List[str]
    """
    extracted_lines = []
    phrases_to_convert = ['(Additional comments)', '(Work notes)']

    lines = comments.splitlines() # Split the paragraph into individual lines
    
    for i, line in enumerate(lines):
        if phrases_to_convert in line:
            # Check if there is a next line to extract
            if i + 1 < len(lines):
                extracted_lines.append(lines[i + 1].strip()) # Add the next line, stripped of leading/trailing whitespace

    return extracted_lines

def map_watchers(sir_watchers: List[Any], service_now_watchers: List[str]) -> Tuple[List[Any], List[str]]:
    """
    Maps watchers between AWS Security Incident Response and Service Now

    Args:
        sir_watchers: List of watcher objects from AWS Security Incident Response (can be strings or dicts with email field)
        service_now_watchers: List of watcher emails from Service Now

    Returns:
        Tuple containing:
        - List of watchers to add to Service Now
        - List of watchers to add to AWS Security Incident Response
    """
    # Extract emails from AWS Security Incident Response watchers for comparison
    sir_watcher_emails = []
    for watcher in sir_watchers:
        if isinstance(watcher, dict) and "email" in watcher:
            sir_watcher_emails.append(watcher["email"].lower())
        elif isinstance(watcher, str):
            sir_watcher_emails.append(watcher.lower())
        else:
            # Skip watchers that don't have a usable identifier
            logger.warning(f"Skipping watcher with invalid format: {watcher}")

    # Convert Service Now watcher emails to lowercase
    service_now_watchers_lower = [
        w.lower() for w in service_now_watchers if isinstance(w, str)]

    # Find watchers in AWS Security Incident Response that are not in Service Now
    watchers_to_add_to_service_now = []
    for i, watcher in enumerate(sir_watchers):
        watcher_email = watcher["email"].lower() if isinstance(watcher, dict) and "email" in watcher else (
            watcher.lower() if isinstance(watcher, str) else None
        )
        if watcher_email and watcher_email not in service_now_watchers_lower:
            watchers_to_add_to_service_now.append(watcher)

    # Find watchers in Service Now that are not in AWS Security Incident Response
    watchers_to_add_to_sir = []
    for i, watcher_email in enumerate(service_now_watchers_lower):
        if watcher_email not in sir_watcher_emails:
            watchers_to_add_to_sir.append(service_now_watchers[i])

    return watchers_to_add_to_service_now, watchers_to_add_to_sir


def map_closure_code(sir_closure_code: str) -> str:
    """
    Maps AWS Security Incident Response closure code to Service Now field value

    Args:
        sir_closure_code: Closure code from AWS Security Incident Response

    Returns:
        Service Now field value for closure code
    """
    return CLOSURE_CODE_MAPPING.get(sir_closure_code.lower(), DEFAULT_CLOSURE_CODE)


def reverse_map_closure_code(service_now_closure_code: str) -> Optional[str]:
    """
    Maps Service Now closure code back to AWS Security Incident Response closure code

    Args:
        service_now_closure_code: Closure code from Service Now

    Returns:
        AWS Security Incident Response closure code
    """
    # Create reverse mapping
    reverse_mapping = {v: k for k, v in CLOSURE_CODE_MAPPING.items()}
    return reverse_mapping.get(service_now_closure_code)

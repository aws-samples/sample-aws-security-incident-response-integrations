"""
JIRA Field Mapper for AWS Security Incident Response Integration

This module provides mapping functionality between AWS Security Incident Response
and JIRA fields, statuses, watchers, and closure codes.
"""
import logging
from typing import Dict, List, Tuple, Any, Optional

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration-based field mappings
STATUS_MAPPING = {
    'Acknowledged': 'In Progress',
    'Detection and Analysis': 'In Progress',
    'Containment, Eradication and Recovery': 'In Progress',
    'Post-incident Activities': 'In Review',
    'Ready to Close': 'In Review',
    'Closed': 'Done'
}

# Default status if no mapping exists
DEFAULT_JIRA_STATUS = 'To Do'

# Custom field mappings (JIRA field name to AWS Security Incident Response field)
FIELD_MAPPING = {
    'summary': 'title',
    'description': 'description',
    # Add additional field mappings based on JIRA instance configuration
    # Example: 'customfield_10001': 'severity',
}

# Closure code mapping
CLOSURE_CODE_FIELD = 'customfield_10002'  # Adjust based on actual JIRA configuration
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
    Maps AWS Security Incident Response case status to JIRA workflow status
    
    Args:
        sir_case_status: Status from AWS Security Incident Response case
        
    Returns:
        Tuple containing:
        - JIRA status
        - Comment to add if the mapping is not direct (None if direct mapping)
    """
    jira_status = STATUS_MAPPING.get(sir_case_status, DEFAULT_JIRA_STATUS)
    
    # If the mapping is not direct (i.e., multiple AWS Security Incident Response statuses map to the same JIRA status),
    # provide a comment for additional context
    if sir_case_status in STATUS_MAPPING and list(STATUS_MAPPING.values()).count(jira_status) > 1:
        comment = f"AWS Security Incident Response case status updated to '{sir_case_status}' (mapped to JIRA status '{jira_status}')"
        return jira_status, comment
    
    return jira_status, None


def map_fields_to_jira(sir_case: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps AWS Security Incident Response case fields to JIRA fields
    
    Args:
        sir_case: Dictionary containing AWS Security Incident Response case data
        
    Returns:
        Dictionary with mapped fields for JIRA
    """
    jira_fields = {}
    unmapped_fields = {}
    
    # Map fields according to configuration
    for jira_field, sir_field in FIELD_MAPPING.items():
        if sir_field in sir_case:
            jira_fields[jira_field] = sir_case[sir_field]
    
    # Collect unmapped fields to include in description
    for key, value in sir_case.items():
        if key not in FIELD_MAPPING.values():
            # Skip complex objects, empty lists, and None values
            if value and not (isinstance(value, list) and len(value) == 0):
                if isinstance(value, (str, int, float, bool)) or (isinstance(value, list) and all(isinstance(x, (str, int, float, bool)) for x in value)):
                    unmapped_fields[key] = value
    
    # Handle special case for description - append unmapped fields
    if 'description' in jira_fields and unmapped_fields:
        if jira_fields['description'].find("Additional AWS Security Incident Response Information") == -1:
            jira_fields['description'] += "\n\n--- Additional AWS Security Incident Response Information ---\n"
            
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
                    display_name = field_display_names.get(field, field.capitalize())
                    jira_fields['description'] += f"\n{display_name}: {unmapped_fields[field]}"
                    # Remove from unmapped_fields to avoid duplication
                    del unmapped_fields[field]
            
            # Then add any remaining unmapped fields
            for key, value in unmapped_fields.items():
                display_name = field_display_names.get(key, key.capitalize())
                jira_fields['description'] += f"\n{display_name}: {value}"
    
    # Handle closure code if present
    if 'closureCode' in sir_case and sir_case.get('caseStatus') == 'Closed':
        closure_code = map_closure_code(sir_case['closureCode'])
        jira_fields[CLOSURE_CODE_FIELD] = closure_code
    
    return jira_fields


def map_fields_to_sir(jira_issue: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps JIRA fields to AWS Security Incident Response case fields
    
    Args:
        jira_issue: Dictionary containing JIRA issue data
        
    Returns:
        Dictionary with mapped fields for AWS Security Incident Response
    """
    sir_fields = {}
    
    # Reverse mapping
    reverse_mapping = {sir_field: jira_field for jira_field, sir_field in FIELD_MAPPING.items()}
    
    for sir_field, jira_field in reverse_mapping.items():
        if jira_field in jira_issue:
            sir_fields[sir_field] = jira_issue[jira_field]
    
    # Extract closure code if available
    if CLOSURE_CODE_FIELD in jira_issue:
        jira_closure = jira_issue[CLOSURE_CODE_FIELD]
        sir_closure = reverse_map_closure_code(jira_closure)
        if sir_closure:
            sir_fields['closureCode'] = sir_closure
    
    return sir_fields


def map_watchers(sir_watchers: List[Any], jira_watchers: List[str]) -> Tuple[List[Any], List[str]]:
    """
    Maps watchers between AWS Security Incident Response and JIRA
    
    Args:
        sir_watchers: List of watcher objects from AWS Security Incident Response (can be strings or dicts with email field)
        jira_watchers: List of watcher emails from JIRA
        
    Returns:
        Tuple containing:
        - List of watchers to add to JIRA
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
    
    # Convert JIRA watcher emails to lowercase
    jira_watchers_lower = [w.lower() for w in jira_watchers if isinstance(w, str)]
    
    # Find watchers in AWS Security Incident Response that are not in JIRA
    watchers_to_add_to_jira = []
    for i, watcher in enumerate(sir_watchers):
        watcher_email = watcher["email"].lower() if isinstance(watcher, dict) and "email" in watcher else (
            watcher.lower() if isinstance(watcher, str) else None
        )
        if watcher_email and watcher_email not in jira_watchers_lower:
            watchers_to_add_to_jira.append(watcher)
    
    # Find watchers in JIRA that are not in AWS Security Incident Response
    watchers_to_add_to_sir = []
    for i, watcher_email in enumerate(jira_watchers_lower):
        if watcher_email not in sir_watcher_emails:
            watchers_to_add_to_sir.append(jira_watchers[i])
    
    return watchers_to_add_to_jira, watchers_to_add_to_sir


def map_closure_code(sir_closure_code: str) -> str:
    """
    Maps AWS Security Incident Response closure code to JIRA field value
    
    Args:
        sir_closure_code: Closure code from AWS Security Incident Response
        
    Returns:
        JIRA field value for closure code
    """
    return CLOSURE_CODE_MAPPING.get(sir_closure_code.lower(), DEFAULT_CLOSURE_CODE)


def reverse_map_closure_code(jira_closure_code: str) -> Optional[str]:
    """
    Maps JIRA closure code back to AWS Security Incident Response closure code
    
    Args:
        jira_closure_code: Closure code from JIRA
        
    Returns:
        AWS Security Incident Response closure code
    """
    # Create reverse mapping
    reverse_mapping = {v: k for k, v in CLOSURE_CODE_MAPPING.items()}
    return reverse_mapping.get(jira_closure_code)

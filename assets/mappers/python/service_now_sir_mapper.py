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

# Configuration-based field mappings for Service Now ITSM module
# ITSM module mappings
ITSM_STATUS_MAPPING = {
    "Detection and Analysis": "2",  # For 'In Progress' state in Service Now
    "Containment, Eradication and Recovery": "2",  # For 'In Progress' state in Service Now
    "Post-incident Activities": "2",  # For 'In Progress' state in Service Now
    "Closed": "7",  # For 'Closed' state in Service Now
}

# Default status if no mapping exists
ITSM_DEFAULT_SERVICE_NOW_STATUS = "1"  # For 'New' state in Service Now

# Custom field mappings (Service Now field name to AWS Security Incident Response field)
SNOW_FIELD_MAPPING = {
    "short_description": "title",
    "description": "description",
    "comments_and_work_notes": "caseComments",
    # Add additional field mappings based on Service Now instance configuration
    # Example: 'u_severity': 'severity',
}

# Mandatory fields required by ServiceNow data policy
# Based on the error, Resolution code is mandatory even for new incidents
ITSM_MANDATORY_FIELDS = {
    "close_code": "",  # Empty resolution code for new incidents - will be populated when closed
    "caller_id": "System Administrator",  # Default caller - adjust based on your ServiceNow setup
    "category": "inquiry",  # Default category
    "subcategory": "internal application",
    "impact": "2",  # Default impact (1=High, 2=Medium, 3=Low)
    "urgency": "2",  # Default urgency (1=High, 2=Medium, 3=Low)
    "priority": "3",  # Default priority (calculated from impact/urgency)
    "severity": "1",  # Default severity (1=High)
    "comments_and_work_notes": "",  # Empty comments field required by ServiceNow
}

# Resolution fields for closed incidents
ITSM_RESOLUTION_FIELDS = {
    # Standard ServiceNow resolution code field
    "close_code": "Solved (Work Around)",
    # Standard ServiceNow close notes field
    "close_notes": "Incident resolved through AWS Security Incident Response integration",
}

# Closure code mapping
# Adjust based on actual Service Now configuration

ITSM_CLOSURE_CODE_FIELD = "u_closure_code"
ITSM_DEFAULT_CLOSURE_CODE = "Other"

# Closure code values mapping
ITSM_CLOSURE_CODE_MAPPING = {
    "false_positive": "False Positive",
    "resolved": "Resolved",
    "duplicate": "Duplicate",
    "benign": "Benign",
    "expected_activity": "Expected Activity",
    # Add other mappings as needed
}

# Configuration-based field mappings for Service Now IR module
# IR module mappings 10, 16, 18, 19, 20, 100, 3
IR_STATUS_MAPPING = {
    "Detection and Analysis": "16",  # For 'Analysis' state in Service Now
    "Containment, Eradication and Recovery": "18",  # For 'Contain' state in Service Now. We will map AWS Security IR's status to Contain in SNOW. There are other states Eradicate, Recover separately in SNOW.
    "Post-incident Activities": "100",  # For 'Review' state in Service Now
    "Closed": "3",  # For 'Closed' state in Service Now
}

# Default status if no mapping exists
IR_DEFAULT_SERVICE_NOW_STATUS = "10"  # For 'Draft' state in Service Now

IR_MANDATORY_FIELDS = {
    # "caller_id": "System Administrator",  # Default caller - adjust based on your ServiceNow setup
    # "category": "inquiry",  # Default category
    # "subcategory": "internal application",
    "impact": "3",  # Default impact (1=Critical, 2=High, 3=Non-critical/Low)
    "urgency": "3",  # Default urgency (1=High, 2=Medium, 3=Low)
    "priority": "4",  # Default priority (1=Critical, 2=High, 3=Moderate, 4=Low, 5=Planning)
    # "severity": "1",  # Default severity (1=High)
    "comments_and_work_notes": "",  # Empty comments field required by ServiceNow
}


def map_case_status(
    sir_case_status: str, integration_module: str = "itsm"
) -> Tuple[str, Optional[str]]:
    """Map AWS Security Incident Response case status to Service Now workflow status.

    Args:
        sir_case_status (str): Status from AWS Security Incident Response case
        integration_module (str): Integration module type ('itsm' or 'ir')

    Returns:
        Tuple[str, Optional[str]]: Tuple containing:
        - Service Now status
        - Comment to add if the mapping is not direct (None if direct mapping)
    """
    if integration_module == "itsm":
        status_mapping = ITSM_STATUS_MAPPING
        default_status = ITSM_DEFAULT_SERVICE_NOW_STATUS
    elif integration_module == "ir":
        status_mapping = IR_STATUS_MAPPING
        default_status = IR_DEFAULT_SERVICE_NOW_STATUS
    else:
        logger.error(
            "No integration-module set for ServiceNow. Please re-deploy the solution with the integration module as either ITSM or IR"
        )
    #     status_mapping = ITSM_STATUS_MAPPING
    #     default_status = ITSM_DEFAULT_SERVICE_NOW_STATUS

    service_now_status = status_mapping.get(sir_case_status, default_status)

    # If the mapping is not direct (i.e., multiple AWS Security Incident Response statuses map to the same Service Now status),
    # provide a comment for additional context
    if (
        sir_case_status in status_mapping
        and list(status_mapping.values()).count(service_now_status) > 1
    ):
        comment = f"[AWS Security Incident Response Update] Case status updated to '{sir_case_status}' (mapped to Service Now status '{service_now_status}')"
        return service_now_status, comment

    return service_now_status, None


def map_sir_fields_to_service_now(
    sir_case: Dict[str, Any], integration_module: str = "itsm"
) -> Dict[str, Any]:
    """Map AWS Security Incident Response case fields to Service Now fields.

    Args:
        sir_case (Dict[str, Any]): Dictionary containing AWS Security Incident Response case data
        integration_module (str): Integration module type ('itsm' or 'ir')

    Returns:
        Dict[str, Any]: Dictionary with mapped fields for Service Now
    """
    service_now_fields = {}

    if integration_module == "itsm":
        # Add mandatory fields required by ServiceNow ITSM data policy
        service_now_fields.update(ITSM_MANDATORY_FIELDS)

        # Handle closure code if present
        if "closureCode" in sir_case and sir_case.get("caseStatus") == "Closed":
            closure_code = map_closure_code(sir_case["closureCode"])
            service_now_fields[ITSM_CLOSURE_CODE_FIELD] = closure_code

        # Add resolution fields only when incident is being closed/resolved
        case_status = sir_case.get("caseStatus", "")
        mapped_state = service_now_fields.get("state", "")

        # Check if this is a closed/resolved incident
        if (
            case_status in ["Closed", "Resolved"]
            or
            # 6=Resolved, 7=Closed in ServiceNow
            mapped_state in ["Resolved", "Closed", "6", "7"]
        ):
            service_now_fields.update(ITSM_RESOLUTION_FIELDS)
    elif integration_module == "ir":
        # Add mandatory fields required by ServiceNow IR data policy
        service_now_fields.update(IR_MANDATORY_FIELDS)

    # Map fields according to configuration
    for service_now_field, sir_field in SNOW_FIELD_MAPPING.items():
        if sir_field in sir_case:
            service_now_fields[service_now_field] = sir_case[sir_field]

    return service_now_fields


def map_sir_case_comments_to_service_now_incident(
    sir_case_comments: List[Dict[str, Any]], service_now_incident_comments: str
) -> List[str]:
    """Map AWS Security Incident Response case comments to Service Now incident comments.

    Args:
        sir_case_comments (List[Dict[str, Any]]): List of comments from AWS Security Incident Response case
        service_now_incident_comments (str): Comments string from Service Now incident

    Returns:
        List[str]: List of comments to be added to Service Now incident
    """
    UPDATE_TAG_TO_SKIP = "[service-now Update]"
    comments_list = []

    logger.info("Preparing list of comments to be added in ServiceNow incident")

    sir_case_comments_bodies = [comment["body"] for comment in sir_case_comments]

    if sir_case_comments_bodies:
        # Extract ServiceNow comments once if they exist
        logger.info(f"ServiceNow incident comments: {service_now_incident_comments}")
        service_now_incident_comments_list = []
        if service_now_incident_comments:
            service_now_incident_comments_list = convert_service_now_comments_to_list(
                service_now_incident_comments
            )

        logger.info(
            f"ServiceNow incident comments as a list: {service_now_incident_comments_list}"
        )
        for sir_case_comment in sir_case_comments_bodies:
            logger.info(f"Security IR case comment: {sir_case_comment}")

            # Skip comments with update tag
            if UPDATE_TAG_TO_SKIP in sir_case_comment:
                continue

            # Check if comment already exists in ServiceNow
            comment_exists = False
            for service_now_comment in service_now_incident_comments_list:
                logger.info(
                    "Validating if AWS Security Incident Response case comment already exists in ServiceNow incident"
                )
                logger.info(f"AWS Security IR comment: {str(sir_case_comment).strip()}")
                logger.info(f"ServiceNow comment: {str(service_now_comment).strip()}")
                if str(sir_case_comment).strip() == str(service_now_comment).strip():
                    comment_exists = True
                    break

            if not comment_exists:
                logger.info(f"Adding {sir_case_comment} comment to the list")
                comments_list.append(sir_case_comment)
            else:
                logger.info(
                    f"Comment already exists in ServiceNow, skipping: {sir_case_comment}"
                )

    logger.info(f"List of comments to be added in ServiceNow incident: {comments_list}")
    return comments_list


def convert_unmapped_fields_to_string_for_snow_comments(
    sir_case: Dict[str, Any],
) -> str:
    """Map unmapped or additional AWS Security Incident Response case fields to Service Now comments.

    Args:
        sir_case (Dict[str, Any]): Dictionary containing AWS Security Incident Response case data

    Returns:
        str: Unmapped fields in the form of a string
    """
    unmapped_fields = {}

    # Collect unmapped fields to include in description
    for key, value in sir_case.items():
        if key not in SNOW_FIELD_MAPPING.values():
            # Skip complex objects, empty lists, and None values
            if value and not (isinstance(value, list) and len(value) == 0):
                if isinstance(value, (str, int, float, bool)) or (
                    isinstance(value, list)
                    and all(isinstance(x, (str, int, float, bool)) for x in value)
                ):
                    unmapped_fields[key] = value

    # Handle special case for unmapped fields - append to comments_and_work_notes
    if unmapped_fields:
        additional_info = (
            "[AWS Security Incident Response Update] Additional Information: \n"
        )

        # Format specific fields with proper capitalization and formatting
        field_display_names = {
            "caseArn": "Case ARN",
            "incidentStartDate": "Incident Start Date",
            "impactedAccounts": "Impacted Accounts",
            "impactedRegions": "Impacted regions",
            "createdDate": "Created Date",
            "lastUpdated": "Last Updated",
            # Add other field mappings as needed
        }

        # Process fields in a specific order if they exist
        priority_fields = [
            "caseArn",
            "incidentStartDate",
            "impactedAccounts",
            "impactedRegions",
            "createdDate",
            "lastUpdated",
        ]

        # First add priority fields in order
        for field in priority_fields:
            if field in unmapped_fields:
                display_name = field_display_names.get(field, field.capitalize())
                additional_info += f"\n{display_name}: {unmapped_fields[field]}"
                # Remove from unmapped_fields to avoid duplication
                del unmapped_fields[field]

        # Then add any remaining unmapped fields
        for key, value in unmapped_fields.items():
            display_name = field_display_names.get(key, key.capitalize())
            additional_info += f"\n{display_name}: {value}"

    return additional_info.strip()


def map_service_now_fields_to_sir(
    service_now_incident: Dict[str, Any], integration_module: str = "itsm"
) -> Dict[str, Any]:
    """Map Service Now fields to AWS Security Incident Response case fields.

    Args:
        service_now_incident (Dict[str, Any]): Dictionary containing Service Now incident data
        integration_module (str): Integration module type ('itsm' or 'ir')

    Returns:
        Dict[str, Any]: Dictionary with mapped fields for AWS Security Incident Response
    """
    sir_fields = {}

    # TODO: Move the below setup (for an integration target), which is being invoked from the handlers, outside of the lambdas to speed up processing like a pre-compute (see: https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210991530761708)
    # Reverse mapping
    reverse_mapping = {
        sir_field: service_now_field
        for service_now_field, sir_field in SNOW_FIELD_MAPPING.items()
    }

    for sir_field, service_now_field in reverse_mapping.items():
        if service_now_field in service_now_incident:
            sir_fields[sir_field] = service_now_incident[service_now_field]

    # Extract closure code if available - only for ITSM integration
    if integration_module == "itsm":
        if ITSM_CLOSURE_CODE_FIELD in service_now_incident:
            service_now_closure = service_now_incident[ITSM_CLOSURE_CODE_FIELD]
            sir_closure = reverse_map_closure_code(service_now_closure)
            if sir_closure:
                sir_fields["closureCode"] = sir_closure

    return sir_fields


def map_service_now_incident_comments_to_sir_case(
    service_now_incident_comments: str, sir_case_comments: List[Dict[str, Any]]
) -> List[str]:
    """Map ServiceNow incident comments to Security IR case comments.

    Args:
        service_now_incident_comments (str): ServiceNow incident comments
        sir_case_comments (List[Dict[str, Any]]): Security IR case comments

    Returns:
        List[str]: List of comments to be added to Security IR case
    """
    UPDATE_TAG_TO_SKIP = "[AWS Security Incident Response Update]"
    comments_list = []

    logger.info("Preparing list of comments to be added in Security IR case")

    # extract ServiceNow incident comments in a list for validation, comparison and updates to SIR case
    service_now_incident_comments_list = convert_service_now_comments_to_list(
        service_now_incident_comments
    )

    sir_case_comments_bodies = [comment["body"] for comment in sir_case_comments]

    for service_now_incident_comment in service_now_incident_comments_list:
        logger.info(
            f"Validating if ServiceNow incident comment: {service_now_incident_comment}, exists in Security IR or not"
        )

        # Skip comments with update tag
        if UPDATE_TAG_TO_SKIP in service_now_incident_comment:
            continue

        # Check if comment already exists in SIR case
        comment_exists = False
        if sir_case_comments_bodies:
            for sir_case_comment in sir_case_comments_bodies:
                if (
                    str(service_now_incident_comment).strip()
                    == str(sir_case_comment).strip()
                ):
                    comment_exists = True
                    break

        if not comment_exists:
            logger.info(f"Adding {service_now_incident_comment} comment to the list")
            comments_list.append(service_now_incident_comment)
        else:
            logger.info(
                f"Comment already exists in SIR case, skipping: {service_now_incident_comment}"
            )

    logger.info(f"List of comments to be added in Security IR case: {comments_list}")
    return comments_list


def convert_service_now_comments_to_list(comments: str) -> List[str]:
    """Convert ServiceNow comments to a list of strings.

    Extracts lines following specific phrases like '(Additional comments)' and '(Work notes)'.

    Args:
        comments (str): ServiceNow comments string to parse

    Returns:
        List[str]: List of extracted comment lines
    """
    if not comments:
        return []

    lines = comments.strip().split("\n")
    comments_list = []
    current_comment = []

    for line in lines:
        if "(Work notes)" in line or "(Additional comments)" in line:
            if current_comment:
                comments_list.append("\n".join(current_comment).strip())
                current_comment = []
        else:
            current_comment.append(line)

    if current_comment:
        comments_list.append("\n".join(current_comment).strip())

    return [comment for comment in comments_list if comment]


def validate_if_comment_needs_to_be_added(
    source_comment, dest_comment, tag_to_skip
) -> bool:
    """Validate if a comment needs to be added to the destination.

    Args:
        source_comment (str): The comment to be validated
        dest_comment (str): The destination comment to be validated against
        tag_to_skip (str): The tag to be skipped in the validation

    Returns:
        bool: True if the comment needs to be added, False otherwise
    """
    UPDATE_TAG_TO_SKIP = tag_to_skip
    add_comment = True
    if UPDATE_TAG_TO_SKIP in source_comment:
        add_comment = False
    logger.info(f"Source comment: {source_comment}")
    logger.info(f"Destination comment: {dest_comment}")
    if str(source_comment).strip() == str(dest_comment).strip():
        add_comment = False
    return add_comment


def map_watchers(
    sir_watchers: List[Any], service_now_watchers: List[str]
) -> Tuple[List[Any], List[str]]:
    """Map watchers between AWS Security Incident Response and Service Now.

    Args:
        sir_watchers (List[Any]): List of watcher objects from AWS Security Incident Response (can be strings or dicts with email field)
        service_now_watchers (List[str]): List of watcher emails from Service Now

    Returns:
        Tuple[List[Any], List[str]]: Tuple containing:
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
        w.lower() for w in service_now_watchers if isinstance(w, str)
    ]

    # Find watchers in AWS Security Incident Response that are not in Service Now
    watchers_to_add_to_service_now = []
    for i, watcher in enumerate(sir_watchers):
        watcher_email = (
            watcher["email"].lower()
            if isinstance(watcher, dict) and "email" in watcher
            else (watcher.lower() if isinstance(watcher, str) else None)
        )
        if watcher_email and watcher_email not in service_now_watchers_lower:
            watchers_to_add_to_service_now.append(watcher)

    # TODO: Move the below setup (for an integration target), which is being invoked from the handlers, outside of the lambdas to speed up processing like a pre-compute (see: https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210991530761708)
    # Find watchers in Service Now that are not in AWS Security Incident Response
    watchers_to_add_to_sir = []
    for i, watcher_email in enumerate(service_now_watchers_lower):
        if watcher_email not in sir_watcher_emails:
            watchers_to_add_to_sir.append(service_now_watchers[i])

    return watchers_to_add_to_service_now, watchers_to_add_to_sir


def map_closure_code(sir_closure_code: str) -> str:
    """Map AWS Security Incident Response closure code to Service Now field value.

    Args:
        sir_closure_code (str): Closure code from AWS Security Incident Response

    Returns:
        str: Service Now field value for closure code
    """
    return ITSM_CLOSURE_CODE_MAPPING.get(
        sir_closure_code.lower(), ITSM_DEFAULT_CLOSURE_CODE
    )


# TODO: Move the below setup (for an integration target), which is being invoked from the handlers, outside of the lambdas to speed up processing like a pre-compute (see: https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210991530761708)
def reverse_map_closure_code(service_now_closure_code: str) -> Optional[str]:
    """Map Service Now closure code back to AWS Security Incident Response closure code.

    Args:
        service_now_closure_code (str): Closure code from Service Now

    Returns:
        Optional[str]: AWS Security Incident Response closure code or None if not found
    """
    # Create reverse mapping
    reverse_mapping = {v: k for k, v in ITSM_CLOSURE_CODE_MAPPING.items()}
    return reverse_mapping.get(service_now_closure_code)

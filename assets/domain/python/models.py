"""
Domain models for security incident response.
"""

import logging

# Configure logging
logger = logging.getLogger()


class Case:
    """
    Domain model for a security incident case
    """

    def __init__(
        self,
        case_id,
        title,
        description,
        severity,
        status,
        created_at,
        updated_at=None,
        case_arn=None,
        engagement_type=None,
        reported_incident_start_date=None,
        impacted_aws_regions=None,
        threat_actor_ip_addresses=None,
        pending_action=None,
        impacted_accounts=None,
        watchers=None,
        resolver_type=None,
        impacted_services=None,
        case_comments=None,
        case_attachments=None,
    ):
        """
        Initialize a Case

        Args:
            case_id (str): Case ID
            title (str): Case title
            description (str): Case description
            severity (str): Case severity
            status (str): Case status
            created_at (datetime): Case creation time
            updated_at (datetime, optional): Case update time
            case_arn (str, optional): Case ARN
            engagement_type (str, optional): Engagement type
            reported_incident_start_date (datetime, optional): Reported incident start date
            impacted_aws_regions (list, optional): List of impacted AWS regions
            threat_actor_ip_addresses (list, optional): List of threat actor IP addresses
            pending_action (str, optional): Pending action
            impacted_accounts (list, optional): List of impacted accounts
            watchers (list, optional): List of watchers
            resolver_type (str, optional): Resolver type
            impacted_services (list, optional): List of impacted services
            case_comments (list, optional): List of case comments
            case_attachments (list, optional): List of case attachments
        """
        self.case_id = case_id
        self.title = title
        self.description = description
        self.severity = severity
        self.status = status
        self.created_at = created_at
        self.updated_at = updated_at or created_at
        self.case_arn = case_arn
        self.engagement_type = engagement_type
        self.reported_incident_start_date = reported_incident_start_date
        self.impacted_aws_regions = impacted_aws_regions or []
        self.threat_actor_ip_addresses = threat_actor_ip_addresses or []
        self.pending_action = pending_action
        self.impacted_accounts = impacted_accounts or []
        self.watchers = watchers or []
        self.resolver_type = resolver_type
        self.impacted_services = impacted_services or []
        self.case_comments = case_comments or []
        self.case_attachments = case_attachments or []

    def to_dict(self):
        """Convert the case to a dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the case
        """
        return {
            "caseId": self.case_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "caseArn": self.case_arn,
            "engagementType": self.engagement_type,
            "reportedIncidentStartDate": self.reported_incident_start_date,
            "impactedAwsRegions": self.impacted_aws_regions,
            "threatActorIpAddresses": self.threat_actor_ip_addresses,
            "pendingAction": self.pending_action,
            "impactedAccounts": self.impacted_accounts,
            "watchers": self.watchers,
            "resolverType": self.resolver_type,
            "impactedServices": self.impacted_services,
            "caseComments": self.case_comments,
            "caseAttachments": self.case_attachments,
        }


def create_case_from_api_response(response):
    """Create a Case domain model from an API response.

    Args:
        response (dict): API response

    Returns:
        Case: Case domain model
    """
    logger.debug(f"Creating Case from API response: {response.get('caseId')}")
    return Case(
        case_id=response.get("caseId"),
        title=response.get("title"),
        description=response.get("description", ""),
        severity=response.get("severity", "Unknown"),
        status=response.get("caseStatus"),
        created_at=response.get("createdAt") or response.get("createdDate"),
        updated_at=response.get("updatedAt") or response.get("lastUpdatedDate"),
        case_arn=response.get("caseArn"),
        engagement_type=response.get("engagementType"),
        reported_incident_start_date=response.get("reportedIncidentStartDate"),
        impacted_aws_regions=response.get("impactedAwsRegions"),
        threat_actor_ip_addresses=response.get("threatActorIpAddresses"),
        pending_action=response.get("pendingAction"),
        impacted_accounts=response.get("impactedAccounts"),
        watchers=response.get("watchers"),
        resolver_type=response.get("resolverType"),
        impacted_services=response.get("impactedServices"),
        case_comments=response.get("caseComments", []),
        case_attachments=response.get("caseAttachments", []),
    )

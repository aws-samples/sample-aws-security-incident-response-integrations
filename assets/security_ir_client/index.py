"""
Security IR Client Lambda function for AWS Security Incident Response integration.
This module handles the creation and updating of Security IR cases based on Jira issues.
"""

import json
import os
import re
import logging
import datetime
from typing import List, Dict, Optional, Any, Tuple, Union
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

UPDATE_TAG_TO_SKIP = "[AWS Security Incident Response Update]"
ITSM_NAME = "TBD"

# Try to import from Lambda layer
try:
    # This import works for lambda function and imports the lambda layer at runtime
    from jira_sir_mapper import (
        map_case_status,
        map_fields_to_sir,
        map_closure_code,
    )
    from security_ir_wrapper import SecurityIRClient
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..mappers.python.jira_sir_mapper import (
        Case,
        create_case_from_api_response,
        map_fields_to_sir as map_jira_fields_to_sir,
    )
    from ..wrappers.python.security_ir_wrapper import SecurityIRClient

try:
    from service_now_sir_mapper import (
        map_case_status,
        map_security_now_fields_to_sir,
        map_closure_code,
    )
except ImportError:
    from ..mappers.python.service_now_sir_mapper import (
        Case,
        create_case_from_api_response,
        map_security_now_fields_to_sir,
    )

# Get log level from environment variable
log_level = os.environ.get("LOG_LEVEL", "error").lower()
if log_level == "debug":
    logger.setLevel(logging.DEBUG)
elif log_level == "info":
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

# Remove after dev/test
logger.setLevel(logging.INFO)

# Initialize AWS clients
security_ir_client = boto3.client("security-ir")


def process_service_now_event(security_now_incident: dict) -> None:
    incident_service = IncidentService()
    database_service = DatabaseService()

    logger.info("Processing ServiceNow event")
    security_ir_fields = map_security_now_fields_to_sir(security_now_incident)
    service_now_incident_id = security_now_incident["number"]

    security_ir_status = map_case_status(security_now_incident["state"])
    # join dict objects
    security_ir_fields = security_ir_fields | {"status": security_ir_status[0]}
    # add fields to incident object
    security_ir_fields["key"] = service_now_incident_id
    security_ir_fields["source"] = "servicenow"

    # determine if this is an incident created or incident updated event
    event_type = security_now_incident["event_type"]

    if "created" in event_type.lower():
        security_ir_case_id = incident_service.create_incident_in_sir(
            security_ir_incident=security_ir_fields
        )
        security_ir_fields["caseId"] = security_ir_case_id
        logger.info("New Security IR case created: %s", security_ir_case_id)

        # get latest security_ir now that all fields have been updated
        #  and store it in the database
        security_ir_incident = incident_service.get_incident_from_sir(
            security_ir_case_id
        )

        if security_ir_incident:
            security_ir_incident["caseId"] = security_ir_case_id
            database_service.store_issue_details_in_dynamodb(security_ir_incident, "servicenow")

    elif "updated" in event_type.lower():
        # if it's an update then an entry for the incident must already exist in the database
        security_ir_case_id = database_service.get_incident_id_from_dynamodb(
            issue_id=service_now_incident_id, event_source="servicenow"
        )

        if security_ir_case_id:
            security_ir_fields["caseId"] = security_ir_case_id
            _ = incident_service.update_incident_details_in_sir(
                security_ir_case=security_ir_fields
            )

        # get latest security_ir now that all fields have been updated
        #  and store it in the database
        security_ir_incident = incident_service.get_incident_from_sir(
            security_ir_case_id
        )

        if security_ir_incident:
            security_ir_incident["caseId"] = security_ir_case_id
            database_service.store_issue_details_in_dynamodb(security_ir_incident, "servicenow")

    return


def process_jira_event(jira_issue: dict) -> None:
    """
    Creates or updates Security Incident Response Case based on an incoming Jira Issue details

    Args:
        Jira Issue dict

    Returns:
        None
    """
    logger.info("Processing Jira event")

    # map Jira issue to Security Incident Response case
    jira_event_type = jira_issue["eventType"]
    jira_issue_key = jira_issue["key"]
    jira_issue_status = jira_issue["status"]

    # map Jira issue status to Security IR case status
    ir_case_status = None
    if jira_issue_status == "To Do":
        ir_case_status = "Submitted"
    elif jira_issue_status == "In Progress":
        ir_case_status = "Detection and Analysis"
    elif jira_issue_status == "Done":
        ir_case_status = "Closed"

    # map fields from issue to case
    security_ir_fields = map_fields_to_sir(jira_issue)
    security_ir_fields["caseStatus"] = ir_case_status
    security_ir_fields["key"] = jira_issue_key

    database_service = DatabaseService()
    incident_service = IncidentService()

    # create incident in Security IR via API
    security_ir_case_id = "0"
    if jira_event_type == "IssueCreated":
        security_ir_case_id = incident_service.create_incident_in_sir(
            security_ir_incident=security_ir_fields
        )
        security_ir_fields["caseId"] = security_ir_case_id

        # add attachments
        if jira_issue["attachments"]:
            for attachment in jira_issue["attachments"]:
                attachment_filename = attachment["filename"]
                _ = incident_service.add_incident_attachment_in_sir(
                    security_ir_case_id=security_ir_case_id,
                    attachment_filename=attachment_filename,
                )

    elif jira_event_type == "IssueUpdated":
        # get case ID from ddb
        security_ir_case_id = database_service.get_incident_id_from_dynamodb(
            issue_id=jira_issue_key, event_source="jira")

        if security_ir_case_id:
            security_ir_fields["caseId"] = security_ir_case_id
            _ = incident_service.update_incident_details_in_sir(
                security_ir_case=security_ir_fields
            )

            # get comments for matching sir case
            sir_comments = incident_service.get_incident_comments_from_sir(
                security_ir_case_id=security_ir_case_id
            )
            jira_comments = jira_issue["comments"]
            sir_comment_bodies = [comment["body"] for comment in sir_comments["items"]]
            jira_comment_bodies = [comment["body"] for comment in jira_comments]

            for jira_comment in jira_comment_bodies:
                add_comment = True

                if UPDATE_TAG_TO_SKIP in jira_comment:
                    add_comment = False

                for sir_comment in sir_comment_bodies:
                    if str(jira_comment).strip() == str(sir_comment).strip():
                        add_comment = False

                if add_comment is True:
                    logger.info(
                        "Adding comment '%s' to Security IR case %s",
                        jira_comment,
                        security_ir_case_id,
                    )
                    _ = incident_service.add_incident_comment_in_sir(
                        security_ir_case_id=security_ir_case_id,
                        ir_case_comment=jira_comment,
                    )

            # TODO: add missing attachments as files to case
            # security_ir_case = incident_service.get_incident_from_sir(
            #     security_ir_case_id
            # )
            # security_ir_case_attachments = security_ir_case["caseAttachments"]
            # security_ir_filenames = [
            #     security_ir_attachment["fileName"]
            #     for security_ir_attachment in security_ir_case_attachments
            # ]

            #  add incoming attachments as comments for now
            jira_issue_attachments = jira_issue["attachments"]
            jira_attachment_filenames = [
                jira_attachment["filename"]
                for jira_attachment in jira_issue_attachments
            ]

            # determine whether this is a new attachment before adding
            for jira_attachment_name in jira_attachment_filenames:
                add_attachment_comment = True
                for sir_comment in sir_comment_bodies:
                    if jira_attachment_name in sir_comment:
                        add_attachment_comment = False

                # only add a comment for new attachments
                if add_attachment_comment is True:
                    # add attachment to Security IR case
                    _ = incident_service.add_incident_attachment_in_sir(
                        security_ir_case_id=security_ir_case_id,
                        attachment_filename=jira_attachment_name,
                    )
                    logger.info(
                        f"Added attachment to Security IR case {security_ir_case_id}"
                    )

        else:  # create case because doesn't exist in database
            logger.info(
                f"Security IR case not found for {jira_issue_key} not found in database. Creating ..."
            )

            # create incident in Security Incident Response
            security_ir_case_id = incident_service.create_incident_in_sir(
                security_ir_incident=security_ir_fields
            )

    # get latest security_ir now that all fields have been updated
    #  and store it in the database
    security_ir_incident = incident_service.get_incident_from_sir(
        security_ir_case_id
    )
    if security_ir_incident:
        security_ir_incident["caseId"] = security_ir_case_id
        database_service.store_issue_details_in_dynamodb(security_ir_incident, "jira")


class DatabaseService:
    """Class to handle database operations"""
    __dynamodb = boto3.resource("dynamodb")
    __table_name = os.environ["INCIDENTS_TABLE_NAME"]
    __ddb_table = __dynamodb.Table(__table_name)
    __dynamodb_client = boto3.client("dynamodb")
    #TODO: use dynamodb resource only

    def __init__(self):
        """Initialize the database manager"""


    def get_incident_id_from_dynamodb(self, issue_id: str, event_source: str) -> str:
        """
        Fetch Case Id associated with Issue Id in Jira

        Args:
            Issue Id

        Returns:create_incident_in_sir
            Security Incident Response Case Id
        """
        attr_name = ""
        if event_source == "jira":
            attr_name = "jiraIssueId"
        elif event_source == "servicenow":
            attr_name = "serviceNowIncidentId"
        try:
            response = self.__ddb_table.scan(
                FilterExpression=Attr(attr_name).eq(issue_id), Limit=1000
            )
            if response["Items"] == []:
                logger.info(
                    f"Security IR case for {event_source} issue {issue_id} not found in database"
                )
                security_ir_case_id = None
            else:
                security_ir_case_id = response["Items"][0]["PK"]
                security_ir_case_id = re.search(
                    r"Case#(\d+)", security_ir_case_id
                ).group(1)
                logger.info(f"Security IR case ID: {security_ir_case_id}")

            return security_ir_case_id

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(
                f"Error retrieving details from the DynamoDB table: {error_code}"
            )
            return None
        except KeyError:
            logger.info(f"Jira issue for Case#{jira_issue_id} not found in database")
            return None


    def store_issue_details_in_dynamodb(self, incident: dict, event_source: str) -> bool:
        """
        Store or update incidents in DynamoDB

        Args:
            incidents: List of incidents to store
            event_source: source of event (ITSM)

        Returns:
            Boolean indicating success or failure
        """
        if not incident or not self.__table_name:
            logger.warning("No incidents or table name provided")
            return False

        try:
            case_id = incident["caseId"]
            case_status = incident["caseStatus"]

            if case_status != "Closed":
                # skip closed incidents
                print(f"Processing incident id: {case_id}")

                # Check if incident exists in DynamoDB
                existing_incident = self.__dynamodb_client.get_item(
                    TableName=self.__table_name,
                    Key={"PK": {"S": f"Case#{case_id}"}, "SK": {"S": "latest"}},
                ).get("Item", {})

                if existing_incident:
                    # Update existing incident if details have changed
                    existing_details = json.loads(
                        existing_incident.get("incidentDetails", {}).get("S", "{}")
                    )
                    if event_source == "jira":
                        field_name = "jiraIssueDetails"
                    if event_source == "servicenow":
                        field_name = "serviceNowIncidentDetails"
                    
                    if existing_details != incident:
                        self.__dynamodb_client.update_item(
                            TableName=self.__table_name,
                            Key={"PK": {"S": f"Case#{case_id}"}, "SK": {"S": "latest"}},
                            UpdateExpression="SET incidentDetails = :incidentDetails",
                            ExpressionAttributeValues={
                                ":incidentDetails": {
                                    "S": json.dumps(
                                        incident, default=self.json_datetime_encoder
                                    )
                                }
                            },
                        )
                        logger.info("Incident %s updated in database", case_id)

                else:
                    # Create new incident
                    self.__dynamodb_client.put_item(
                        TableName=self.__table_name,
                        Item={
                            "PK": {"S": f"Case#{case_id}"},
                            "SK": {"S": "latest"},
                            "incidentDetails": {
                                "S": json.dumps(
                                    incident, default=self.json_datetime_encoder
                                )
                            },
                        },
                    )
                    logger.info("Incident %s added to database", case_id)

            return True

        except Exception as e:
            logger.error(f"Error storing incident in DynamoDB: {str(e)}")
            return False

    def json_datetime_encoder(self, obj: Any) -> str:
        """
        JSON encoder for datetime objects

        Args:
            obj: Object to encode

        Returns:
            String representation of datetime or raises TypeError
        """
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")


class IncidentService:
    """Class to handle security IR incident operations"""

    __database_service = DatabaseService()
    __security_ir_client = boto3.client("security-ir")
    #TODO: use SecurityIRClient wrapper instead

    def __init__(self):
        """Initialize the incident manager"""

    def update_incident_details_in_sir(self, security_ir_case: dict) -> bool:
        """
        Updates Security IR case using API

        Args:
            Security IR case

        Returns:
            result of update attempt
        """
        security_ir_case_id = security_ir_case["caseId"]
        # TODO: Add watcher support
        # watchers
        # logger.info(f"Security IR case {security_ir_case}")
        # if security_ir_case["watchers"]:
        #     logger.info(f"Watchers: {security_ir_case["watchers"]}")

        #     request_kwargs = {
        #         'caseId': security_ir_case_id,
        #         'watchers': security_ir_case["watchers"]
        #     }
        #     _ = security_ir_client.update_watchers(**request_kwargs)

        # update case
        try:
            # update case content
            request_kwargs = {
                "caseId": security_ir_case_id,
                "title": security_ir_case["title"],
                "description": security_ir_case["description"],
            }
            _ = self.__security_ir_client.update_case(**request_kwargs)

        except Exception as e:
            logger.error(
                f"Error updating Security IR case {security_ir_case_id} details: {str(e)}"
            )
            return False
        
        try:
            # update case status
            _ = self.update_incident_status_in_sir(security_ir_case)

        except Exception as e:
            logger.error(
                f"Error updating Security IR case {security_ir_case_id} status: {str(e)}"
            )
            return False

        return True

    def update_incident_status_in_sir(self, security_ir_case: dict) -> bool:
        """
        Updates Security IR case status using API

        Args:
            Security IR case

        Returns:
            result of update status attempt
        """
        security_ir_case_id = security_ir_case["caseId"]
        security_ir_case_status = security_ir_case["caseStatus"]

        if security_ir_case_status == "Closed":
            try:
                request_kwargs = {"caseId": security_ir_case_id}
                _ = self.__security_ir_client.close_case(**request_kwargs)
                logger.info(f"Closed Security IR case {security_ir_case_id}")
            except Exception as e1:
                logger.error(
                    f"Could not close Security IR case {security_ir_case_id}: {e1}"
                )
                return False

        elif security_ir_case_status != "Submitted":
            try:
                request_kwargs = {
                    "caseId": security_ir_case_id,
                    "caseStatus": security_ir_case_status,
                }
                # TODO: Support different case status transitions so that case can be set
                # to any status via update from Jira
                update_result = self.__security_ir_client.update_case_status(**request_kwargs)
                logger.info(
                    f"Updated status of Security IR case {security_ir_case_id}: {update_result}"
                )
                return True

            except Exception as e:
                logger.error(
                    f"Could not update status of Security IR case {security_ir_case_id} to {security_ir_case_status}: {str(e)}"
                )

                return False

        return True

    def get_incident_comments_from_sir(
        self, security_ir_case_id: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch comments associated with Security IR case

        Args:
            Security IR case ID

        Returns:
            List of comments
        """
        # TODO: add pagination support for comments

        request_kwargs = {"caseId": security_ir_case_id, "maxResults": 25}
        sir_comments = self.__security_ir_client.list_comments(**request_kwargs)

        return sir_comments

    def add_incident_comment_in_sir(
        self, security_ir_case_id: str, ir_case_comment: str
    ) -> bool:
        """
        Add comment to Security IR case

        Args:
            Security IR case ID
            Comment to add to Security IR case

        Returns:
            True if successful, False otherwise
        """

        try:
            request_kwargs = {"caseId": security_ir_case_id, "body": ir_case_comment}
            _ = self.__security_ir_client.create_case_comment(**request_kwargs)
        except Exception as e:
            logger.error(
                f"Error adding comment to Security IR case {security_ir_case_id}: {str(e)}"
            )
            return False

        return True

    def create_incident_in_sir(self, security_ir_incident: dict) -> str:
        """
        Create a new case in Security IR based on Jira issue

        Args:
            incident details

        Returns:
            Security IR case ID
        """
        # create current datetime object
        current_datetime = datetime.datetime
        current_datetime_str = current_datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_source = security_ir_incident["source"].strip()
        event_source_map = {
            "servicenow": "ServiceNow",
            "jira": "Jira",
            "slack": "Slack"
        }
        
        event_source_description = event_source_map.get(event_source, "Unknown")

        # 1. create case in Security IR
        try:
            # get account ID for default
            sts_client = boto3.client("sts")
            response = sts_client.get_caller_identity()
            self_account_id = response["Account"]

            # create default values in case none are provided in the Jira issue
            default_impacted_accounts = [self_account_id]
            default_watchers = [
                {
                    "email": "admin@amazon.com",
                    "name": "Admin",
                    "jobTitle": "To be added",
                }
            ]
            default_impacted_regions = [{"region": "us-east-1"}]
            default_threat_actor_ip_addresses = [
                {"ipAddress": "1.2.3.4", "userAgent": "To be added"}
            ]

            security_ir_description = security_ir_incident.get(
                "description", "Description not provided"
            )
            
            security_ir_description += f"\n\nThis Security Incident Response case was created as a result of a {event_source_description} issue being created."
            security_ir_description += (
                f"\n\nRelated {event_source_description} issue: {security_ir_incident['key']}"
            )

            request_kwargs = {
                "title": security_ir_incident.get("title", "Unknown"),
                "description": security_ir_description,
                "engagementType": "Security Incident",
                "resolverType": "Self",
                "reportedIncidentStartDate": current_datetime_str,
                "impactedAccounts": default_impacted_accounts,
                "watchers": default_watchers,
                "threatActorIpAddresses": default_threat_actor_ip_addresses,
                "impactedAwsRegions": default_impacted_regions,
                "impactedServices": ["TBD"],
            }
            logger.info(
                f"Required values not provided in {event_source_description} issue, using default values for Security IR case creation. Please update the Security IR case with actual values."
            )

            # get newly-created case
            security_ir_case = self.__security_ir_client.create_case(**request_kwargs)
            security_ir_case_id = security_ir_case["caseId"]

            # # add to database
            security_ir_incident = self.get_incident_from_sir(security_ir_case_id)
            security_ir_incident["caseId"] = security_ir_case_id

        except Exception as e:
            logger.error(f"Error creating Security IR case: {e}")
            return None

        return security_ir_case_id

    def get_incident_from_sir(self, security_ir_case_id: str) -> dict:
        """
        Gets Security IR case based on case ID

        Args:
            Security IR case ID

        Returns:
            Security IR case (dict)
        """
        try:
            kwargs = {"caseId": security_ir_case_id}
            security_ir_case = self.__security_ir_client.get_case(**kwargs)
            return security_ir_case

        except Exception as e:
            logger.error(
                f"Error retrieving Security IR case {security_ir_case_id}: {str(e)}"
            )
            return None

    def add_incident_attachment_in_sir(
        self, security_ir_case_id: str, attachment_filename: str
    ) -> bool:
        """
        Create a new case in Security IR based on ITSM issue
        For now we are going to add a comment as we need to get the attachment binary
        from the ITSM case in order to attach it

        Args:
            Security IR case ID
            Attachment name

        Returns:
            True if add is successful, False otherwise
        """
        comment = f"[{ITSM_NAME} Update] {ITSM_NAME} issue has an attachment: {attachment_filename}. Download the file from the associated ITSM issue."

        try:
            # TODO: add support to copy binary file attachment from Jira to Security IR
            _ = self.add_incident_comment_in_sir(security_ir_case_id, comment)
        except Exception as e:
            logger.info(
                f"Error adding attachment to Security IR case {security_ir_case_id}: {str(e)}"
            )
            return False

        return True


def handler(event, context) -> dict:
    """
    Lambda handler to process jira events/notifications

    Args:
        event: Lambda event object
        context: Lambda context object

    Returns:
        Dictionary containing response status and details
    """
    # only process events from jira
    # determine type of event to process it correctly
    event_source = ""
    try:
        event_source = event["source"]
    except:
        logger.info("Event does not have source field")

        try:
            event_source = event["sys_id"]
            event_source = "servicenow"
        except:
            logger.info("Event does not have sys_id field")

    if event_source == "jira":
        ITSM_NAME = "Jira"
        process_jira_event(event)        

    elif event_source == "servicenow":
        ITSM_NAME = "ServiceNow"
        process_service_now_event(event)
    
    elif event_source == "slack":
        ITSM_NAME = "Slack"

    return {
        "statusCode": 200,
        "body": json.dumps(
            "Security Incident Response Client Lambda function processing completed"
        ),
    }

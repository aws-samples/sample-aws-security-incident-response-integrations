"""
Security IR Client Lambda function for AWS Security Incident Response integration.
This module handles the creation and updating of Security IR cases based on Jira issues.
"""

import json
import os
import re
import logging
import datetime
from typing import List, Dict, Optional, Any
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr
import requests

# Configure logging
logger = logging.getLogger()

# Get log level from environment variable
log_level = os.environ.get("LOG_LEVEL", "error").lower()
if log_level == "debug":
    logger.setLevel(logging.DEBUG)
elif log_level == "info":
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

# Constants
JIRA_EVENT_SOURCE = os.environ.get("JIRA_EVENT_SOURCE", "jira")
SERVICE_NOW_EVENT_SOURCE = os.environ.get("SERVICE_NOW_EVENT_SOURCE", "service-now")
UPDATE_TAG_TO_SKIP = "[AWS Security Incident Response Update]"

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from service_now_wrapper import ServiceNowClient
    from service_now_sir_mapper import (
        map_service_now_fields_to_sir,
        map_service_now_incident_comments_to_sir_case,
    )
    from jira_sir_mapper import (
        map_fields_to_sir,
    )
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..wrappers.python.service_now_wrapper import ServiceNowClient
    from ..mappers.python.service_now_sir_mapper import (
        map_service_now_fields_to_sir,
        map_service_now_incident_comments_to_sir_case,
    )
    from ..mappers.python.jira_sir_mapper import (
        map_fields_to_sir,
    )

# Initialize AWS clients
security_ir_client = boto3.client("security-ir")


def process_service_now_event(
    service_now_incident: dict, event_source: str, integration_module: str = "itsm"
) -> None:
    """Process ServiceNow event and create/update Security IR case.

    Args:
        service_now_incident (dict): ServiceNow incident details
        event_source (str): Source of the event
        integration_module (str): Integration module type ('itsm' or 'ir')
    """
    if not service_now_incident:
        logger.error("ServiceNow incident data is None or empty")
        return

    service_now_event_type = service_now_incident.get("eventType", "")
    logger.info(f"Processing ServiceNow event {service_now_event_type}")

    # map ServiceNow incident to Security Incident Response case
    service_now_incident_id = service_now_incident.get("number", "")
    service_now_issue_status = service_now_incident.get("state", "")

    if not service_now_incident_id:
        logger.error("ServiceNow incident number is missing")
        return

    # map ServiceNow incident state to Security Incident Response case status based on integration module
    ir_case_status = "Submitted"  # Default status

    if integration_module == "itsm":
        # ITSM status mapping
        if service_now_issue_status in [
            "Closed",
            "Resolved",
            "Canceled",
            "6",
            "7",
            "8",
        ]:
            ir_case_status = "Closed"
        elif service_now_issue_status in ["In Progress", "On Hold", "2", "3"]:
            ir_case_status = "Detection and Analysis"
        elif service_now_issue_status in ["New", "1"]:
            ir_case_status = "Submitted"
    elif integration_module == "ir":
        # IR status mapping
        if service_now_issue_status in ["Closed", "3"]:
            ir_case_status = "Closed"
        elif service_now_issue_status in ["Review", "100"]:
            ir_case_status = "Post-incident Activities"
        elif service_now_issue_status in [
            "Contain",
            "Eradicate",
            "Recover",
            "18",
            "19",
            "20",
        ]:
            ir_case_status = "Containment, Eradication and Recovery"
        elif service_now_issue_status in ["Analysis", "16"]:
            ir_case_status = "Detection and Analysis"
        elif service_now_issue_status in ["Draft", "10"]:
            ir_case_status = "Submitted"
    else:
        # Default to ITSM mapping
        if service_now_issue_status in [
            "Closed",
            "Resolved",
            "Canceled",
            "6",
            "7",
            "8",
        ]:
            ir_case_status = "Closed"
        elif service_now_issue_status in ["In Progress", "On Hold", "2", "3"]:
            ir_case_status = "Detection and Analysis"
        elif service_now_issue_status in ["New", "1"]:
            ir_case_status = "Submitted"

    # map fields from incident to case
    security_ir_fields = map_service_now_fields_to_sir(
        service_now_incident, integration_module
    )
    security_ir_fields["caseStatus"] = ir_case_status
    security_ir_fields["key"] = service_now_incident_id

    incident_service = IncidentService()
    database_service = DatabaseService()

    if "created" in service_now_event_type.lower():
        security_ir_case_id = incident_service.create_incident_in_sir(
            security_ir_incident=security_ir_fields,
            event_source=event_source,
        )
        security_ir_fields["caseId"] = security_ir_case_id
        logger.info(f"New Security IR case created: {security_ir_case_id}")

    elif "updated" in service_now_event_type.lower():
        # if it's an update then an entry for the incident must already exist in the database
        logger.info(
            f"Getting Security IR case id from DDB for: {service_now_incident_id}"
        )
        security_ir_case_id = database_service.get_incident_id_from_dynamodb(
            service_now_incident_id, event_source
        )

        if security_ir_case_id:
            # Get current Security IR case details to compare for changes
            current_sir_case = incident_service.get_incident_from_sir(
                security_ir_case_id
            )

            if current_sir_case:
                # Check if there are actual changes before updating
                needs_update = False

                # Compare title
                if current_sir_case.get("title") != security_ir_fields.get("title"):
                    needs_update = True
                    logger.info(
                        f"Title changed: {current_sir_case.get('title')} -> {security_ir_fields.get('title')}"
                    )

                # Compare description
                if current_sir_case.get("description") != security_ir_fields.get(
                    "description"
                ):
                    needs_update = True
                    logger.info(
                        f"Description changed: {current_sir_case.get('description')}"
                    )

                # Compare status
                if current_sir_case.get("caseStatus") != security_ir_fields.get(
                    "caseStatus"
                ):
                    needs_update = True
                    logger.info(
                        f"Status changed: {current_sir_case.get('caseStatus')} -> {security_ir_fields.get('caseStatus')}"
                    )

                if needs_update:
                    security_ir_fields["caseId"] = security_ir_case_id
                    _ = incident_service.update_incident_details_in_sir(
                        security_ir_case=security_ir_fields
                    )
                    logger.info(
                        f"Updated Security IR case {security_ir_case_id} due to changes"
                    )
                else:
                    logger.info(
                        f"No changes detected for Security IR case {security_ir_case_id}, skipping update"
                    )
            else:
                # If we can't get current case details, proceed with update
                security_ir_fields["caseId"] = security_ir_case_id
                _ = incident_service.update_incident_details_in_sir(
                    security_ir_case=security_ir_fields
                )
        else:
            # Create case in Security IR since no record entry exists for the ServiceNow incident in the database
            security_ir_case_id = incident_service.create_incident_in_sir(
                security_ir_incident=security_ir_fields,
                event_source=event_source,
            )
            security_ir_fields["caseId"] = security_ir_case_id

    # Add comments as applicable to the SIR case
    # get comments for matching sir case
    sir_case_comments = incident_service.get_incident_comments_from_sir(
        security_ir_case_id=security_ir_case_id
    )

    # extract ServiceNow incident comments in a list for validation, comparison and updates to SIR case
    service_now_incident_comments = service_now_incident.get(
        "comments_and_work_notes", ""
    )

    logger.info(
        f"Mapping ServiceNow incident comments to Security IR case : {service_now_incident_comments}"
    )
    comments_list = map_service_now_incident_comments_to_sir_case(
        service_now_incident_comments, sir_case_comments["items"]
    )

    if comments_list:
        for comment in comments_list:
            logger.info(
                f"Adding {comment} comment to Security IR case {security_ir_case_id}"
            )
            _ = incident_service.add_incident_comment_in_sir(
                security_ir_case_id=security_ir_case_id,
                ir_case_comment=comment,
            )

    # Add attachments to the SIR case
    # get attachments for matching sir case
    security_ir_case_filenames = []
    security_ir_incident = incident_service.get_incident_from_sir(security_ir_case_id)
    if security_ir_incident:
        security_ir_case_attachments = security_ir_incident.get("caseAttachments")
        if security_ir_case_attachments:
            security_ir_case_filenames = [
                security_ir_attachment["fileName"]
                for security_ir_attachment in security_ir_case_attachments
            ]

    #  add incoming attachments as comments for now
    service_now_incident_filenames = []
    service_now_incident_attachments = service_now_incident["attachments"]
    if service_now_incident_attachments:
        for service_now_incident_attachment in service_now_incident_attachments:
            service_now_incident_filenames.append(
                service_now_incident_attachment["filename"]
            )
        for service_now_incident_attachment_name in service_now_incident_filenames:
            logger.info(
                f"ServiceNow incident filenames: {service_now_incident_filenames}"
            )
            if security_ir_case_filenames:
                if service_now_incident_attachment_name in security_ir_case_filenames:
                    logger.info(
                        f"Attachment {service_now_incident_attachment_name} already exists in Security IR case"
                    )
                    continue
                # add attachment to Security IR case
                logger.info(
                    f"Uploading attachment {service_now_incident_attachment_name} to Security IR case {security_ir_case_id}"
                )
                _ = incident_service.add_incident_attachment_in_sir(
                    security_ir_case_id=security_ir_case_id,
                    attachment_filename=service_now_incident_attachment_name,
                    event_source=event_source,
                    incident_number=service_now_incident_id,
                )
                logger.info(
                    f"Uploaded attachment {service_now_incident_attachment_name} to Security IR case {security_ir_case_id}"
                )
            else:
                # add attachment to Security IR case
                logger.info(
                    f"Uploading attachment {service_now_incident_attachment_name} to Security IR case {security_ir_case_id}"
                )
                _ = incident_service.add_incident_attachment_in_sir(
                    security_ir_case_id=security_ir_case_id,
                    attachment_filename=service_now_incident_attachment_name,
                    event_source=event_source,
                    incident_number=service_now_incident_id,
                )
                logger.info(
                    f"Uploaded attachment {service_now_incident_attachment_name} to Security IR case {security_ir_case_id}"
                )

    # get latest security_ir now that all fields have been updated
    # and store it in the database
    security_ir_incident = incident_service.get_incident_from_sir(security_ir_case_id)

    if security_ir_incident:
        security_ir_incident["caseId"] = security_ir_case_id
        database_service.store_incident_in_dynamodb(security_ir_incident)


def process_jira_event(jira_issue: dict, event_source: str) -> None:
    """Create or update Security Incident Response Case based on incoming Jira Issue details.

    Args:
        jira_issue (dict): Jira issue details
        event_source (str): Source of the event
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
            security_ir_incident=security_ir_fields,
            event_source=event_source,
        )
        security_ir_fields["caseId"] = security_ir_case_id

        # add attachments
        if jira_issue["attachments"]:
            for attachment in jira_issue["attachments"]:
                attachment_filename = attachment["filename"]
                _ = incident_service.add_incident_attachment_in_sir(
                    security_ir_case_id=security_ir_case_id,
                    attachment_filename=attachment_filename,
                    event_source=event_source,
                )

    elif jira_event_type == "IssueUpdated":
        # get case ID from ddb
        security_ir_case_id = database_service.get_incident_id_from_dynamodb(
            jira_issue_key,
            event_source=event_source,
        )

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

            # TODO: add missing attachments as files to case (see https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210991530761700?focus=true)
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
                        event_source=event_source,
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
                security_ir_incident=security_ir_fields,
                event_source=event_source,
            )

    # get latest security_ir now that all fields have been updated
    #  and store it in the database
    security_ir_incident = incident_service.get_incident_from_sir(security_ir_case_id)
    if security_ir_incident:
        security_ir_incident["caseId"] = security_ir_case_id
        database_service.store_incident_in_dynamodb(security_ir_incident)


class ParameterService:
    """Class to handle parameter operations."""

    def __init__(self):
        """Initialize the parameter service."""
        self.ssm_client = boto3.client("ssm")

    def get_parameter(self, parameter_name: str) -> Optional[str]:
        """
        Get a parameter from SSM Parameter Store.

        Args:
            parameter_name (str): The name of the parameter to retrieve

        Returns:
            Optional[str]: Parameter value or None if retrieval fails
        """
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving parameter {parameter_name}: {error_code}")
            return None


class DatabaseService:
    """Class to handle database operations."""

    __dynamodb = boto3.resource("dynamodb")
    __table_name = os.environ["INCIDENTS_TABLE_NAME"]
    __ddb_table = __dynamodb.Table(__table_name)
    __dynamodb_client = boto3.client("dynamodb")

    def __init__(self):
        """Initialize the database service."""

    def get_incident_id_from_dynamodb(
        self, record_id: str, event_source: str
    ) -> Optional[str]:
        """Fetch Case Id associated with Record Id of the integration target.

        Args:
            record_id (str): Record ID from integration target
            event_source (str): Source of the event

        Returns:
            Optional[str]: Security Incident Response Case Id or None if not found
        """
        attr_name = ""
        if event_source == JIRA_EVENT_SOURCE:
            attr_name = "jiraIssueId"
        elif event_source == SERVICE_NOW_EVENT_SOURCE:
            attr_name = "serviceNowIncidentId"
        try:
            response = self.__ddb_table.scan(
                FilterExpression=Attr(attr_name).eq(record_id)
            )
            items = response["Items"]

            # Handle pagination if there are more items
            while "LastEvaluatedKey" in response:
                response = self.table.scan(
                    FilterExpression=Attr(attr_name).eq(record_id),
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                items.extend(response["Items"])

            if not items:
                logger.info(
                    f"Security IR case for {event_source} issue/incident {record_id} not found in database"
                )
                security_ir_case_id = None
            else:
                security_ir_case_id = items[0]["PK"]
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
            logger.info(
                f"{event_source} issue/incident for Case#{record_id} not found in database"
            )
            return None

    def store_incident_in_dynamodb(self, incident: dict) -> bool:
        """Store or update incident in DynamoDB.

        Args:
            incident (dict): Incident to store

        Returns:
            bool: Boolean indicating success or failure
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
        """JSON encoder for datetime objects.

        Args:
            obj (Any): Object to encode

        Returns:
            str: String representation of datetime or raises TypeError
        """
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        raise TypeError(f"Type {type(obj)} not serializable")


class ServiceNowService:
    """Class to handle ServiceNow operations for Security IR integration."""

    def __init__(self, instance_id, username, password_param_name):
        """Initialize the ServiceNow service.

        Args:
            instance_id (str): ServiceNow instance ID
            username (str): ServiceNow username
            password_param_name (str): SSM parameter name containing password
        """

        self.service_now_client = ServiceNowClient(
            instance_id, username, password_param_name
        )

    def get_incident_attachment_data(
        self, incident_number: str, attachment_filename: str
    ):
        """Get attachment data from ServiceNow incident.

        Args:
            incident_number (str): ServiceNow incident number
            attachment_filename (str): Name of the attachment file

        Returns:
            dict: Dictionary containing attachment data and content type, or None if retrieval fails
        """
        if not self.service_now_client:
            logger.error("ServiceNow client not initialized")
            return None

        try:
            # Get the incident record
            integration_module = os.environ.get("INTEGRATION_MODULE", "itsm")
            glide_record = self.service_now_client.get_incident(
                incident_number, integration_module
            )
            if not glide_record:
                logger.error(f"Incident {incident_number} not found in ServiceNow")
                return None

            # Get attachment data using the wrapper method
            attachment_data = self.service_now_client.get_incident_attachment_data(
                glide_record, attachment_filename
            )
            return attachment_data

        except Exception as e:
            logger.error(f"Error getting attachment data from ServiceNow: {str(e)}")
            return None


class IncidentService:
    """Class to handle security IR incident operations."""

    __database_service = DatabaseService()
    __security_ir_client = boto3.client("security-ir")
    # TODO: use SecurityIRClient wrapper instead

    def __init__(self):
        """Initialize the incident service."""

    def update_incident_details_in_sir(self, security_ir_case: dict) -> bool:
        """Update Security IR case using API.

        Args:
            security_ir_case (dict): Security IR case details

        Returns:
            bool: Result of update attempt
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
        """Update Security IR case status using API.

        Args:
            security_ir_case (dict): Security IR case details

        Returns:
            bool: Result of update status attempt
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
                update_result = self.__security_ir_client.update_case_status(
                    **request_kwargs
                )
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
        """Fetch comments associated with Security IR case.

        Args:
            security_ir_case_id (str): Security IR case ID

        Returns:
            List[Dict[str, Any]]: List of comments
        """
        # TODO: add pagination support for comments

        request_kwargs = {"caseId": security_ir_case_id, "maxResults": 25}
        sir_comments = self.__security_ir_client.list_comments(**request_kwargs)

        return sir_comments

    def add_incident_comment_in_sir(
        self, security_ir_case_id: str, ir_case_comment: str
    ) -> bool:
        """Add comment to Security IR case.

        Args:
            security_ir_case_id (str): Security IR case ID
            ir_case_comment (str): Comment to add to Security IR case

        Returns:
            bool: True if successful, False otherwise
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

    def create_incident_in_sir(
        self, security_ir_incident: dict, event_source: str
    ) -> Optional[str]:
        """Create a new case in Security IR based on the integration target.

        Args:
            security_ir_incident (dict): Incident details
            event_source (str): Source of the event

        Returns:
            Optional[str]: Security IR case ID or None if creation fails
        """
        # create current datetime object
        current_datetime = datetime.datetime
        current_datetime_str = current_datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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

            security_ir_description += f"\n\nThis Security Incident Response case was created as a result of a {event_source} issue/incident."
            security_ir_description += f"\n\nRelated {event_source} issue/incident: {security_ir_incident['key']}"

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
                f"Required values not provided in {event_source} issue/incident, using default values for Security IR case creation. Please update the Security IR case with actual values."
            )

            # get newly-created case
            security_ir_case = self.__security_ir_client.create_case(**request_kwargs)
            security_ir_case_id = security_ir_case["caseId"]

            # # add to database
            security_ir_incident = self.get_incident_from_sir(security_ir_case_id)
            security_ir_incident["caseId"] = security_ir_case_id

        except Exception as e:
            logger.error(f"Error creating Security IR case: {str(e)}")
            return None

        return security_ir_case_id

    def get_incident_from_sir(self, security_ir_case_id: str) -> Optional[dict]:
        """Get Security IR case based on case ID.

        Args:
            security_ir_case_id (str): Security IR case ID

        Returns:
            Optional[dict]: Security IR case details or None if retrieval fails
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
        self,
        security_ir_case_id: str,
        attachment_filename: str,
        event_source: str,
        incident_number: str = None,
    ) -> bool:
        """Add an attachment to a Security IR case based on the event_source.

        For ServiceNow events, attempts to retrieve and upload attachment data.
        For other events, adds a comment about the attachment.

        Args:
            security_ir_case_id (str): Security IR case ID
            attachment_filename (str): Attachment filename
            event_source (str): Source of the event
            incident_number (str): ServiceNow incident number (required for ServiceNow)

        Returns:
            bool: True if add is successful, False otherwise
        """
        try:
            if event_source == SERVICE_NOW_EVENT_SOURCE and incident_number:
                parameter_service = ParameterService()
                # Get credentials from SSM
                instance_id = parameter_service.get_parameter(
                    os.environ.get("SERVICE_NOW_INSTANCE_ID")
                )
                logger.info(f"instance: {instance_id}")
                username = parameter_service.get_parameter(
                    os.environ.get("SERVICE_NOW_USERNAME")
                )
                password_param_name = os.environ.get("SERVICE_NOW_PASSWORD_PARAM_NAME")

                service_now_service = ServiceNowService(
                    instance_id, username, password_param_name
                )

                # Get attachment data from ServiceNow
                attachment_data = service_now_service.get_incident_attachment_data(
                    incident_number, attachment_filename
                )

                if attachment_data:
                    # get the content length of the attachment for uploading to AWS Security Incident Response case
                    attachment_content = attachment_data.get("attachment_content")
                    content_length = attachment_data.get("attachment_content_length")

                    # Get upload URL from Security IR
                    upload_response = (
                        self.__security_ir_client.get_case_attachment_upload_url(
                            caseId=security_ir_case_id,
                            fileName=attachment_filename,
                            contentLength=int(content_length),
                        )
                    )

                    if upload_response:
                        attachment_upload_presigned_url = upload_response[
                            "attachmentPresignedUrl"
                        ]
                        logger.info(
                            f"Successfully retrieved upload URL for attachment {attachment_filename} to Security IR case {security_ir_case_id}: {attachment_upload_presigned_url}"
                        )
                        logger.info(
                            f"Successfully retrieved the attachment content: {attachment_content}"
                        )

                        # Upload attachment data to Security IR
                        response = requests.put(
                            attachment_upload_presigned_url,
                            data=attachment_content,
                            headers={
                                "If-None-Match": "*",
                                "Content-Length": content_length,
                                "Content-Type": "application/octet-stream",
                            },
                        )

                        if response.status_code == 200:
                            logger.info(
                                f"Successfully uploaded attachment {attachment_filename} to Security IR case {security_ir_case_id}"
                            )
                            return True
                        else:
                            logger.error(
                                f"Failed to upload attachment: {response.status_code}"
                            )
                            # Fall back to comment
                            comment = f"[{event_source} Update] Failed to upload attachment: {attachment_filename}. Download from ServiceNow incident {incident_number}."
                            _ = self.add_incident_comment_in_sir(
                                security_ir_case_id, comment
                            )
                    else:
                        logger.error("Failed to get upload URL from Security IR")
                        # Fall back to comment
                        comment = f"[{event_source} Update] {event_source} incident has an attachment: {attachment_filename}. Download from ServiceNow incident {incident_number}."
                        _ = self.add_incident_comment_in_sir(
                            security_ir_case_id, comment
                        )
                else:
                    # Fall back to comment if attachment data not found
                    comment = f"[{event_source} Update] {event_source} incident has an attachment: {attachment_filename}. Download from ServiceNow incident {incident_number}."
                    _ = self.add_incident_comment_in_sir(security_ir_case_id, comment)
            else:
                # For other event sources or missing incident_number, add a comment
                comment = f"[{event_source} Update] {event_source} incident/issue has an attachment: {attachment_filename}. Download the file from the associated {event_source} incident/issue."
                _ = self.add_incident_comment_in_sir(security_ir_case_id, comment)

        except Exception as e:
            logger.error(
                f"Error adding attachment to Security IR case {security_ir_case_id}: {str(e)}"
            )
            return False

        return True


def handler(event, context) -> dict:
    """Lambda handler to process Jira and ServiceNow events/notifications.

    Args:
        event (dict): Lambda event object containing event source and details
        context: Lambda context object

    Returns:
        dict: Dictionary containing response status and details
    """
    # determine type of event to process it correctly
    event_source = ""

    try:
        event_source = event["source"]
    except Exception as e:
        logger.info(f"Event does not have source field: {str(e)}")

    if event_source == JIRA_EVENT_SOURCE:
        logger.info(
            "Received Jira event. Security Incident Response Client lambda handler will process this event."
        )
        process_jira_event(event.get("detail"), event_source)

    elif event_source == SERVICE_NOW_EVENT_SOURCE:
        logger.info(
            "Received ServiceNow event. Security Incident Response Client lambda handler will process this event."
        )
        # Get integration module once
        integration_module = os.environ.get("INTEGRATION_MODULE", "itsm")
        process_service_now_event(event.get("detail"), event_source, integration_module)

    return {
        "statusCode": 200,
        "body": json.dumps(
            "Security Incident Response Client Lambda function processing completed"
        ),
    }

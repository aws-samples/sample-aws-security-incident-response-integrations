"""
Enhanced DynamoDB schema operations for Slack integration.

This module provides enhanced DynamoDB operations that include Slack-specific attributes
while maintaining compatibility with existing integrations.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()


class EnhancedDynamoDBService:
    """Enhanced DynamoDB service with Slack integration support"""

    def __init__(self, table_name: str):
        """Initialize the enhanced DynamoDB service.

        Args:
            table_name (str): Name of the DynamoDB table
        """
        self.table_name = table_name
        self.dynamodb = boto3.resource("dynamodb")
        self.table = self.dynamodb.Table(table_name)
        self.dynamodb_client = boto3.client("dynamodb")

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get a case from the database.

        Args:
            case_id (str): The IR case ID

        Returns:
            Optional[Dict[str, Any]]: Case data or None if retrieval fails
        """
        try:
            response = self.table.get_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"}
            )
            return response.get("Item")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(
                f"Error retrieving case {case_id} from DynamoDB table: {error_code}"
            )
            return None

    def update_slack_mapping(
        self,
        case_id: str,
        slack_channel_id: str,
        case_description: Optional[str] = None,
        case_title: Optional[str] = None,
        case_comments: Optional[List[str]] = None
    ) -> bool:
        """Update the Slack mapping for a case.

        Args:
            case_id (str): The IR case ID
            slack_channel_id (str): The Slack channel ID
            case_description (Optional[str]): Case description
            case_title (Optional[str]): Case title
            case_comments (Optional[List[str]]): List of case comments

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            update_expression = "SET slackChannelId = :channel_id, slackChannelUpdateTimestamp = :timestamp"
            expression_values = {
                ":channel_id": slack_channel_id,
                ":timestamp": datetime.utcnow().isoformat()
            }

            if case_description is not None:
                update_expression += ", slackChannelCaseDescription = :description"
                expression_values[":description"] = case_description

            if case_title is not None:
                update_expression += ", slackChannelCaseTitle = :title"
                expression_values[":title"] = case_title

            if case_comments is not None:
                update_expression += ", slackChannelCaseComments = :comments"
                expression_values[":comments"] = case_comments

            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW",
            )
            logger.info(f"IR case {case_id} mapped to Slack channel {slack_channel_id}")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error updating Slack mapping in DynamoDB table: {error_code}")
            return False

    def get_slack_channel_id(self, case_id: str) -> Optional[str]:
        """Get the Slack channel ID for a case.

        Args:
            case_id (str): The IR case ID

        Returns:
            Optional[str]: Slack channel ID or None if not found
        """
        case_data = self.get_case(case_id)
        if case_data:
            return case_data.get("slackChannelId")
        return None

    def update_slack_case_details(
        self,
        case_id: str,
        case_description: Optional[str] = None,
        case_title: Optional[str] = None,
        case_comments: Optional[List[str]] = None
    ) -> bool:
        """Update Slack-specific case details.

        Args:
            case_id (str): The IR case ID
            case_description (Optional[str]): Updated case description
            case_title (Optional[str]): Updated case title
            case_comments (Optional[List[str]]): Updated list of case comments

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            update_expression_parts = ["slackChannelUpdateTimestamp = :timestamp"]
            expression_values = {":timestamp": datetime.utcnow().isoformat()}

            if case_description is not None:
                update_expression_parts.append("slackChannelCaseDescription = :description")
                expression_values[":description"] = case_description

            if case_title is not None:
                update_expression_parts.append("slackChannelCaseTitle = :title")
                expression_values[":title"] = case_title

            if case_comments is not None:
                update_expression_parts.append("slackChannelCaseComments = :comments")
                expression_values[":comments"] = case_comments

            if len(update_expression_parts) == 1:
                # Only timestamp update, nothing else to do
                return True

            update_expression = "SET " + ", ".join(update_expression_parts)

            self.table.update_item(
                Key={"PK": f"Case#{case_id}", "SK": "latest"},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW",
            )
            logger.info(f"Updated Slack case details for case {case_id}")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error updating Slack case details in DynamoDB: {error_code}")
            return False

    def add_slack_comment(self, case_id: str, comment: str) -> bool:
        """Add a comment to the Slack case comments list.

        Args:
            case_id (str): The IR case ID
            comment (str): Comment to add

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # First, get current comments
            case_data = self.get_case(case_id)
            if not case_data:
                logger.error(f"Case {case_id} not found")
                return False

            current_comments = case_data.get("slackChannelCaseComments", [])
            
            # Check if comment already exists to prevent duplicates
            if comment in current_comments:
                logger.info(f"Comment already exists for case {case_id}, skipping duplicate")
                return True

            # Add new comment
            current_comments.append(comment)

            return self.update_slack_case_details(
                case_id=case_id,
                case_comments=current_comments
            )
        except Exception as e:
            logger.error(f"Error adding Slack comment for case {case_id}: {str(e)}")
            return False

    def get_slack_case_details(self, case_id: str) -> Dict[str, Any]:
        """Get Slack-specific case details.

        Args:
            case_id (str): The IR case ID

        Returns:
            Dict[str, Any]: Dictionary containing Slack case details
        """
        case_data = self.get_case(case_id)
        if not case_data:
            return {}

        return {
            "slackChannelId": case_data.get("slackChannelId"),
            "slackChannelCaseDescription": case_data.get("slackChannelCaseDescription"),
            "slackChannelCaseTitle": case_data.get("slackChannelCaseTitle"),
            "slackChannelCaseComments": case_data.get("slackChannelCaseComments", []),
            "slackChannelUpdateTimestamp": case_data.get("slackChannelUpdateTimestamp")
        }

    def find_case_by_slack_channel(self, slack_channel_id: str) -> Optional[str]:
        """Find a case ID by Slack channel ID.

        Args:
            slack_channel_id (str): The Slack channel ID

        Returns:
            Optional[str]: Case ID or None if not found
        """
        try:
            response = self.table.query(
                IndexName="slack-channel-index",
                KeyConditionExpression="slackChannelId = :channel_id",
                ExpressionAttributeValues={":channel_id": slack_channel_id}
            )

            items = response.get("Items", [])

            # Handle pagination if there are more items
            while "LastEvaluatedKey" in response:
                response = self.table.query(
                    IndexName="slack-channel-index",
                    KeyConditionExpression="slackChannelId = :channel_id",
                    ExpressionAttributeValues={":channel_id": slack_channel_id},
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                items.extend(response.get("Items", []))

            if not items:
                logger.info(f"No case found for Slack channel {slack_channel_id}")
                return None

            # Extract case ID from PK
            pk = items[0]["PK"]
            case_id = pk.replace("Case#", "")
            logger.info(f"Found case {case_id} for Slack channel {slack_channel_id}")
            return case_id

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error finding case by Slack channel: {error_code}")
            return None

    def check_comment_exists(self, case_id: str, comment: str) -> bool:
        """Check if a comment already exists for a case.

        Args:
            case_id (str): The IR case ID
            comment (str): Comment to check

        Returns:
            bool: True if comment exists, False otherwise
        """
        case_data = self.get_case(case_id)
        if not case_data:
            return False

        current_comments = case_data.get("slackChannelCaseComments", [])
        return comment in current_comments

    def get_last_update_timestamp(self, case_id: str) -> Optional[str]:
        """Get the last update timestamp for a case.

        Args:
            case_id (str): The IR case ID

        Returns:
            Optional[str]: Last update timestamp or None if not found
        """
        case_data = self.get_case(case_id)
        if case_data:
            return case_data.get("slackChannelUpdateTimestamp")
        return None

    def validate_schema_compatibility(self) -> bool:
        """Validate that the enhanced schema is compatible with existing integrations.

        Returns:
            bool: True if compatible, False otherwise
        """
        try:
            # Test that we can still read existing records without Slack attributes
            response = self.table.scan(Limit=1)
            items = response.get("Items", [])
            
            if items:
                item = items[0]
                # Check that existing attributes are still accessible
                required_keys = ["PK", "SK"]
                for key in required_keys:
                    if key not in item:
                        logger.error(f"Missing required key {key} in DynamoDB item")
                        return False
                        
                logger.info("Schema compatibility validation passed")
                return True
            else:
                logger.info("No items found for schema validation, assuming compatible")
                return True
                
        except Exception as e:
            logger.error(f"Schema compatibility validation failed: {str(e)}")
            return False
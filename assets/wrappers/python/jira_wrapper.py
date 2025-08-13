"""
Jira API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the Jira API for use in the Security Incident Response integration.
"""

import os
import logging
from typing import List, Dict, Optional, Any, Union

import boto3
from jira import JIRA

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ssm_client = boto3.client("ssm")

# Import mappers with fallbacks for different environments
try:
    from jira_sir_mapper import map_watchers
except ImportError:
    try:
        from assets.mappers.python.jira_sir_mapper import map_watchers
    except ImportError:
        from ...mappers.python.jira_sir_mapper import map_watchers


class JiraClient:
    """Class to handle Jira API interactions"""

    def __init__(self):
        """Initialize the Jira client."""
        self.client = self._create_client()

    def _create_client(self) -> Optional[JIRA]:
        """Create a Jira client instance.

        Returns:
            Optional[JIRA]: JIRA client or None if creation fails
        """
        try:
            jira_email = ssm_client.get_parameter(Name=os.environ["JIRA_EMAIL"])[
                "Parameter"
            ]["Value"]
            jira_url = ssm_client.get_parameter(Name=os.environ["JIRA_URL"])[
                "Parameter"
            ]["Value"]
            jira_token = self._get_token()

            if not jira_token:
                logger.error("Failed to retrieve Jira token")
                return None

            return JIRA(server=jira_url, basic_auth=(jira_email, jira_token))
        except Exception as e:
            logger.error(f"Error creating Jira client: {str(e)}")
            return None

    def _get_token(self) -> Optional[str]:
        """Fetch the Jira API token from SSM Parameter Store.

        Returns:
            Optional[str]: API token or None if retrieval fails
        """
        try:
            jira_token_param_name = os.environ["JIRA_TOKEN_PARAM"]
            response = ssm_client.get_parameter(
                Name=jira_token_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving Jira token from SSM: {str(e)}")
            return None

    def get_issue(self, issue_id: str) -> Optional[Any]:
        """Get a Jira issue by ID.

        Args:
            issue_id (str): The Jira issue ID

        Returns:
            Optional[Any]: Jira issue object or None if retrieval fails
        """
        try:
            return self.client.issue(issue_id)
        except Exception as e:
            logger.error(f"Error getting issue {issue_id} from Jira API: {str(e)}")
            return None

    def create_issue(self, fields: Dict[str, Any]) -> Optional[Any]:
        """Create a new Jira issue.

        Args:
            fields (Dict[str, Any]): Dictionary of issue fields

        Returns:
            Optional[Any]: Created Jira issue or None if creation fails
        """
        try:
            return self.client.create_issue(fields=fields)
        except Exception as e:
            logger.error(f"Error creating Jira issue: {str(e)}")
            return None

    def update_issue(self, issue_id: str, fields: Dict[str, Any]) -> bool:
        """Update a Jira issue.

        Args:
            issue_id (str): The Jira issue ID
            fields (Dict[str, Any]): Dictionary of issue fields to update

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            issue = self.client.issue(issue_id)
            issue.update(fields=fields)
            return True
        except Exception as e:
            logger.error(f"Error updating Jira issue {issue_id}: {str(e)}")
            return False

    def update_status(
        self, issue_id: str, status: str, comment: Optional[str] = None
    ) -> bool:
        """Update the status of a Jira issue.

        Args:
            issue_id (str): The Jira issue ID
            status (str): Target status to transition to
            comment (Optional[str]): Optional comment to add with the status update

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get current issue to check status
            issue = self.client.issue(issue_id)
            current_status = issue.fields.status.name

            # Only attempt transition if status is different
            if current_status != status:
                # Get available transitions
                transitions = self.client.transitions(issue_id)
                for t in transitions:
                    if t["to"]["name"].lower() == status.lower():
                        self.client.transition_issue(issue_id, t["id"])
                        logger.info(f"Transitioned issue {issue_id} to {status}")
                        break
                else:
                    logger.error(
                        f"Could not transition issue to {status}, no valid transition found"
                    )
                    return False

                # Add status comment if needed
                if comment:
                    self.client.add_comment(issue_id, comment)

            return True
        except Exception as e:
            logger.error(f"Error updating status for Jira issue {issue_id}: {str(e)}")
            return False

    def add_comment(self, issue_id: str, comment: str) -> bool:
        """Add a comment to a Jira issue.

        Args:
            issue_id (str): The Jira issue ID
            comment (str): Comment text

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.client.add_comment(issue_id, comment)
            return True
        except Exception as e:
            logger.error(f"Error adding comment to Jira issue {issue_id}: {str(e)}")
            return False

    def add_attachment(self, issue_id: str, file_obj) -> bool:
        """Add an attachment to a Jira issue.

        Args:
            issue_id (str): The Jira issue ID
            file_obj: File object to attach

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.client.add_attachment(issue=issue_id, attachment=file_obj)
            return True
        except Exception as e:
            logger.error(f"Error adding attachment to Jira issue {issue_id}: {str(e)}")
            return False

    def add_watchers(
        self, issue_id: str, watchers: List[Union[str, Dict[str, str]]]
    ) -> None:
        """Add watchers to a Jira issue.

        Args:
            issue_id (str): The Jira issue ID
            watchers (List[Union[str, Dict[str, str]]]): List of watchers to add (can be strings or dicts with email field)
        """
        if not watchers:
            return

        for watcher in watchers:
            try:
                # Extract email from watcher if it's a dictionary
                watcher_id = (
                    watcher["email"]
                    if isinstance(watcher, dict) and "email" in watcher
                    else watcher
                )
                self.client.add_watcher(issue_id, watcher_id)
            except Exception as e:
                logger.error(f"Could not add watcher {watcher} to Jira issue: {e}")

    def sync_watchers(
        self, issue_id: str, sir_watchers: List[Union[str, Dict[str, str]]]
    ) -> None:
        """Sync watchers between SIR and Jira.

        Args:
            issue_id (str): The Jira issue ID
            sir_watchers (List[Union[str, Dict[str, str]]]): List of watchers from SIR
        """
        try:
            # Get current JIRA watchers
            jira_watchers = [
                watcher.emailAddress
                for watcher in self.client.watchers(issue_id).watchers
            ]

            # Map and add missing watchers
            watchers_to_add, _ = map_watchers(sir_watchers, jira_watchers)
            self.add_watchers(issue_id, watchers_to_add)
        except Exception as e:
            logger.error(f"Error syncing watchers for Jira issue {issue_id}: {str(e)}")

#!/usr/bin/env python3
"""
Slack Parameter Setup and Validation Script

This script helps set up and validate SSM parameters for the Slack integration.
It provides parameter validation, rotation capabilities, and secure parameter management.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

import boto3
from botocore.exceptions import ClientError


class SlackParameterManager:
    """Manages SSM parameters for Slack integration with validation and rotation."""

    # Parameter paths from constants.py
    SLACK_BOT_TOKEN_PARAMETER = "/SecurityIncidentResponse/slackBotToken"  # nosec B105
    SLACK_SIGNING_SECRET_PARAMETER = "/SecurityIncidentResponse/slackSigningSecret"  # nosec B105
    SLACK_WORKSPACE_ID_PARAMETER = "/SecurityIncidentResponse/slackWorkspaceId"  # nosec B105

    # Validation patterns
    BOT_TOKEN_PATTERN = re.compile(r"^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$")
    SIGNING_SECRET_PATTERN = re.compile(r"^[a-f0-9]{32}$")
    WORKSPACE_ID_PATTERN = re.compile(r"^[A-Z0-9]{9,11}$")

    def __init__(self, region: Optional[str] = None):
        """Initialize the parameter manager."""
        self.ssm_client = boto3.client("ssm", region_name=region)
        self.region = region or boto3.Session().region_name

    def validate_bot_token(self, token: str) -> Tuple[bool, str]:
        """
        Validate Slack Bot Token format.

        Args:
            token: The bot token to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not token:
            return False, "Bot token cannot be empty"

        if not self.BOT_TOKEN_PATTERN.match(token):
            return (
                False,
                "Bot token must be in format: xoxb-XXXXXXXXX-XXXXXXXXX-XXXXXXXXXXXXXXXX",
            )

        return True, ""

    def validate_signing_secret(self, secret: str) -> Tuple[bool, str]:
        """
        Validate Slack Signing Secret format.

        Args:
            secret: The signing secret to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not secret:
            return False, "Signing secret cannot be empty"

        if not self.SIGNING_SECRET_PATTERN.match(secret):
            return False, "Signing secret must be a 32-character hexadecimal string"

        return True, ""

    def validate_workspace_id(self, workspace_id: str) -> Tuple[bool, str]:
        """
        Validate Slack Workspace ID format.

        Args:
            workspace_id: The workspace ID to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not workspace_id:
            return False, "Workspace ID cannot be empty"

        if not self.WORKSPACE_ID_PATTERN.match(workspace_id):
            return (
                False,
                "Workspace ID must be 9-11 uppercase alphanumeric characters",
            )

        return True, ""

    def create_or_update_parameter(
        self,
        parameter_name: str,
        parameter_value: str,
        description: str,
        overwrite: bool = False,
    ) -> bool:
        """
        Create or update an SSM parameter with encryption.

        Args:
            parameter_name: The parameter name/path
            parameter_value: The parameter value
            description: Description of the parameter
            overwrite: Whether to overwrite existing parameter

        Returns:
            True if successful, False otherwise
        """
        try:
            self.ssm_client.put_parameter(
                Name=parameter_name,
                Value=parameter_value,
                Description=description,
                Type="SecureString",
                Overwrite=overwrite,
                Tags=[
                    {"Key": "Integration", "Value": "SlackSecurityIR"},
                    {"Key": "ManagedBy", "Value": "SlackParameterSetup"},
                    {"Key": "LastRotated", "Value": datetime.utcnow().isoformat()},
                ],
            )
            print("✅ Successfully created/updated parameter")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ParameterAlreadyExists" and not overwrite:
                print(
                    f"⚠️  Parameter already exists. Use --rotate to update."
                )
            else:
                print(f"❌ Error creating parameter: {e}")
            return False

    def get_parameter(self, parameter_name: str) -> Optional[Dict]:
        """
        Get parameter details including metadata.

        Args:
            parameter_name: The parameter name/path

        Returns:
            Parameter details or None if not found
        """
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_name, WithDecryption=False
            )
            return response["Parameter"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ParameterNotFound":
                return None
            print(f"❌ Error retrieving parameter: {e}")
            return None

    def validate_existing_parameters(self) -> bool:
        """
        Validate all existing Slack parameters.

        Returns:
            True if all parameters are valid, False otherwise
        """
        print("\n🔍 Validating existing Slack parameters...\n")

        all_valid = True

        # Check bot token
        bot_token_param = self.get_parameter(self.SLACK_BOT_TOKEN_PARAMETER)
        if bot_token_param:
            print("✅ Bot token parameter exists")
            print(f"   Last modified: {bot_token_param.get('LastModifiedDate')}")
        else:
            print("❌ Bot token parameter not found")
            all_valid = False

        # Check signing secret
        signing_secret_param = self.get_parameter(self.SLACK_SIGNING_SECRET_PARAMETER)
        if signing_secret_param:
            print("✅ Signing secret parameter exists")
        else:
            print("❌ Signing secret parameter not found")
            all_valid = False

        # Check workspace ID
        workspace_id_param = self.get_parameter(self.SLACK_WORKSPACE_ID_PARAMETER)
        if workspace_id_param:
            print("✅ Workspace ID parameter exists")
            print(f"   Last modified: {workspace_id_param.get('LastModifiedDate')}")
        else:
            print("❌ Workspace ID parameter not found")
            all_valid = False

        return all_valid

    def rotate_parameters(
        self, bot_token: str, signing_secret: str, workspace_id: str
    ) -> bool:
        """
        Rotate Slack parameters with new values.

        Args:
            bot_token: New bot token
            signing_secret: New signing secret
            workspace_id: New workspace ID

        Returns:
            True if all rotations successful, False otherwise
        """
        print("\n🔄 Rotating Slack parameters...\n")

        # Validate all parameters first
        is_valid, error = self.validate_bot_token(bot_token)
        if not is_valid:
            print(f"❌ Bot token validation failed: {error}")
            return False

        is_valid, error = self.validate_signing_secret(signing_secret)
        if not is_valid:
            print(f"❌ Signing secret validation failed: {error}")
            return False

        is_valid, error = self.validate_workspace_id(workspace_id)
        if not is_valid:
            print(f"❌ Workspace ID validation failed: {error}")
            return False

        # Update all parameters
        success = True

        success &= self.create_or_update_parameter(
            self.SLACK_BOT_TOKEN_PARAMETER,
            bot_token,
            "Slack Bot User OAuth Token",
            overwrite=True,
        )

        success &= self.create_or_update_parameter(
            self.SLACK_SIGNING_SECRET_PARAMETER,
            signing_secret,
            "Slack App Signing Secret",
            overwrite=True,
        )

        success &= self.create_or_update_parameter(
            self.SLACK_WORKSPACE_ID_PARAMETER,
            workspace_id,
            "Slack Workspace ID",
            overwrite=True,
        )

        if success:
            print("\n✅ All parameters rotated successfully!")
        else:
            print("\n❌ Some parameters failed to rotate. Check errors above.")

        return success

    def setup_parameters(
        self, bot_token: str, signing_secret: str, workspace_id: str
    ) -> bool:
        """
        Initial setup of Slack parameters.

        Args:
            bot_token: Bot token
            signing_secret: Signing secret
            workspace_id: Workspace ID

        Returns:
            True if setup successful, False otherwise
        """
        print("\n🚀 Setting up Slack parameters...\n")

        # Validate all parameters first
        is_valid, error = self.validate_bot_token(bot_token)
        if not is_valid:
            print(f"❌ Bot token validation failed: {error}")
            return False

        is_valid, error = self.validate_signing_secret(signing_secret)
        if not is_valid:
            print(f"❌ Signing secret validation failed: {error}")
            return False

        is_valid, error = self.validate_workspace_id(workspace_id)
        if not is_valid:
            print(f"❌ Workspace ID validation failed: {error}")
            return False

        # Create all parameters
        success = True

        success &= self.create_or_update_parameter(
            self.SLACK_BOT_TOKEN_PARAMETER,
            bot_token,
            "Slack Bot User OAuth Token",
            overwrite=False,
        )

        success &= self.create_or_update_parameter(
            self.SLACK_SIGNING_SECRET_PARAMETER,
            signing_secret,
            "Slack App Signing Secret",
            overwrite=False,
        )

        success &= self.create_or_update_parameter(
            self.SLACK_WORKSPACE_ID_PARAMETER,
            workspace_id,
            "Slack Workspace ID",
            overwrite=False,
        )

        if success:
            print("\n✅ All parameters set up successfully!")
        else:
            print(
                "\n⚠️  Some parameters may already exist. Use --rotate to update them."
            )

        return success


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Manage SSM parameters for Slack integration"
    )

    parser.add_argument(
        "--region", help="AWS region (defaults to current session region)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Initial parameter setup")
    setup_parser.add_argument(
        "--bot-token", required=True, help="Slack Bot User OAuth Token (xoxb-...)"
    )
    setup_parser.add_argument(
        "--signing-secret", required=True, help="Slack App Signing Secret"
    )
    setup_parser.add_argument(
        "--workspace-id", required=True, help="Slack Workspace ID"
    )

    # Rotate command
    rotate_parser = subparsers.add_parser("rotate", help="Rotate existing parameters")
    rotate_parser.add_argument(
        "--bot-token", required=True, help="New Slack Bot User OAuth Token (xoxb-...)"
    )
    rotate_parser.add_argument(
        "--signing-secret", required=True, help="New Slack App Signing Secret"
    )
    rotate_parser.add_argument(
        "--workspace-id", required=True, help="New Slack Workspace ID"
    )

    # Validate command
    validate_parser = subparsers.add_parser(
        "validate", help="Validate existing parameters"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    manager = SlackParameterManager(region=args.region)

    try:
        if args.command == "setup":
            success = manager.setup_parameters(
                args.bot_token, args.signing_secret, args.workspace_id
            )
            sys.exit(0 if success else 1)

        elif args.command == "rotate":
            success = manager.rotate_parameters(
                args.bot_token, args.signing_secret, args.workspace_id
            )
            sys.exit(0 if success else 1)

        elif args.command == "validate":
            success = manager.validate_existing_parameters()
            sys.exit(0 if success else 1)

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

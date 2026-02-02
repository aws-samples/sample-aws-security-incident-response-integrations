"""
Permission models for Slack command authorization.

This module defines the data structures and models used for validating
user permissions when executing Slack commands.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import Enum


class PermissionMode(Enum):
    """Permission validation modes."""
    ALLOW_ALL = "allow-all"  # Allow all users (backward compatibility)
    WATCHER_BASED = "watcher-based"  # Only case watchers can execute commands
    USER_MAPPING = "user-mapping"  # Use explicit Slack-to-AWS user mapping


@dataclass
class PermissionConfig:
    """Configuration for permission validation."""
    
    permission_mode: PermissionMode = PermissionMode.ALLOW_ALL
    slack_to_aws_user_mapping: Dict[str, str] = None  # Slack user ID -> AWS IAM ARN
    admin_users: List[str] = None  # Slack user IDs with full access
    read_only_commands: List[str] = None  # Commands that don't require write permissions
    
    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.slack_to_aws_user_mapping is None:
            self.slack_to_aws_user_mapping = {}
        if self.admin_users is None:
            self.admin_users = []
        if self.read_only_commands is None:
            self.read_only_commands = ["status", "summarize", "help"]
    
    @classmethod
    def from_dict(cls, config_dict: Dict) -> "PermissionConfig":
        """Create PermissionConfig from dictionary.
        
        Args:
            config_dict: Dictionary containing configuration
            
        Returns:
            PermissionConfig instance
        """
        permission_mode_str = config_dict.get("permissionMode", "allow-all")
        try:
            permission_mode = PermissionMode(permission_mode_str)
        except ValueError:
            permission_mode = PermissionMode.ALLOW_ALL
        
        return cls(
            permission_mode=permission_mode,
            slack_to_aws_user_mapping=config_dict.get("slackToAwsUserMapping", {}),
            admin_users=config_dict.get("adminUsers", []),
            read_only_commands=config_dict.get("readOnlyCommands", ["status", "summarize", "help"])
        )
    
    def is_admin_user(self, slack_user_id: str) -> bool:
        """Check if user is an admin.
        
        Args:
            slack_user_id: Slack user ID
            
        Returns:
            True if user is admin, False otherwise
        """
        return slack_user_id in self.admin_users
    
    def is_read_only_command(self, command: str) -> bool:
        """Check if command is read-only.
        
        Args:
            command: Command name
            
        Returns:
            True if command is read-only, False otherwise
        """
        return command in self.read_only_commands
    
    def get_aws_identity(self, slack_user_id: str) -> Optional[str]:
        """Get AWS identity for Slack user.
        
        Args:
            slack_user_id: Slack user ID
            
        Returns:
            AWS IAM ARN or None if not mapped
        """
        return self.slack_to_aws_user_mapping.get(slack_user_id)


@dataclass
class PermissionCheckResult:
    """Result of a permission check."""
    
    allowed: bool
    reason: str
    user_id: str
    case_id: str
    command: str
    
    def __str__(self) -> str:
        """String representation of permission check result."""
        status = "ALLOWED" if self.allowed else "DENIED"
        return f"Permission {status} for user {self.user_id} on case {self.case_id} (command: {self.command}): {self.reason}"

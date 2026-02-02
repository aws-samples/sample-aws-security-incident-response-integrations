"""
Unit tests for Slack command permission validation.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../assets/domain/python"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../../assets/slack_command_handler"))

from permission_models import PermissionConfig, PermissionMode, PermissionCheckResult


class TestPermissionModels:
    """Test permission model classes."""
    
    def test_permission_config_default(self):
        """Test default permission configuration."""
        config = PermissionConfig()
        assert config.permission_mode == PermissionMode.ALLOW_ALL
        assert config.slack_to_aws_user_mapping == {}
        assert config.admin_users == []
        assert "status" in config.read_only_commands
        assert "summarize" in config.read_only_commands
    
    def test_permission_config_from_dict(self):
        """Test creating permission config from dictionary."""
        config_dict = {
            "permissionMode": "watcher-based",
            "slackToAwsUserMapping": {
                "U12345": "arn:aws:iam::123456789012:user/john.doe"
            },
            "adminUsers": ["U99999"],
            "readOnlyCommands": ["status", "summarize"]
        }
        
        config = PermissionConfig.from_dict(config_dict)
        assert config.permission_mode == PermissionMode.WATCHER_BASED
        assert config.slack_to_aws_user_mapping["U12345"] == "arn:aws:iam::123456789012:user/john.doe"
        assert "U99999" in config.admin_users
    
    def test_is_admin_user(self):
        """Test admin user check."""
        config = PermissionConfig(admin_users=["U12345", "U67890"])
        assert config.is_admin_user("U12345") is True
        assert config.is_admin_user("U99999") is False
    
    def test_is_read_only_command(self):
        """Test read-only command check."""
        config = PermissionConfig()
        assert config.is_read_only_command("status") is True
        assert config.is_read_only_command("summarize") is True
        assert config.is_read_only_command("update-status") is False
        assert config.is_read_only_command("close") is False
    
    def test_get_aws_identity(self):
        """Test AWS identity retrieval."""
        config = PermissionConfig(
            slack_to_aws_user_mapping={
                "U12345": "arn:aws:iam::123456789012:user/john.doe"
            }
        )
        assert config.get_aws_identity("U12345") == "arn:aws:iam::123456789012:user/john.doe"
        assert config.get_aws_identity("U99999") is None


class TestPermissionValidation:
    """Test permission validation logic."""
    
    @patch("index.get_permission_config")
    def test_validate_admin_user(self, mock_get_config):
        """Test that admin users are always allowed."""
        mock_config = PermissionConfig(
            permission_mode=PermissionMode.WATCHER_BASED,
            admin_users=["U12345"]
        )
        mock_get_config.return_value = mock_config
        
        # Import after mocking
        from index import validate_user_permissions
        
        result = validate_user_permissions("U12345", "case-123", "update-status")
        assert result is True
    
    @patch("index.get_permission_config")
    def test_validate_allow_all_mode(self, mock_get_config):
        """Test allow-all permission mode."""
        mock_config = PermissionConfig(permission_mode=PermissionMode.ALLOW_ALL)
        mock_get_config.return_value = mock_config
        
        from index import validate_user_permissions
        
        result = validate_user_permissions("U99999", "case-123", "update-status")
        assert result is True
    
    @patch("index.get_permission_config")
    def test_validate_read_only_command(self, mock_get_config):
        """Test that read-only commands are allowed for all users."""
        mock_config = PermissionConfig(
            permission_mode=PermissionMode.WATCHER_BASED,
            read_only_commands=["status", "summarize"]
        )
        mock_get_config.return_value = mock_config
        
        from index import validate_user_permissions
        
        result = validate_user_permissions("U99999", "case-123", "status")
        assert result is True
    
    @patch("index.check_watcher_based_permission")
    @patch("index.get_permission_config")
    def test_validate_watcher_based_allowed(self, mock_get_config, mock_check_watcher):
        """Test watcher-based validation when user is a watcher."""
        mock_config = PermissionConfig(
            permission_mode=PermissionMode.WATCHER_BASED,
            slack_to_aws_user_mapping={"U12345": "arn:aws:iam::123456789012:user/john.doe"}
        )
        mock_get_config.return_value = mock_config
        
        mock_check_watcher.return_value = PermissionCheckResult(
            allowed=True,
            reason="User is a case watcher",
            user_id="U12345",
            case_id="case-123",
            command="update-status"
        )
        
        from index import validate_user_permissions
        
        result = validate_user_permissions("U12345", "case-123", "update-status")
        assert result is True
    
    @patch("index.check_watcher_based_permission")
    @patch("index.get_permission_config")
    def test_validate_watcher_based_denied(self, mock_get_config, mock_check_watcher):
        """Test watcher-based validation when user is not a watcher."""
        mock_config = PermissionConfig(
            permission_mode=PermissionMode.WATCHER_BASED,
            slack_to_aws_user_mapping={"U12345": "arn:aws:iam::123456789012:user/john.doe"}
        )
        mock_get_config.return_value = mock_config
        
        mock_check_watcher.return_value = PermissionCheckResult(
            allowed=False,
            reason="User is not a case watcher",
            user_id="U12345",
            case_id="case-123",
            command="update-status"
        )
        
        from index import validate_user_permissions
        
        result = validate_user_permissions("U12345", "case-123", "update-status")
        assert result is False
    
    @patch("index.get_permission_config")
    def test_validate_user_mapping_mode_allowed(self, mock_get_config):
        """Test user-mapping mode when user has mapping."""
        mock_config = PermissionConfig(
            permission_mode=PermissionMode.USER_MAPPING,
            slack_to_aws_user_mapping={"U12345": "arn:aws:iam::123456789012:user/john.doe"}
        )
        mock_get_config.return_value = mock_config
        
        from index import validate_user_permissions
        
        result = validate_user_permissions("U12345", "case-123", "update-status")
        assert result is True
    
    @patch("index.get_permission_config")
    def test_validate_user_mapping_mode_denied(self, mock_get_config):
        """Test user-mapping mode when user has no mapping."""
        mock_config = PermissionConfig(
            permission_mode=PermissionMode.USER_MAPPING,
            slack_to_aws_user_mapping={}
        )
        mock_get_config.return_value = mock_config
        
        from index import validate_user_permissions
        
        result = validate_user_permissions("U99999", "case-123", "update-status")
        assert result is False


class TestPermissionCheckResult:
    """Test PermissionCheckResult class."""
    
    def test_permission_check_result_allowed(self):
        """Test permission check result for allowed access."""
        result = PermissionCheckResult(
            allowed=True,
            reason="User is admin",
            user_id="U12345",
            case_id="case-123",
            command="status"
        )
        
        assert result.allowed is True
        assert "ALLOWED" in str(result)
        assert "U12345" in str(result)
        assert "case-123" in str(result)
    
    def test_permission_check_result_denied(self):
        """Test permission check result for denied access."""
        result = PermissionCheckResult(
            allowed=False,
            reason="User not a watcher",
            user_id="U99999",
            case_id="case-456",
            command="close"
        )
        
        assert result.allowed is False
        assert "DENIED" in str(result)
        assert "U99999" in str(result)
        assert "case-456" in str(result)

"""Tests for deploy_integrations_solution.py deployment script."""

import argparse
import subprocess
import sys
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from deploy_integrations_solution import deploy_jira, deploy_servicenow, deploy_slack, main

# Test account ID used by moto
MOTO_ACCOUNT_ID = "123456789012"


class TestArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_jira_required_arguments(self):
        """Test that Jira integration requires all mandatory arguments."""
        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", ["prog", "jira"]):
                main()

    def test_jira_all_arguments_parsed(self):
        """Test that all Jira arguments are correctly parsed."""
        args = argparse.Namespace(
            email="test@example.com",
            url="https://example.atlassian.net",
            token="test-token",
            project_key="PROJ",
            log_level="error",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = deploy_jira(args)
            assert result == 0

    def test_servicenow_required_arguments(self):
        """Test that ServiceNow integration requires all mandatory arguments."""
        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", ["prog", "service-now"]):
                main()

    def test_servicenow_all_arguments_parsed(self):
        """Test that all ServiceNow arguments are correctly parsed."""
        args = argparse.Namespace(
            instance_id="test-instance",
            client_id="client123",
            client_secret="secret456",
            user_id="user789",
            private_key_path="./test.key",
            integration_module="itsm",
            log_level="error",
            use_oauth=False,
        )
        mock_s3 = MagicMock()
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        with patch("os.path.exists", return_value=True):
            with patch("boto3.client") as mock_boto:
                mock_boto.side_effect = lambda service: mock_s3 if service == "s3" else mock_sts
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(returncode=0)
                    result = deploy_servicenow(args)
                    assert result == 0

    def test_slack_required_arguments(self):
        """Test that Slack integration requires all mandatory arguments."""
        with pytest.raises(SystemExit):
            with patch.object(sys, "argv", ["prog", "slack"]):
                main()

    def test_slack_all_arguments_parsed(self):
        """Test that all Slack arguments are correctly parsed."""
        args = argparse.Namespace(
            bot_token="xoxb-test-token",
            signing_secret="test-secret",
            workspace_id="T12345",
            region="us-east-1",
            skip_verification=True,
            log_level="error",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = deploy_slack(args)
            assert result == 0

    def test_slack_optional_arguments(self):
        """Test Slack optional arguments have correct defaults."""
        args = argparse.Namespace(
            bot_token="xoxb-test",
            signing_secret="secret",
            workspace_id="T123",
            region="us-east-1",
            skip_verification=False,
            log_level="error",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = deploy_slack(args)
            assert result == 0

    def test_no_integration_specified(self):
        """Test that missing integration type shows error."""
        with patch.object(sys, "argv", ["prog"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

    def test_log_level_override(self):
        """Test that log level can be overridden."""
        args = argparse.Namespace(
            email="test@example.com",
            url="https://example.atlassian.net",
            token="token",
            project_key="PROJ",
            log_level="debug",
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = deploy_jira(args)
            assert result == 0
            cmd = mock_run.call_args[0][0]
            assert "AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel=debug" in " ".join(cmd)


class TestDeployJira:
    """Tests for Jira deployment function."""

    def test_deploy_jira_success(self):
        """Test successful Jira deployment."""
        args = argparse.Namespace(
            email="test@example.com",
            url="https://example.atlassian.net",
            token="test-token",
            project_key="PROJ",
            log_level="error",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_jira(args)
            assert result == 0
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "npx" in cmd
            assert "cdk" in cmd
            assert "deploy" in cmd
            assert "AwsSecurityIncidentResponseJiraIntegrationStack" in cmd

    def test_deploy_jira_builds_correct_command(self):
        """Test that Jira deployment builds correct CDK command."""
        args = argparse.Namespace(
            email="user@test.com",
            url="https://test.atlassian.net",
            token="my-token",
            project_key="TEST",
            log_level="debug",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            deploy_jira(args)
            cmd = mock_run.call_args[0][0]
            assert "AwsSecurityIncidentResponseJiraIntegrationStack:jiraEmail=user@test.com" in " ".join(cmd)
            assert "AwsSecurityIncidentResponseJiraIntegrationStack:jiraUrl=https://test.atlassian.net" in " ".join(cmd)
            assert "AwsSecurityIncidentResponseJiraIntegrationStack:jiraToken=my-token" in " ".join(cmd)
            assert "AwsSecurityIncidentResponseJiraIntegrationStack:jiraProjectKey=TEST" in " ".join(cmd)

    def test_deploy_jira_subprocess_error(self):
        """Test Jira deployment handles subprocess errors."""
        args = argparse.Namespace(
            email="test@example.com",
            url="https://example.atlassian.net",
            token="test-token",
            project_key="PROJ",
            log_level="error",
        )
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "cmd"),
        ):
            result = deploy_jira(args)
            assert result == 1

    def test_deploy_jira_unexpected_error(self):
        """Test Jira deployment handles unexpected errors."""
        args = argparse.Namespace(
            email="test@example.com",
            url="https://example.atlassian.net",
            token="test-token",
            project_key="PROJ",
            log_level="error",
        )
        with patch("subprocess.run", side_effect=Exception("Unexpected")):
            result = deploy_jira(args)
            assert result == 1


class TestDeployServiceNow:
    """Tests for ServiceNow deployment function."""

    @pytest.fixture
    def servicenow_args(self, tmp_path):
        """Common ServiceNow deployment arguments with a real temp key file."""
        key_file = tmp_path / "test.key"
        key_file.write_text("fake-private-key-content")
        return argparse.Namespace(
            instance_id="test-instance",
            client_id="client123",
            client_secret="secret456",
            user_id="user789",
            private_key_path=str(key_file),
            integration_module="itsm",
            log_level="error",
            use_oauth=False,
        )

    def test_deploy_servicenow_private_key_not_found(self):
        """Test ServiceNow deployment fails when private key file doesn't exist."""
        args = argparse.Namespace(
            instance_id="test-instance",
            client_id="client123",
            client_secret="secret456",
            user_id="user789",
            private_key_path="./nonexistent.key",
            integration_module="itsm",
            log_level="error",
            use_oauth=False,
        )
        result = deploy_servicenow(args)
        assert result == 1

    @mock_aws
    def test_deploy_servicenow_success(self, servicenow_args):
        """Test successful ServiceNow deployment."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_servicenow(servicenow_args)
            assert result == 0
            mock_run.assert_called_once()

    @mock_aws
    def test_deploy_servicenow_s3_bucket_already_exists(self, servicenow_args):
        """Test ServiceNow deployment handles existing S3 bucket."""
        # Pre-create the bucket to simulate "already exists"
        s3 = boto3.client("s3", region_name="us-east-1")
        bucket_name = f"snow-key-{MOTO_ACCOUNT_ID}"
        s3.create_bucket(Bucket=bucket_name)

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_servicenow(servicenow_args)
            assert result == 0
            mock_run.assert_called_once()

    def test_deploy_servicenow_s3_bucket_creation_error(self, tmp_path):
        """Test ServiceNow deployment handles S3 bucket creation errors."""
        key_file = tmp_path / "test.key"
        key_file.write_text("fake-private-key-content")
        args = argparse.Namespace(
            instance_id="test-instance",
            client_id="client123",
            client_secret="secret456",
            user_id="user789",
            private_key_path=str(key_file),
            integration_module="itsm",
            log_level="error",
            use_oauth=False,
        )
        mock_s3 = MagicMock()
        mock_s3.exceptions.BucketAlreadyOwnedByYou = type("BucketAlreadyOwnedByYou", (Exception,), {})
        mock_s3.exceptions.BucketAlreadyExists = type("BucketAlreadyExists", (Exception,), {})
        mock_s3.create_bucket.side_effect = Exception("Bucket creation failed")
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": MOTO_ACCOUNT_ID}

        with patch("boto3.client") as mock_boto:
            mock_boto.side_effect = lambda service, **kwargs: mock_s3 if service == "s3" else mock_sts
            result = deploy_servicenow(args)
            assert result == 1

    def test_deploy_servicenow_s3_upload_error(self, tmp_path):
        """Test ServiceNow deployment handles S3 upload errors."""
        key_file = tmp_path / "test.key"
        key_file.write_text("fake-private-key-content")
        args = argparse.Namespace(
            instance_id="test-instance",
            client_id="client123",
            client_secret="secret456",
            user_id="user789",
            private_key_path=str(key_file),
            integration_module="itsm",
            log_level="error",
            use_oauth=False,
        )
        mock_s3 = MagicMock()
        mock_s3.exceptions.BucketAlreadyOwnedByYou = type("BucketAlreadyOwnedByYou", (Exception,), {})
        mock_s3.exceptions.BucketAlreadyExists = type("BucketAlreadyExists", (Exception,), {})
        mock_s3.upload_file.side_effect = Exception("Upload failed")
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {"Account": MOTO_ACCOUNT_ID}

        with patch("boto3.client") as mock_boto:
            mock_boto.side_effect = lambda service, **kwargs: mock_s3 if service == "s3" else mock_sts
            result = deploy_servicenow(args)
            assert result == 1

    @mock_aws
    def test_deploy_servicenow_subprocess_error(self, servicenow_args):
        """Test ServiceNow deployment handles subprocess errors."""
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "cmd")):
            result = deploy_servicenow(servicenow_args)
            assert result == 1

    @mock_aws
    def test_deploy_servicenow_use_oauth_false(self, servicenow_args):
        """Test ServiceNow deployment with use_oauth explicitly set to False."""
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_servicenow(servicenow_args)
            assert result == 0
            cmd = " ".join(mock_run.call_args[0][0])
            assert "useOAuth=false" in cmd

    @mock_aws
    def test_deploy_servicenow_use_oauth_true(self, servicenow_args):
        """Test ServiceNow deployment with use_oauth explicitly set to True."""
        servicenow_args.use_oauth = True
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_servicenow(servicenow_args)
            assert result == 0
            cmd = " ".join(mock_run.call_args[0][0])
            assert "useOAuth=true" in cmd

    @mock_aws
    def test_deploy_servicenow_use_oauth_missing_attribute(self, tmp_path):
        """Test ServiceNow deployment defaults use_oauth to False when attribute is missing."""
        key_file = tmp_path / "test.key"
        key_file.write_text("fake-private-key-content")
        args = argparse.Namespace(
            instance_id="test-instance",
            client_id="client123",
            client_secret="secret456",
            user_id="user789",
            private_key_path=str(key_file),
            integration_module="itsm",
            log_level="error",
            # use_oauth intentionally omitted - should default to False
        )
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_servicenow(args)
            assert result == 0
            cmd = " ".join(mock_run.call_args[0][0])
            assert "useOAuth=false" in cmd


class TestDeploySlack:
    """Tests for Slack deployment function."""

    def test_deploy_slack_success_skip_verification(self):
        """Test successful Slack deployment with verification skipped."""
        args = argparse.Namespace(
            bot_token="xoxb-test-token",
            signing_secret="test-secret",
            workspace_id="T12345",
            region="us-east-1",
            skip_verification=True,
            log_level="error",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_slack(args)
            assert result == 0
            # Should only be called once (CDK deploy, no verification)
            assert mock_run.call_count == 1

    def test_deploy_slack_success_with_verification(self):
        """Test successful Slack deployment with verification."""
        args = argparse.Namespace(
            bot_token="xoxb-test-token",
            signing_secret="test-secret",
            workspace_id="T12345",
            region="us-west-2",
            skip_verification=False,
            log_level="error",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = deploy_slack(args)
            assert result == 0
            # Should be called twice (CDK deploy + verification)
            assert mock_run.call_count == 2

    def test_deploy_slack_builds_correct_command(self):
        """Test that Slack deployment builds correct CDK command."""
        args = argparse.Namespace(
            bot_token="xoxb-my-token",
            signing_secret="my-secret",
            workspace_id="T99999",
            region="us-east-1",
            skip_verification=True,
            log_level="info",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            deploy_slack(args)
            cmd = mock_run.call_args[0][0]
            assert "AwsSecurityIncidentResponseSlackIntegrationStack:slackBotToken=xoxb-my-token" in " ".join(cmd)
            assert "AwsSecurityIncidentResponseSlackIntegrationStack:slackSigningSecret=my-secret" in " ".join(cmd)
            assert "AwsSecurityIncidentResponseSlackIntegrationStack:slackWorkspaceId=T99999" in " ".join(cmd)

    def test_deploy_slack_subprocess_error(self):
        """Test Slack deployment handles subprocess errors."""
        args = argparse.Namespace(
            bot_token="xoxb-test-token",
            signing_secret="test-secret",
            workspace_id="T12345",
            region="us-east-1",
            skip_verification=True,
            log_level="error",
        )
        with patch(
            "subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "cmd"),
        ):
            result = deploy_slack(args)
            assert result == 1

    def test_deploy_slack_unexpected_error(self):
        """Test Slack deployment handles unexpected errors."""
        args = argparse.Namespace(
            bot_token="xoxb-test-token",
            signing_secret="test-secret",
            workspace_id="T12345",
            region="us-east-1",
            skip_verification=True,
            log_level="error",
        )
        with patch("subprocess.run", side_effect=Exception("Unexpected")):
            result = deploy_slack(args)
            assert result == 1

    def test_deploy_slack_verification_failure_still_returns_success(self):
        """Test that verification failure doesn't change deployment return code."""
        args = argparse.Namespace(
            bot_token="xoxb-test-token",
            signing_secret="test-secret",
            workspace_id="T12345",
            region="us-east-1",
            skip_verification=False,
            log_level="error",
        )
        deploy_result = MagicMock()
        deploy_result.returncode = 0
        verify_result = MagicMock()
        verify_result.returncode = 1

        with patch("subprocess.run", side_effect=[deploy_result, verify_result]):
            result = deploy_slack(args)
            # Deployment succeeded even though verification failed
            assert result == 0

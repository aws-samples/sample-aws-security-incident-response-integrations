"""
Unit tests for Slack API Gateway Authorizer Lambda function.
"""

import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock, patch, Mock
import sys
from pathlib import Path

import pytest

# Store original boto3 module reference if it exists
_original_boto3 = sys.modules.get("boto3")

# Mock boto3 before importing the module
_mock_boto3 = Mock()
sys.modules["boto3"] = _mock_boto3

# Add the assets directory to the path
assets_path = Path(__file__).parent.parent.parent.parent / "assets"
sys.path.insert(0, str(assets_path / "slack_api_gateway_authorizer"))

import index

# Restore original boto3 module after import to prevent test pollution
if _original_boto3 is not None:
    sys.modules["boto3"] = _original_boto3
else:
    del sys.modules["boto3"]


@pytest.fixture
def mock_ssm_client():
    """Mock SSM client for testing."""
    with patch("index.ssm_client") as mock_client:
        mock_client.get_parameter.return_value = {
            "Parameter": {"Value": "test_signing_secret_1234567890abcdef"}
        }
        yield mock_client


@pytest.fixture
def valid_slack_request():
    """Create a valid Slack request for testing."""
    timestamp = str(int(time.time()))
    body = json.dumps({"type": "event_callback", "event": {"type": "message"}})
    signing_secret = "test_signing_secret_1234567890abcdef"

    # Generate valid signature
    sig_basestring = f"v0:{timestamp}:{body}"
    signature = (
        "v0="
        + hmac.new(
            signing_secret.encode(),
            sig_basestring.encode(),
            hashlib.sha256,
        ).hexdigest()
    )

    return {
        "headers": {
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": signature,
        },
        "body": body,
        "methodArn": "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/POST/slack/events",
    }


@pytest.fixture
def setup_env():
    """Setup environment variables for testing."""
    with patch.dict(
        "os.environ",
        {
            "SLACK_SIGNING_SECRET": "/SecurityIncidentResponse/slackSigningSecret",
            "LOG_LEVEL": "INFO",
        },
    ):
        yield


class TestGetSigningSecret:
    """Tests for get_signing_secret function."""

    def test_get_signing_secret_success(self, mock_ssm_client, setup_env):
        """Test successful retrieval of signing secret."""
        # Clear cache
        index._signing_secret_cache.clear()

        secret = index.get_signing_secret()

        assert secret == "test_signing_secret_1234567890abcdef"
        mock_ssm_client.get_parameter.assert_called_once_with(
            Name="/SecurityIncidentResponse/slackSigningSecret", WithDecryption=True
        )

    def test_get_signing_secret_cached(self, mock_ssm_client, setup_env):
        """Test that signing secret is cached."""
        # Clear cache and populate it
        index._signing_secret_cache.clear()
        index._signing_secret_cache[
            "/SecurityIncidentResponse/slackSigningSecret"
        ] = {
            "value": "cached_secret",
            "timestamp": time.time(),
        }

        secret = index.get_signing_secret()

        assert secret == "cached_secret"
        # Should not call SSM if cached
        mock_ssm_client.get_parameter.assert_not_called()

    def test_get_signing_secret_cache_expired(self, mock_ssm_client, setup_env):
        """Test that expired cache is refreshed."""
        # Clear cache and populate with expired entry
        index._signing_secret_cache.clear()
        index._signing_secret_cache[
            "/SecurityIncidentResponse/slackSigningSecret"
        ] = {
            "value": "old_secret",
            "timestamp": time.time() - 400,  # Expired (> 300 seconds)
        }

        secret = index.get_signing_secret()

        assert secret == "test_signing_secret_1234567890abcdef"
        mock_ssm_client.get_parameter.assert_called_once()

    def test_get_signing_secret_failure(self, mock_ssm_client, setup_env):
        """Test handling of SSM parameter retrieval failure."""
        # Clear cache
        index._signing_secret_cache.clear()

        mock_ssm_client.get_parameter.side_effect = Exception("SSM error")

        with pytest.raises(Exception, match="SSM error"):
            index.get_signing_secret()


class TestVerifySlackSignature:
    """Tests for verify_slack_signature function."""

    def test_verify_valid_signature(self):
        """Test verification of valid Slack signature."""
        signing_secret = "test_secret"
        timestamp = str(int(time.time()))
        body = '{"type":"event_callback"}'

        # Generate valid signature
        sig_basestring = f"v0:{timestamp}:{body}"
        signature = (
            "v0="
            + hmac.new(
                signing_secret.encode(),
                sig_basestring.encode(),
                hashlib.sha256,
            ).hexdigest()
        )

        result = index.verify_slack_signature(
            signing_secret, timestamp, body, signature
        )

        assert result is True

    def test_verify_invalid_signature(self):
        """Test rejection of invalid signature."""
        signing_secret = "test_secret"
        timestamp = str(int(time.time()))
        body = '{"type":"event_callback"}'
        invalid_signature = "v0=invalid_signature_hash"

        result = index.verify_slack_signature(
            signing_secret, timestamp, body, invalid_signature
        )

        assert result is False

    def test_verify_old_timestamp(self):
        """Test rejection of old timestamp (replay attack prevention)."""
        signing_secret = "test_secret"
        old_timestamp = str(int(time.time()) - 400)  # 400 seconds ago
        body = '{"type":"event_callback"}'

        # Generate signature with old timestamp
        sig_basestring = f"v0:{old_timestamp}:{body}"
        signature = (
            "v0="
            + hmac.new(
                signing_secret.encode(),
                sig_basestring.encode(),
                hashlib.sha256,
            ).hexdigest()
        )

        result = index.verify_slack_signature(
            signing_secret, old_timestamp, body, signature
        )

        assert result is False

    def test_verify_future_timestamp(self):
        """Test rejection of future timestamp."""
        signing_secret = "test_secret"
        future_timestamp = str(int(time.time()) + 400)  # 400 seconds in future
        body = '{"type":"event_callback"}'

        # Generate signature with future timestamp
        sig_basestring = f"v0:{future_timestamp}:{body}"
        signature = (
            "v0="
            + hmac.new(
                signing_secret.encode(),
                sig_basestring.encode(),
                hashlib.sha256,
            ).hexdigest()
        )

        result = index.verify_slack_signature(
            signing_secret, future_timestamp, body, signature
        )

        assert result is False


class TestGeneratePolicy:
    """Tests for generate_policy function."""

    def test_generate_allow_policy(self):
        """Test generation of Allow policy."""
        policy = index.generate_policy(
            "slack-user",
            "Allow",
            "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/POST/slack/events",
        )

        assert policy["principalId"] == "slack-user"
        assert policy["policyDocument"]["Version"] == "2012-10-17"
        assert len(policy["policyDocument"]["Statement"]) == 1
        assert policy["policyDocument"]["Statement"][0]["Effect"] == "Allow"
        assert (
            policy["policyDocument"]["Statement"][0]["Action"]
            == "execute-api:Invoke"
        )

    def test_generate_deny_policy(self):
        """Test generation of Deny policy."""
        policy = index.generate_policy(
            "slack-user",
            "Deny",
            "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/POST/slack/events",
        )

        assert policy["principalId"] == "slack-user"
        assert policy["policyDocument"]["Statement"][0]["Effect"] == "Deny"

    def test_generate_policy_with_context(self):
        """Test generation of policy with context."""
        context = {"timestamp": "1234567890", "verified": "true"}
        policy = index.generate_policy(
            "slack-user",
            "Allow",
            "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/POST/slack/events",
            context=context,
        )

        assert "context" in policy
        assert policy["context"]["timestamp"] == "1234567890"
        assert policy["context"]["verified"] == "true"


class TestHandler:
    """Tests for handler function."""

    def test_handler_valid_request(
        self, mock_ssm_client, valid_slack_request, setup_env
    ):
        """Test handler with valid Slack request."""
        # Clear cache
        index._signing_secret_cache.clear()

        result = index.handler(valid_slack_request, None)

        assert result["principalId"] == "slack-user"
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Allow"
        assert result["context"]["verified"] == "true"

    def test_handler_missing_timestamp(
        self, mock_ssm_client, valid_slack_request, setup_env
    ):
        """Test handler with missing timestamp header."""
        # Clear cache
        index._signing_secret_cache.clear()

        # Remove timestamp header
        del valid_slack_request["headers"]["X-Slack-Request-Timestamp"]

        result = index.handler(valid_slack_request, None)

        assert result["principalId"] == "slack-user"
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Deny"

    def test_handler_missing_signature(
        self, mock_ssm_client, valid_slack_request, setup_env
    ):
        """Test handler with missing signature header."""
        # Clear cache
        index._signing_secret_cache.clear()

        # Remove signature header
        del valid_slack_request["headers"]["X-Slack-Signature"]

        result = index.handler(valid_slack_request, None)

        assert result["principalId"] == "slack-user"
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Deny"

    def test_handler_invalid_signature(
        self, mock_ssm_client, valid_slack_request, setup_env
    ):
        """Test handler with invalid signature."""
        # Clear cache
        index._signing_secret_cache.clear()

        # Modify signature to make it invalid
        valid_slack_request["headers"]["X-Slack-Signature"] = "v0=invalid_hash"

        result = index.handler(valid_slack_request, None)

        assert result["principalId"] == "slack-user"
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Deny"

    def test_handler_case_insensitive_headers(
        self, mock_ssm_client, valid_slack_request, setup_env
    ):
        """Test handler with case-insensitive header names."""
        # Clear cache
        index._signing_secret_cache.clear()

        # Change header case
        timestamp = valid_slack_request["headers"]["X-Slack-Request-Timestamp"]
        signature = valid_slack_request["headers"]["X-Slack-Signature"]

        valid_slack_request["headers"] = {
            "x-slack-request-timestamp": timestamp,
            "x-slack-signature": signature,
        }

        result = index.handler(valid_slack_request, None)

        assert result["principalId"] == "slack-user"
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Allow"

    def test_handler_exception(
        self, mock_ssm_client, valid_slack_request, setup_env
    ):
        """Test handler with exception during processing."""
        # Clear cache
        index._signing_secret_cache.clear()

        mock_ssm_client.get_parameter.side_effect = Exception("SSM error")

        result = index.handler(valid_slack_request, None)

        assert result["principalId"] == "slack-user"
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Deny"

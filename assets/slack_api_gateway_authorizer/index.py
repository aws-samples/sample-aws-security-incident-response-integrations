"""
Lambda authorizer for Slack API Gateway webhook authentication.

This authorizer validates Slack request signatures to ensure requests
are genuinely from Slack and prevents replay attacks.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, Dict

import boto3

# Configure logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

# Initialize AWS clients
ssm_client = boto3.client("ssm")

# Cache for SSM parameters
_signing_secret_cache: Dict[str, Any] = {}


def get_signing_secret() -> str:
    """
    Retrieve Slack signing secret from SSM Parameter Store with caching.

    Returns:
        str: Slack signing secret

    Raises:
        Exception: If parameter cannot be retrieved
    """
    param_name = os.environ.get("SLACK_SIGNING_SECRET")
    cache_ttl = 300  # 5 minutes

    # Check cache
    if param_name in _signing_secret_cache:
        cached_data = _signing_secret_cache[param_name]
        if time.time() - cached_data["timestamp"] < cache_ttl:
            return cached_data["value"]

    try:
        response = ssm_client.get_parameter(Name=param_name, WithDecryption=True)
        secret = response["Parameter"]["Value"]

        # Update cache
        _signing_secret_cache[param_name] = {
            "value": secret,
            "timestamp": time.time(),
        }

        return secret
    except Exception as e:
        logger.error(f"Failed to retrieve signing secret: {str(e)}")
        raise


def verify_slack_signature(
    signing_secret: str, timestamp: str, body: str, signature: str
) -> bool:
    """
    Verify Slack request signature.

    Args:
        signing_secret: Slack app signing secret
        timestamp: Request timestamp from X-Slack-Request-Timestamp header
        body: Raw request body
        signature: Signature from X-Slack-Signature header

    Returns:
        bool: True if signature is valid, False otherwise
    """
    # Prevent replay attacks - reject requests older than 5 minutes
    current_timestamp = int(time.time())
    request_timestamp = int(timestamp)

    if abs(current_timestamp - request_timestamp) > 300:
        logger.warning(
            f"Request timestamp too old: {request_timestamp} vs {current_timestamp}"
        )
        return False

    # Compute expected signature
    sig_basestring = f"v0:{timestamp}:{body}"
    expected_signature = (
        "v0="
        + hmac.new(
            signing_secret.encode(),
            sig_basestring.encode(),
            hashlib.sha256,
        ).hexdigest()
    )

    # Compare signatures using constant-time comparison
    return hmac.compare_digest(expected_signature, signature)


def generate_policy(
    principal_id: str, effect: str, resource: str, context: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Generate IAM policy for API Gateway.

    Args:
        principal_id: Principal identifier
        effect: Allow or Deny
        resource: Resource ARN
        context: Optional context to pass to Lambda

    Returns:
        Dict: IAM policy document
    """
    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource,
                }
            ],
        },
    }

    if context:
        policy["context"] = context

    return policy


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda authorizer handler for Slack webhook authentication.

    Args:
        event: API Gateway authorizer event
        context: Lambda context

    Returns:
        Dict: IAM policy allowing or denying access
    """
    try:
        logger.info("Processing authorization request")

        # Extract headers and body
        headers = event.get("headers", {})
        body = event.get("body", "")
        method_arn = event.get("methodArn", "")

        # Get required headers (case-insensitive)
        headers_lower = {k.lower(): v for k, v in headers.items()}
        timestamp = headers_lower.get("x-slack-request-timestamp")
        signature = headers_lower.get("x-slack-signature")

        # Validate required headers are present
        if not timestamp or not signature:
            logger.warning("Missing required Slack headers")
            return generate_policy("slack-user", "Deny", method_arn)

        # Get signing secret from SSM
        signing_secret = get_signing_secret()

        # Verify signature
        if verify_slack_signature(signing_secret, timestamp, body, signature):
            logger.info("Slack signature verified successfully")
            return generate_policy(
                "slack-user",
                "Allow",
                method_arn,
                context={
                    "timestamp": timestamp,
                    "verified": "true",
                },
            )
        else:
            logger.warning("Slack signature verification failed")
            return generate_policy("slack-user", "Deny", method_arn)

    except Exception as e:
        logger.error(f"Authorization error: {str(e)}", exc_info=True)
        # Deny access on any error
        return generate_policy(
            "slack-user", "Deny", event.get("methodArn", "*")
        )

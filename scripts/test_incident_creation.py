#!/usr/bin/env python3
"""
Diagnostic tests for ServiceNow incident creation and visibility.

This test suite replicates the exact flow used by:
1. The acceptance test (creates incident using admin + pysnc)
2. The notification handler Lambda (queries incident using JWT OAuth as aws_integration)

This helps identify where the incident visibility issue occurs.

Run with: pytest scripts/test_incident_creation.py -v
"""

import os
import time
import uuid
import json
import jwt
import pytest
import requests
import boto3
from datetime import datetime, timezone
from pysnc import ServiceNowClient as SnowClient
from requests.auth import AuthBase

# Configuration from environment variables
SERVICENOW_INSTANCE_ID = os.environ.get("SERVICENOW_INSTANCE_ID", "dev184649")
SERVICENOW_URL = f"https://{SERVICENOW_INSTANCE_ID}.service-now.com"
ADMIN_USERNAME = os.environ.get("SERVICENOW_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("SERVICENOW_ADMIN_PASSWORD")
INTEGRATION_USERNAME = os.environ.get("SERVICENOW_INTEGRATION_USERNAME", "aws_integration")
TABLE_NAME = "incident"


class TestEnvironmentVariables:
    """Tests to verify required environment variables are set."""

    def test_servicenow_instance_id_is_set(self):
        """Verify SERVICENOW_INSTANCE_ID is set."""
        assert os.environ.get("SERVICENOW_INSTANCE_ID"), (
            "SERVICENOW_INSTANCE_ID environment variable needs to be set. "
            "Example: export SERVICENOW_INSTANCE_ID='dev123456'"
        )

    def test_servicenow_admin_username_is_set(self):
        """Verify SERVICENOW_ADMIN_USERNAME is set."""
        assert os.environ.get("SERVICENOW_ADMIN_USERNAME"), (
            "SERVICENOW_ADMIN_USERNAME environment variable needs to be set. "
            "Example: export SERVICENOW_ADMIN_USERNAME='admin'"
        )

    def test_servicenow_admin_password_is_set(self):
        """Verify SERVICENOW_ADMIN_PASSWORD is set."""
        assert os.environ.get("SERVICENOW_ADMIN_PASSWORD"), (
            "SERVICENOW_ADMIN_PASSWORD environment variable needs to be set. "
            "Example: export SERVICENOW_ADMIN_PASSWORD='your-password'"
        )

    def test_servicenow_integration_username_is_set(self):
        """Verify SERVICENOW_INTEGRATION_USERNAME is set."""
        assert os.environ.get("SERVICENOW_INTEGRATION_USERNAME"), (
            "SERVICENOW_INTEGRATION_USERNAME environment variable needs to be set. "
            "Example: export SERVICENOW_INTEGRATION_USERNAME='aws_integration'"
        )


class JWTAuth(AuthBase):
    """JWT Bearer token authentication for requests."""
    def __init__(self, token: str):
        self.token = token

    def __call__(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"
        return request


@pytest.fixture(scope="module")
def aws_clients():
    """Create AWS clients for SSM, Secrets Manager, and S3."""
    return {
        "ssm": boto3.client("ssm", region_name="us-east-1"),
        "secrets": boto3.client("secretsmanager", region_name="us-east-1"),
        "s3": boto3.resource("s3", region_name="us-east-1"),
    }


@pytest.fixture(scope="module")
def admin_client():
    """Create ServiceNow admin client."""
    if not ADMIN_PASSWORD:
        pytest.skip("SERVICENOW_ADMIN_PASSWORD environment variable is required")
    return SnowClient(SERVICENOW_URL, (ADMIN_USERNAME, ADMIN_PASSWORD))


@pytest.fixture(scope="module")
def integration_user_sys_id(admin_client):
    """Get the sys_id of the aws_integration user."""
    gr_user = admin_client.GlideRecord("sys_user")
    gr_user.add_query("user_name", INTEGRATION_USERNAME)
    gr_user.query()
    if gr_user.next():
        return gr_user.sys_id
    pytest.fail(f"Could not find {INTEGRATION_USERNAME} user in ServiceNow")


@pytest.fixture(scope="module")
def oauth_token(aws_clients):
    """Get OAuth token using JWT authentication (same as Lambda)."""
    ssm = aws_clients["ssm"]
    secrets = aws_clients["secrets"]
    s3 = aws_clients["s3"]

    def get_param(name: str) -> str:
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]

    def get_secret(arn: str) -> str:
        return secrets.get_secret_value(SecretId=arn)["SecretString"]

    client_id = get_param("/SecurityIncidentResponse/serviceNowClientId")
    client_secret_arn = get_param("/SecurityIncidentResponse/serviceNowClientSecretArn")
    client_secret = get_secret(client_secret_arn)
    user_sys_id = get_param("/SecurityIncidentResponse/serviceNowUserId")
    bucket = get_param("/SecurityIncidentResponse/privateKeyAssetBucket")
    key = get_param("/SecurityIncidentResponse/privateKeyAssetKey")

    # Get private key from S3
    response = s3.Object(bucket, key).get()
    private_key = response["Body"].read().decode("utf-8")
    response["Body"].close()

    # Create JWT
    # NOTE: sub must contain the user's sys_id, not username
    # ServiceNow's oauth_jwt.sub_claim defaults to 'sys_id'
    payload = {
        "iss": client_id,
        "sub": user_sys_id,  # This should be the user's sys_id, not username
        "aud": client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": str(uuid.uuid4()),
    }

    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

    # Exchange JWT for OAuth token
    token_url = f"{SERVICENOW_URL}/oauth_token.do"
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": encoded_jwt,
        "client_id": client_id,
        "client_secret": client_secret,
    }

    response = requests.post(token_url, headers=headers, data=data)
    assert response.status_code == 200, f"OAuth token request failed: {response.text}"

    return response.json()["access_token"]


@pytest.fixture
def test_incident(admin_client, integration_user_sys_id):
    """Create a test incident and clean it up after the test."""
    test_id = uuid.uuid4().hex[:8]
    incident_title = f"Diagnostic Test - {test_id}"
    incident_description = f"Testing incident visibility - {test_id} - Created at {datetime.now(timezone.utc).isoformat()}"

    gr = admin_client.GlideRecord(TABLE_NAME)
    gr.initialize()
    gr.short_description = incident_title
    gr.description = incident_description
    gr.impact = "2"
    gr.urgency = "2"
    gr.caller_id = integration_user_sys_id

    sys_id = gr.insert()
    assert sys_id, "Failed to create incident - gr.insert() returned None/empty"

    incident_data = {
        "sys_id": sys_id,
        "number": gr.number,
        "title": incident_title,
    }

    yield incident_data

    # Cleanup
    gr_delete = admin_client.GlideRecord(TABLE_NAME)
    if gr_delete.get(sys_id):
        gr_delete.delete()


class TestIncidentCreation:
    """Tests for incident creation using admin credentials."""

    def test_incident_created_successfully(self, test_incident):
        """Verify incident is created with valid sys_id and number."""
        assert test_incident["sys_id"], "Incident sys_id should not be empty"
        assert test_incident["number"], "Incident number should not be empty"
        assert test_incident["number"].startswith("INC"), "Incident number should start with INC"


class TestAdminVisibility:
    """Tests for incident visibility using admin credentials."""

    def test_admin_can_read_incident_immediately(self, admin_client, test_incident):
        """Admin should be able to read incident immediately after creation."""
        gr = admin_client.GlideRecord(TABLE_NAME)
        gr.add_query("number", test_incident["number"])
        gr.query()

        assert gr.get_row_count() == 1, f"Expected 1 result, got {gr.get_row_count()}"
        assert gr.next(), "Admin should be able to read the incident"
        assert gr.sys_id == test_incident["sys_id"]

    def test_admin_can_read_incident_after_delay(self, admin_client, test_incident):
        """Admin should be able to read incident after a short delay."""
        time.sleep(3)

        gr = admin_client.GlideRecord(TABLE_NAME)
        gr.add_query("number", test_incident["number"])
        gr.query()

        assert gr.get_row_count() == 1
        assert gr.next()

    def test_admin_rest_api_can_read_incident(self, test_incident):
        """Admin should be able to read incident via REST API."""
        url = f"{SERVICENOW_URL}/api/now/table/{TABLE_NAME}"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        params = {"sysparm_query": f"number={test_incident['number']}", "sysparm_limit": 1}

        response = requests.get(
            url, auth=(ADMIN_USERNAME, ADMIN_PASSWORD), headers=headers, params=params
        )

        assert response.status_code == 200, f"REST API error: {response.text}"
        results = response.json().get("result", [])
        assert len(results) == 1, f"Expected 1 result, got {len(results)}"
        assert results[0]["sys_id"] == test_incident["sys_id"]


class TestOAuthVisibility:
    """Tests for incident visibility using JWT OAuth (same as Lambda)."""

    def test_oauth_rest_api_can_read_incident(self, oauth_token, test_incident):
        """aws_integration should be able to read incident via OAuth REST API."""
        url = f"{SERVICENOW_URL}/api/now/table/{TABLE_NAME}"
        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        params = {
            "sysparm_query": f"number={test_incident['number']}",
            "sysparm_display_value": "all",
            "sysparm_exclude_reference_link": "true",
            "sysparm_limit": 100,
        }

        response = requests.get(url, headers=headers, params=params)

        assert response.status_code == 200, f"OAuth REST API error: {response.text}"
        results = response.json().get("result", [])
        assert len(results) >= 1, (
            f"aws_integration CANNOT see incident via OAuth (got {len(results)} results). "
            "This is the same issue the Lambda is experiencing!"
        )

    def test_pysnc_oauth_can_read_incident(self, oauth_token, test_incident):
        """aws_integration should be able to read incident via pysnc + OAuth."""
        client = SnowClient(SERVICENOW_URL, JWTAuth(oauth_token))

        gr = client.GlideRecord(TABLE_NAME)
        gr.add_query("number", test_incident["number"])
        gr.query()

        row_count = gr.get_row_count()
        assert row_count >= 1, (
            f"pysnc + OAuth CANNOT find incident (got {row_count} results). "
            "This matches the Lambda behavior!"
        )
        assert gr.next()


class TestRecentIncidents:
    """Tests for querying recent incidents."""

    def test_admin_can_see_recent_incidents(self, admin_client):
        """Admin should be able to query incidents created in last 5 minutes."""
        gr = admin_client.GlideRecord(TABLE_NAME)
        gr.add_query("sys_created_on", ">", "javascript:gs.minutesAgoStart(5)")
        gr.query()

        # Just verify the query works - count may vary
        row_count = gr.get_row_count()
        assert row_count >= 0, "Query should return a valid count"

    def test_oauth_can_see_recent_incidents(self, oauth_token):
        """aws_integration should be able to query recent incidents via OAuth."""
        url = f"{SERVICENOW_URL}/api/now/table/{TABLE_NAME}"
        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        params = {
            "sysparm_query": "sys_created_on>javascript:gs.minutesAgoStart(5)",
            "sysparm_limit": 100,
        }

        response = requests.get(url, headers=headers, params=params)

        assert response.status_code == 200, f"Query failed: {response.status_code}"
        # Just verify the query works
        results = response.json().get("result", [])
        assert isinstance(results, list), "Results should be a list"

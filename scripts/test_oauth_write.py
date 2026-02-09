#!/usr/bin/env python3
"""Test OAuth write permissions for aws_integration user."""

import boto3
import requests
import jwt
import time
import uuid
import sys

def main():
    # Get credentials from SSM
    ssm = boto3.client("ssm", region_name="us-east-1")
    secrets = boto3.client("secretsmanager", region_name="us-east-1")
    s3 = boto3.resource("s3", region_name="us-east-1")

    def get_param(name):
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]

    def get_secret(arn):
        return secrets.get_secret_value(SecretId=arn)["SecretString"]

    client_id = get_param("/SecurityIncidentResponse/serviceNowClientId")
    client_secret_arn = get_param("/SecurityIncidentResponse/serviceNowClientSecretArn")
    client_secret = get_secret(client_secret_arn)
    user_id = get_param("/SecurityIncidentResponse/serviceNowUserId")
    bucket = get_param("/SecurityIncidentResponse/privateKeyAssetBucket")
    key = get_param("/SecurityIncidentResponse/privateKeyAssetKey")

    # Get private key from S3
    response = s3.Object(bucket, key).get()
    private_key = response['Body'].read().decode('utf-8')
    response['Body'].close()

    print(f"Client ID: {client_id}")
    print(f"User ID (sys_id): {user_id}")

    # Create JWT
    # NOTE: sub must contain the user's sys_id, not username
    # ServiceNow's oauth_jwt.sub_claim defaults to 'sys_id'
    payload = {
        "iss": client_id,
        "sub": user_id,  # This should be the user's sys_id, not username
        "aud": client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": str(uuid.uuid4())
    }

    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

    # Get OAuth token
    url = "https://dev184649.service-now.com"
    token_url = f"{url}/oauth_token.do"
    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
    data = {
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': encoded_jwt,
        'client_id': client_id,
        'client_secret': client_secret
    }

    response = requests.post(token_url, headers=headers, data=data)
    print(f"Token response: {response.status_code}")
    if response.status_code != 200:
        print(f"Error: {response.text}")
        sys.exit(1)

    oauth_token = response.json()['access_token']
    print(f"Got OAuth token: {oauth_token[:20]}...")

    # Try to create an incident
    headers = {
        'Authorization': f'Bearer {oauth_token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    incident_data = {
        "short_description": "Test incident from script",
        "description": "Testing write permissions"
    }

    response = requests.post(f"{url}/api/now/table/incident", headers=headers, json=incident_data)
    print(f"Create incident response: {response.status_code}")
    print(f"Response: {response.text[:500]}")

    if response.status_code in [200, 201]:
        # Clean up
        sys_id = response.json()["result"]["sys_id"]
        print(f"Created incident: {sys_id}")
        del_response = requests.delete(f"{url}/api/now/table/incident/{sys_id}", headers=headers)
        print(f"Deleted incident: {del_response.status_code}")

if __name__ == "__main__":
    main()

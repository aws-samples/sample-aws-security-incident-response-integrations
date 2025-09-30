import json
import boto3
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secrets_client = boto3.client("secretsmanager")


def handler(event, context):
    """
    Lambda authorizer for ServiceNow API Gateway.

    Validates the authorization token from the request headers against the expected token
    stored in AWS Secrets Manager and returns an IAM policy allowing or denying access.

    Args:
        event (dict): Lambda event containing authorization token and method ARN
        context: Lambda context object (unused)

    Returns:
        dict: IAM policy document with Allow or Deny effect for API Gateway access
    """
    try:
        # Get the authorization token from the event
        token = event.get("authorizationToken", "")

        # Remove 'Bearer ' prefix if present
        if token.startswith("Bearer "):
            token = token[7:]

        # Get expected token from Secrets Manager
        api_auth_secret_arn = os.environ.get("API_AUTH_SECRET")
        if not api_auth_secret_arn:
            logger.error("API_AUTH_SECRET environment variable not set")
            effect = "Deny"
        else:
            try:
                response = secrets_client.get_secret_value(SecretId=api_auth_secret_arn)
                secret_dict = json.loads(response["SecretString"])
                expected_token = secret_dict.get("token")
                # Validate token
                if token == expected_token:
                    effect = "Allow"
                else:
                    effect = "Deny"
            except Exception as e:
                logger.error(f"Failed to retrieve secret: {str(e)}")
                effect = "Deny"

        # Generate policy
        policy = {
            "principalId": "service-now",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": effect,
                        "Resource": event["methodArn"],
                    }
                ],
            },
        }

        return policy

    except Exception as e:
        logger.error(f"Authorization failed: {str(e)}")
        return {
            "principalId": "service-now",
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": "execute-api:Invoke",
                        "Effect": "Deny",
                        "Resource": event["methodArn"],
                    }
                ],
            },
        }
def lambda_handler(event, context):
    """AWS Lambda handler function.
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        Response from handler function
    """
    return handler(event, context)
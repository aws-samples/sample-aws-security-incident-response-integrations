import json
from typing import Optional
import boto3
import requests
import os
from base64 import b64encode
import logging
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()

# Get log level from environment variable
log_level = os.environ.get("LOG_LEVEL", "error").lower()
if log_level == "debug":
    logger.setLevel(logging.DEBUG)
elif log_level == "info":
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

ssm_client = boto3.client("ssm")
secrets_client = boto3.client("secretsmanager")
request_content = "application/json"


class ParameterService:
    """Class to handle parameter operations"""

    def __init__(self):
        """Initialize the parameter service"""

    def get_parameter(self, parameter_name: str) -> Optional[str]:
        """
        Get a parameter from SSM Parameter Store

        Args:
            parameter_name: The name of the parameter to retrieve

        Returns:
            Parameter value or None if retrieval fails
        """
        try:
            response = ssm_client.get_parameter(
                Name=parameter_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving parameter {parameter_name}: {error_code}")
            return None


class SecretsManagerService:
    """Class to handle Secrets Manager operations"""

    def __init__(self):
        """Initialize the secrets manager service"""

    def get_secret_value(self, secret_arn: str) -> Optional[str]:
        """
        Get a secret value from AWS Secrets Manager

        Args:
            secret_arn: The ARN of the secret to retrieve

        Returns:
            Secret token value or None if retrieval fails
        """
        try:
            response = secrets_client.get_secret_value(SecretId=secret_arn)
            secret_dict = json.loads(response["SecretString"])
            return secret_dict.get("token")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving secret {secret_arn}: {error_code}")
            return None
        except Exception as e:
            logger.error(f"Error parsing secret value: {str(e)}")
            return None


class ServiceNowApiService:
    """Class to manage ServiceNow API operations"""

    def __init__(
        self, instance_id, username, password_param_name
    ):
        """Initialize the ServiceNow API service"""
        self.instance_id = instance_id
        self.username = username
        self.password_param_name = password_param_name
        self.secrets_manager_service = SecretsManagerService()

    def __get_password(self, password_param_name) -> Optional[str]:
        """
        Fetch the ServiceNow password from SSM Parameter Store

        Returns:
            Password or None if retrieval fails
        """
        try:
            if not password_param_name:
                logger.error("No ServiceNow password param name provided")
                return None

            response = ssm_client.get_parameter(
                Name=password_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving ServiceNow password from SSM: {str(e)}")
            return None

    def __get_request_headers(self):
        """Get headers for ServiceNow API requests"""
        try:
            password = self.__get_password(self.password_param_name)
            auth = b64encode(f"{self.username}:{password}".encode()).decode()
            return {
                "Authorization": f"Basic {auth}",
                "Content-Type": request_content,
                "Accept": request_content,
            }
        except Exception as e:
            logger.error(f"Error getting request headers: {str(e)}")
            return None

    def __get_request_base_url(self):
        """Get base url for ServiceNow API requests"""
        try:
            return f"https://{self.instance_id}.service-now.com"
        except Exception as e:
            logger.error(f"Error getting base url: {str(e)}")
            return None

    def __get_json_keys_list(self, json_string):
        """Get list of keys from a JSON string"""
        try:
            json_object = json.loads(json_string)
            return list(json_object.keys())
        except Exception as e:
            logger.error(f"Error getting json keys list from the request: {str(e)}")
            return None

    def __add_outbound_rest_message_request_function_parameters(
        self,
        headers,
        base_url,
        request_content,
        outbound_rest_message_request_function_sys_id,
    ):
        """Add parameters to Http request function for Outbound REST Message resource in ServiceNow for integration with AWS Security Incident Response"""
        try:
            logger.info(
                "Adding parameters to Http request function for Outbound REST Message resource in ServiceNow for integration with AWS Security Incident Response"
            )

            # Getting parameters from request_content
            request_content_parameters = self.__get_json_keys_list(request_content)

            if request_content_parameters is None:
                logger.error(
                    "Failed to get parameters from request_content while setting up Outbound REST Message in ServiceNow for integration with AWS Security Incident Response. Exiting."
                )
                return None

            logger.info(
                f"Parameters to be added to the Http request function: {request_content_parameters}"
            )

            # Adding parameters to the Http request function using its sys_id
            for parameter in request_content_parameters:
                rest_message_post_function_parameters_payload = {
                    "name": f"{parameter}",
                    "rest_message_function": f"{outbound_rest_message_request_function_sys_id}",
                }
                requests.post(
                    f"{base_url}/api/now/table/sys_rest_message_fn_parameters",
                    json=rest_message_post_function_parameters_payload,
                    headers=headers,
                    timeout=30,
                )
                logger.info(
                    f"Added parameter {parameter} to Http request function for Outbound REST Message"
                )
        except Exception as e:
            logger.error(f"Error adding parameters to Http request function: {str(e)}")
            
    def __update_outbound_rest_message_request_function_headers(
        self,
        headers,
        base_url,
        outbound_rest_message_request_function_name,
        api_auth_secret_arn
    ):
        """Create/Update Http request headers to be used in the Outbound REST Message function resource in ServiceNow for integration"""
        try:
            logger.info(
                "Updating Http request headers in the Outbound REST Message function resource in ServiceNow for integration with AWS Security Incident Response"
            )
            
            # Get API auth token from Secrets Manager
            auth_token = (
                self.secrets_manager_service.get_secret_value(api_auth_secret_arn)
                if api_auth_secret_arn
                else None
            )
            
            # Update Authorization header if token is available
            if auth_token:
                rest_message_post_function_headers_payload = { 
                                    "rest_message_function": f"{outbound_rest_message_request_function_name}",
                                    "name": "Authorization",
                                    "value": f"Bearer {auth_token}"
                            }
            
            rest_message_post_function_headers_response = requests.post(
                f"{base_url}/api/now/table/sys_rest_message_fn_headers",
                json=rest_message_post_function_headers_payload,
                headers=headers,
                timeout=30,
            )

            rest_message_post_function_headers_response_json = json.loads(
                rest_message_post_function_headers_response.text
            )

            logger.info(
                f"Http request authorization headers added for Outbound REST Message function with response: {rest_message_post_function_headers_response_json}"
            )
        except Exception as e:
            logger.error(f"Error updating Http request headers for the Outbound REST message function: {str(e)}")
            return None

    def __create_outbound_rest_message_request_function(
        self,
        headers,
        base_url,
        request_type,
        request_content,
        outbound_rest_message_name,
        outbound_rest_message_request_function_name,
        api_auth_secret_arn,
    ):
        """Create Http request function to be used in the Outbound REST Message resource in ServiceNow for integration"""
        try:
            logger.info(
                "Creating Http request function in the Outbound REST Message resource in ServiceNow for integration with AWS Security Incident Response"
            )

            rest_message_post_function_payload = {
                "rest_message": f"{outbound_rest_message_name}",
                "function_name": f"{outbound_rest_message_request_function_name}",
                "http_method": f"{request_type}",
                "content": request_content,
            }

            rest_message_post_function_response = requests.post(
                f"{base_url}/api/now/table/sys_rest_message_fn",
                json=rest_message_post_function_payload,
                headers=headers,
                timeout=30,
            )
            rest_message_post_function_response_json = json.loads(
                rest_message_post_function_response.text
            )

            logger.info(
                f"Http request function for Outbound REST Message created with response: {rest_message_post_function_response_json}"
            )
            
            self.__update_outbound_rest_message_request_function_headers(headers, base_url, outbound_rest_message_request_function_name, api_auth_secret_arn)

            rest_message_post_function_sys_id = (
                rest_message_post_function_response_json.get("result").get("sys_id")
            )
            return rest_message_post_function_sys_id
        except Exception as e:
            logger.error(f"Error creating Http request function: {str(e)}")
            return None

    def _create_outbound_rest_message(
        self, webhook_url, resource_prefix, api_auth_secret_arn
    ):
        """Create Outbound REST Message to be used in the Business Rule for publishing Incident events to the integration solution"""
        try:
            logger.info(
                "Creating Outbound REST Message in Service Now to publish Incident related events to AWS Security Incident Response"
            )

            # Get headers for ServiceNow API requests
            headers = self.__get_request_headers()

            # Get base url for ServiceNow API requests
            base_url = self.__get_request_base_url()

            # Create the Outbound REST Message resource
            # Prepare the Outbound REST Message resource name
            outbound_rest_message_name = f"{resource_prefix}-outbound-rest-message"

            # Prepare the Outbound REST Message resource payload
            rest_message_payload = {
                "name": f"{outbound_rest_message_name}",
                "rest_endpoint": f"{webhook_url}",
            }

            outbound_rest_message_response = requests.post(
                f"{base_url}/api/now/table/sys_rest_message",
                json=rest_message_payload,
                headers=headers,
                timeout=30,
            )

            logger.info(
                f"Outbound REST Message created with response: {json.loads(outbound_rest_message_response.text)}"
            )

            # Create the Http Post Request function for Outbound REST Message resource
            request_type = "POST"
            request_content = '{"event_type":"${event_type}","incident_number":"${incident_number}","short_description":"${short_description}"}'
            outbound_rest_message_request_function_name = (
                f"{outbound_rest_message_name}-{request_type}-function"
            )

            outbound_rest_message_request_function_sys_id = self.__create_outbound_rest_message_request_function(
                headers=headers,
                base_url=base_url,
                request_type=request_type,
                request_content=request_content,
                outbound_rest_message_name=outbound_rest_message_name,
                outbound_rest_message_request_function_name=outbound_rest_message_request_function_name,
                api_auth_secret_arn=api_auth_secret_arn,
            )

            if outbound_rest_message_request_function_sys_id is None:
                logger.error(
                    "Failed to create Http Post Request function for Outbound REST Message resource in ServiceNow for integration with AWS Security Incident Response. Exiting."
                )
                return None

            # Add parameters to Http Post Request function for Outbound REST Message resource
            self.__add_outbound_rest_message_request_function_parameters(
                headers=headers,
                base_url=base_url,
                request_content=request_content,
                outbound_rest_message_request_function_sys_id=outbound_rest_message_request_function_sys_id,
            )

            return (
                outbound_rest_message_name,
                outbound_rest_message_request_function_name,
            )
        except Exception as e:
            logger.error(
                f"Error while creating Outbound REST Message in Service Now to publish Incident related events to AWS Security Incident Response: {str(e)}"
            )
            return None

    def _create_incident_business_rule(
        self,
        outbound_rest_message_name,
        outbound_rest_message_request_function_name,
        resource_prefix,
    ):
        """Create Business Rule to trigger Incident events"""
        try:
            logger.info(
                "Creating Business Rule in Service Now to publish Incident related events to AWS"
            )

            # Get headers for ServiceNow API requests
            headers = self.__get_request_headers()

            # Get base url for ServiceNow API requests
            base_url = self.__get_request_base_url()

            # Business rule for incident events
            rule_payload = {
                "name": f"{resource_prefix}-business-rule",
                "collection": "incident",
                "when": "after",
                "action_insert": True,
                "action_update": True,
                "active": True,
                "script": f"""
        (function executeRule(current, previous) {{
            try {{
                var event_type = previous ? 'IncidentUpdated' : 'IncidentCreated';
                var payload = {{
                    "event_type": event_type,
                    "incident_number": current.number.toString(),
                    "short_description": current.short_description.toString(),
                }};
                var outbound_rest_message_name_str = "{outbound_rest_message_name}";
                var outbound_rest_message_request_function_name_str = "{outbound_rest_message_request_function_name}";
                var request = new sn_ws.RESTMessageV2(outbound_rest_message_name_str, outbound_rest_message_request_function_name_str);
                request.setRequestBody(JSON.stringify(payload));
                
                var response = request.executeAsync();
                gs.info('Incident event published to AWS Security Incident Response API Gateway: ' + event_type);
                var responseBody = response.getBody();
                var httpStatus = response.getStatusCode();
                gs.info("Incident Event Response: " + responseBody);
                gs.info("Incident Event HTTP Status: " + httpStatus);
                
            }} catch (error) {{
                gs.error('Error sending incident event: ' + error.message);
            }}
        }})(current, previous);
        """,
            }

            # Create Business Rule resource in Service Now using REST API
            response = requests.post(
                f"{base_url}/api/now/table/sys_script",
                json=rule_payload,
                headers=headers,
                timeout=30,
            )

            logger.info(
                f"Business Rule created in Service Now: {json.loads(response.text)}"
            )

            return response
        except Exception as e:
            logger.error(
                f"Error while creating Business Rule in Service Now to publish Incident related events to AWS: {str(e)}"
            )
            return None


def handler(event, context):
    """
    Custom resource handler to create ServiceNow resources
    """
    request_type = event.get("RequestType")
    
    # Handle DELETE events - just return success
    if request_type == "DELETE":
        logger.info("DELETE request received - returning success")
        return {"Status": "SUCCESS", "PhysicalResourceId": "service-now-api-setup"}
    
    # Handle CREATE and UPDATE events
    try:
        # Get environment variables
        service_now_resource_prefix = os.environ.get("SERVICE_NOW_RESOURCE_PREFIX")
        webhook_url = os.environ.get("WEBHOOK_URL", "")
        api_auth_secret_arn = os.environ.get("API_AUTH_SECRET")

        # Get credentials from SSM
        parameter_service = ParameterService()
        instance_id = parameter_service.get_parameter(
            os.environ.get("SERVICE_NOW_INSTANCE_ID")
        )
        username = parameter_service.get_parameter(os.environ.get("SERVICE_NOW_USER"))
        password_param_name = os.environ.get("SERVICE_NOW_PASSWORD_PARAM")

        service_now_api_service = ServiceNowApiService(
            instance_id, username, password_param_name
        )
        
        outbound_rest_message_result = service_now_api_service._create_outbound_rest_message(
            webhook_url, service_now_resource_prefix, api_auth_secret_arn
        )

        if outbound_rest_message_result is None:
            logger.error(
                "Failed to create Outbound REST Message resources in ServiceNow to provide automated publishing of Incident related events to AWS Security Incident Response. Exiting."
            )
            return {"Status": "FAILED", "PhysicalResourceId": "service-now-api-setup"}
        
        (
            service_now_api_outbound_rest_message_name,
            service_now_api_outbound_rest_message_request_function_name,
        ) = outbound_rest_message_result

        service_now_api_service._create_incident_business_rule(
            service_now_api_outbound_rest_message_name,
            service_now_api_outbound_rest_message_request_function_name,
            service_now_resource_prefix,
        )

        return {"Status": "SUCCESS", "PhysicalResourceId": "service-now-api-setup"}
    
    except Exception as e:
        logger.error(f"Error in custom resource handler: {str(e)}")
        return {"Status": "FAILED", "PhysicalResourceId": "service-now-api-setup"}

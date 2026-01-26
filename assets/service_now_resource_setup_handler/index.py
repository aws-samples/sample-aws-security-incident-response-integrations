import json
from typing import Optional
import boto3
import requests
import os
from base64 import b64encode
import logging
from botocore.exceptions import ClientError
import requests
from requests.auth import AuthBase
import time
import uuid
import jwt

# ServiceNowJWTAuth is not used in this file, removing the import

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

# Static variables
JWT_CONTENT_TYPE = 'application/x-www-form-urlencoded; charset=UTF-8'
JWT_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
JWT_HEADER = {
            'alg': 'RS256',  # Or RS256 if using certificate-based signing
            'typ': 'JWT'
            # 'kid': 'key_id_if_applicable' # If you have a specific key ID
        }

class ParameterService:
    """Class to handle parameter operations."""

    def __init__(self):
        """Initialize the parameter service."""

    def get_parameter(self, parameter_name: str) -> Optional[str]:
        """Get a parameter from SSM Parameter Store.

        Args:
            parameter_name (str): The name of the parameter to retrieve

        Returns:
            Optional[str]: Parameter value or None if retrieval fails
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
    """Class to handle Secrets Manager operations."""

    def __init__(self):
        """Initialize the secrets manager service."""

    def get_secret_value(self, secret_arn: str) -> Optional[str]:
        """Get a secret value from AWS Secrets Manager.

        Args:
            secret_arn (str): The ARN of the secret to retrieve

        Returns:
            Optional[str]: Secret token value or None if retrieval fails
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
    """Class to manage ServiceNow API operations."""

    def __init__(self, instance_id, **kwargs):
        """
        Initialize the ServiceNow API service.

        Args:
            instance_id (str): ServiceNow instance ID
            **kwargs: OAuth configuration parameters including:
                - client_id_param_name (str): SSM parameter name containing OAuth client ID
                - client_secret_arn (str): Secret ARN containing OAuth client secret
                - user_id_param_name (str): SSM parameter name containing ServiceNow user ID
                - private_key_asset_bucket_param_name (str): SSM parameter name containing S3 bucket for private key asset
                - private_key_asset_key_param_name (str): SSM parameter name containing S3 object key for private key asset
        """
        self.instance_id = instance_id
        self.client_id_param_name = kwargs.get('client_id_param_name')
        self.client_secret_arn = kwargs.get('client_secret_arn')
        self.user_id_param_name = kwargs.get('user_id_param_name')
        self.private_key_asset_bucket_param_name = kwargs.get('private_key_asset_bucket_param_name')
        self.private_key_asset_key_param_name = kwargs.get('private_key_asset_key_param_name')
        self.secrets_manager_service = SecretsManagerService()
        self.s3_resource = boto3.resource('s3')

    def __get_secret_value(self, secret_arn: str) -> Optional[str]:
        """
        Fetch a secret value from AWS Secrets Manager.

        Args:
            secret_arn (str): Secret ARN

        Returns:
            Optional[str]: Secret value or None if retrieval fails
        """
        try:
            if not secret_arn:
                logger.error("No secret ARN provided")
                return None

            response = secrets_client.get_secret_value(SecretId=secret_arn)
            return response["SecretString"]
        except Exception as e:
            logger.error(f"Error retrieving secret {secret_arn} from Secrets Manager: {str(e)}")
            return None
        
    def __get_request_base_url(self) -> Optional[str]:
        """Get base URL for ServiceNow API requests.

        Returns:
            Optional[str]: ServiceNow instance base URL or None if error
        """
        try:
            return f"https://{self.instance_id}.service-now.com"
        except Exception as e:
            logger.error(f"Error getting base url: {str(e)}")
            return None
        
    def __get_jwt_oauth_token_url(self) -> Optional[str]:
        """Get JWT OAuth token URL for ServiceNow.

        Returns:
            Optional[str]: OAuth token URL or None if error
        """
        try:
            return f"https://{self.instance_id}.service-now.com/oauth_token.do"
        except Exception as e:
            logger.error(f"Error getting token url: {str(e)}")
            return None

    def __get_encoded_jwt(self, client_id: str, user_id: str) -> Optional[str]:
        """Generate encoded JWT using private key from S3 asset.

        Args:
            client_id (str): OAuth client ID for JWT issuer
            user_id (str): ServiceNow user ID for JWT subject

        Returns:
            Optional[str]: Encoded JWT or None if generation fails
        """
        try:
            # Get S3 bucket and key from parameters
            bucket = self.__get_parameter(self.private_key_asset_bucket_param_name)
            key = self.__get_parameter(self.private_key_asset_key_param_name)
            
            if not bucket or not key:
                logger.error("Missing S3 bucket or key for private key asset")
                return None
            
            # Read private key using S3 resource
            s3_object = self.s3_resource.Object(bucket, key)
            private_key = s3_object.get()['Body'].read().decode('utf-8')
            
            if not user_id or not client_id:
                logger.error("Missing user ID or client ID for JWT")
                return None
            
            # Create JWT payload
            payload = {
                "iss": client_id,  # Issuer - OAuth client ID
                "sub": user_id,    # Subject - ServiceNow user ID
                "aud": client_id,  # Audience - OAuth client ID
                "iat": int(time.time()),  # Issued at - current timestamp
                "exp": int(time.time()) + 3600,  # Expiration - 1 hour from now
                "jti": str(uuid.uuid4())  # JWT ID - unique identifier
            }
            
            # Encode JWT
            encoded_jwt = jwt.encode(payload, private_key, algorithm=JWT_HEADER["alg"], headers=JWT_HEADER)
            return encoded_jwt
            
        except jwt.ExpiredSignatureError:  
            logger.error("Token has expired")  
            return None
        except jwt.InvalidIssuerError:  
            logger.error("Invalid issuer")
            return None
        except jwt.InvalidAudienceError:  
            logger.error("Invalid audience")
            return None
        except jwt.InvalidTokenError:  
            logger.error("Invalid token")
            return None
        
    def __get_jwt_oauth_access_token(self) -> Optional[str]:
        """Get OAuth access token using JWT authentication.

        Returns:
            Optional[str]: OAuth access token or None if retrieval fails
        """
        try:
            if not self.instance_id:
                logger.error("No ServiceNow instance id provided")
                return None
            
            # Get parameters for JWT OAuth
            client_secret = self.__get_secret_value(self.client_secret_arn)
            client_id = self.__get_parameter(self.client_id_param_name)
            user_id = self.__get_parameter(self.user_id_param_name)
            
            # Get encoded JWT
            encoded_jwt = self.__get_encoded_jwt(client_id, user_id)

            # Prepare request headers, data to get OAuth access token using encoded_jwt
            token_url = self.__get_jwt_oauth_token_url()
            headers = {
                        'Content-Type': JWT_CONTENT_TYPE,
                        'Authentication': f"Bearer {encoded_jwt}"
                    }
            data = {
                'grant_type': JWT_GRANT_TYPE,
                'assertion': encoded_jwt,
                'client_id': client_id,
                'client_secret': client_secret
            }
            response = requests.post(token_url, headers=headers, data=data)
            return (response.json())['access_token']
        except requests.exceptions.RequestException as e:
            logger.error(f"HTTP request failed: {str(e)}")
            return None
        except (KeyError, ValueError) as e:
            logger.error(f"Invalid response format: {str(e)}")
            return None
        
    def __get_request_headers(self) -> Optional[dict]:
        """Get headers for ServiceNow API requests.

        Returns:
            Optional[dict]: HTTP headers with Bearer authentication or None if error
        """
        try:
            oauth_access_token = self.__get_jwt_oauth_access_token()
            return {
                "Authorization": f"Bearer {oauth_access_token}",
                "Content-Type": request_content,
                "Accept": request_content,
            }
        except Exception as e:
            logger.error(f"Error getting request headers: {str(e)}")
            return None

    def __get_json_keys_list(self, json_string: str) -> Optional[list]:
        """Get list of keys from a JSON string.

        Args:
            json_string (str): JSON string to parse

        Returns:
            Optional[list]: List of keys from JSON object or None if error
        """
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
        """Add parameters to HTTP request function for Outbound REST Message resource in ServiceNow.

        Args:
            headers (Dict[str, str]): HTTP headers for ServiceNow API requests
            base_url (str): ServiceNow instance base URL
            request_content (str): JSON string containing request parameters
            outbound_rest_message_request_function_sys_id (str): System ID of the REST message function
        """
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

    def _create_system_property(self, apigw_api_key_property_name, api_auth_secret_arn):
        """Create system property for API Gateway key in ServiceNow.

        Args:
            apigw_api_key_property_name (str): Name of the system property to create
            api_auth_secret_arn (str): ARN of the API auth secret in Secrets Manager

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(
                "Creating system property for API Gateway key in ServiceNow"
            )

            # Get headers and base URL for ServiceNow API requests
            headers = self.__get_request_headers()
            base_url = self.__get_request_base_url()

            # Get API auth token from Secrets Manager
            auth_token = (
                self.secrets_manager_service.get_secret_value(api_auth_secret_arn)
                if api_auth_secret_arn
                else None
            )

            # Create password2 type property in sys_properties table if token is available
            if auth_token:
                sys_property_payload = {
                    "name": apigw_api_key_property_name,
                    "value": auth_token,
                    "type": "password2",
                    "description": "Password for external API integration",
                    "ignore_cache": "true"
                }

                requests.post(
                    f"{base_url}/api/now/table/sys_properties",
                    json=sys_property_payload,
                    headers=headers,
                    timeout=30,
                )
                logger.info(f"System property {apigw_api_key_property_name} created successfully")
                return True
            else:
                logger.error("No auth token available to create system property")
                return False
        except Exception as e:
            logger.error(f"Error creating system property: {str(e)}")
            return False

    def __update_outbound_rest_message_request_function_headers(
        self,
        headers,
        base_url,
        outbound_rest_message_request_function_name,
        api_auth_secret_arn,
    ):
        """Create/Update HTTP request headers for the Outbound REST Message function in ServiceNow.

        Args:
            headers (Dict[str, str]): HTTP headers for ServiceNow API requests
            base_url (str): ServiceNow instance base URL
            outbound_rest_message_request_function_name (str): Name of the REST message function
            api_auth_secret_arn (str): ARN of the API auth secret in Secrets Manager
        """
        try:
            logger.info(
                "Updating Http request headers in the Outbound REST Message function resource in ServiceNow for integration with AWS Security Incident Response"
            )

            # Get headers and base URL for ServiceNow API requests
            headers = self.__get_request_headers()
            base_url = self.__get_request_base_url()

            # Update Authorization header to use sys_property dynamically
            rest_message_post_function_headers_payload = {
                "rest_message_function": f"{outbound_rest_message_request_function_name}",
                # "name": "Authorization",
                # "value": "Bearer ${gs.getProperty('aws-security-ir-apigw-key')}",
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
            logger.error(
                f"Error updating Http request headers for the Outbound REST message function: {str(e)}"
            )
            return None

    def __create_outbound_rest_message_request_function(
        self,
        headers,
        base_url,
        request_type,
        request_content,
        outbound_rest_message_name,
        outbound_rest_message_request_function_name,
    ):
        """Create HTTP request function for the Outbound REST Message resource in ServiceNow.

        Args:
            headers (Dict[str, str]): HTTP headers for ServiceNow API requests
            base_url (str): ServiceNow instance base URL
            request_type (str): HTTP method (e.g., 'POST')
            request_content (str): JSON string containing request body template
            outbound_rest_message_name (str): Name of the outbound REST message
            outbound_rest_message_request_function_name (str): Name of the request function

        Returns:
            Optional[str]: System ID of the created function or None if error
        """
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

            rest_message_post_function_sys_id = (
                rest_message_post_function_response_json.get("result").get("sys_id")
            )
            return rest_message_post_function_sys_id
        except Exception as e:
            logger.error(f"Error creating Http request function: {str(e)}")
            return None

    def _create_outbound_rest_message(
        self, webhook_url, resource_prefix
    ):
        """Create Outbound REST Message for publishing Incident events to the integration solution.

        Args:
            webhook_url (str): URL of the webhook endpoint
            resource_prefix (str): Prefix for ServiceNow resource naming

        Returns:
            Optional[Tuple[str, str]]: (outbound_rest_message_name, outbound_rest_message_request_function_name) or None if error
        """
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

    def _create_incident_business_rule_itsm(
        self,
        outbound_rest_message_name,
        outbound_rest_message_request_function_name,
        resource_prefix,
        apigw_api_key_property_name,
    ):
        """Create Business Rule to trigger Incident events for ITSM module.

        Args:
            outbound_rest_message_name (str): Name of the outbound REST message
            outbound_rest_message_request_function_name (str): Name of the request function
            resource_prefix (str): Prefix for ServiceNow resource naming

        Returns:
            Optional[requests.Response]: Response from ServiceNow API or None if error
        """
        try:
            logger.info(
                "Creating ITSM Business Rule in Service Now to publish Incident related events to AWS"
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
                var event_type = current.operation() == 'insert' ? 'IncidentCreated' : 'IncidentUpdated';
                var payload = {{
                    "event_type": event_type,
                    "incident_number": current.number.toString(),
                    "short_description": current.short_description.toString(),
                }};
                var outbound_rest_message_name_str = "{outbound_rest_message_name}";
                var outbound_rest_message_request_function_name_str = "{outbound_rest_message_request_function_name}";
                var request = new sn_ws.RESTMessageV2(outbound_rest_message_name_str, outbound_rest_message_request_function_name_str);
                var api_key = gs.getProperty('{apigw_api_key_property_name}');
				request.setRequestHeader('Authorization', api_key);
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
                f"ITSM Business Rule created in Service Now: {json.loads(response.text)}"
            )

            return response
        except Exception as e:
            logger.error(
                f"Error while creating ITSM Business Rule in Service Now to publish Incident related events to AWS: {str(e)}"
            )
            return None

    def _create_incident_business_rule_ir(
        self,
        outbound_rest_message_name,
        outbound_rest_message_request_function_name,
        resource_prefix,
        apigw_api_key_property_name,
    ):
        """Create Business Rule to trigger Incident events for IR module.

        Args:
            outbound_rest_message_name (str): Name of the outbound REST message
            outbound_rest_message_request_function_name (str): Name of the request function
            resource_prefix (str): Prefix for ServiceNow resource naming

        Returns:
            Optional[requests.Response]: Response from ServiceNow API or None if error
        """
        try:
            logger.info(
                "Creating IR Business Rule in Service Now to publish Security Incident related events to AWS"
            )

            # Get headers for ServiceNow API requests
            headers = self.__get_request_headers()

            # Get base url for ServiceNow API requests
            base_url = self.__get_request_base_url()

            # Business rule for security incident events
            rule_payload = {
                "name": f"{resource_prefix}-ir-business-rule",
                "collection": "sn_si_incident",
                "when": "after",
                "action_insert": True,
                "action_update": True,
                "active": True,
                "script": f"""
        (function executeRule(current, previous) {{
            try {{
                var event_type = current.operation() == 'insert' ? 'IncidentCreated' : 'IncidentUpdated';
                var payload = {{
                    "event_type": event_type,
                    "incident_number": current.number.toString(),
                    "short_description": current.short_description.toString(),
                }};
                var outbound_rest_message_name_str = "{outbound_rest_message_name}";
                var outbound_rest_message_request_function_name_str = "{outbound_rest_message_request_function_name}";
                var request = new sn_ws.RESTMessageV2(outbound_rest_message_name_str, outbound_rest_message_request_function_name_str);
                var api_key = gs.getProperty('{apigw_api_key_property_name}');
				request.setRequestHeader('Authorization', api_key);
                request.setRequestBody(JSON.stringify(payload));
                
                var response = request.executeAsync();
                gs.info('Security Incident event published to AWS Security Incident Response API Gateway: ' + event_type);
                var responseBody = response.getBody();
                var httpStatus = response.getStatusCode();
                gs.info("Security Incident Event Response: " + responseBody);
                gs.info("Security Incident Event HTTP Status: " + httpStatus);
                
            }} catch (error) {{
                gs.error('Error sending security incident event: ' + error.message);
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
                f"IR Business Rule created in Service Now: {json.loads(response.text)}"
            )

            return response
        except Exception as e:
            logger.error(
                f"Error while creating IR Business Rule in Service Now to publish Security Incident related events to AWS: {str(e)}"
            )
            return None

    def _create_attachment_business_rule_itsm(
        self,
        outbound_rest_message_name,
        outbound_rest_message_request_function_name,
        resource_prefix,
        apigw_api_key_property_name,
    ):
        """Create Business Rule to trigger Incident events for attachment changes.

        Args:
            outbound_rest_message_name (str): Name of the outbound REST message
            outbound_rest_message_request_function_name (str): Name of the request function
            resource_prefix (str): Prefix for ServiceNow resource naming
            apigw_api_key_property_name (str): Name of the system property containing API key

        Returns:
            Optional[requests.Response]: Response from ServiceNow API or None if error
        """
        try:
            logger.info(
                "Creating Attachment Business Rule in Service Now to publish Incident attachment events to AWS"
            )

            # Get headers for ServiceNow API requests
            headers = self.__get_request_headers()

            # Get base url for ServiceNow API requests
            base_url = self.__get_request_base_url()

            # Business rule for attachment events on incident table
            rule_payload = {
                "name": f"{resource_prefix}-attachment-business-rule",
                "collection": "sys_attachment",
                "when": "after",
                "action_insert": True,
                "active": True,
                "script": f"""
        (function executeRule(current, previous) {{
            try {{
                // Only process attachments for incident table
                gs.info('The current table name is:' + current.table_name);
                if (current.table_name != 'incident') {{
                    return;
                }}
                
                var event_type = 'IncidentUpdated';
                var incident_sys_id = current.table_sys_id.getDisplayValue().toString();
				gs.info('The incident sys_id: ' + incident_sys_id);
                
                // Get incident record to fetch incident number
                var incident = new GlideRecord('incident');
                if (incident.get(incident_sys_id)) {{
                    var payload = {{
                        "event_type": event_type,
                        "incident_number": incident.number.toString(),
                        "short_description": incident.short_description.toString(),
                    }};
                    
                    var outbound_rest_message_name_str = "{outbound_rest_message_name}";
                    var outbound_rest_message_request_function_name_str = "{outbound_rest_message_request_function_name}";
                    var request = new sn_ws.RESTMessageV2(outbound_rest_message_name_str, outbound_rest_message_request_function_name_str);
                    var api_key = gs.getProperty('{apigw_api_key_property_name}');
				    request.setRequestHeader('Authorization', api_key);
                    request.setRequestBody(JSON.stringify(payload));
                    
                    var response = request.executeAsync();
                    gs.info('Incident attachment event published to AWS Security Incident Response API Gateway: ' + event_type);
                    var responseBody = response.getBody();
                    var httpStatus = response.getStatusCode();
                    gs.info("Attachment Event Response: " + responseBody);
                    gs.info("Attachment Event HTTP Status: " + httpStatus);
                }} else {{
                    gs.warn('Could not find incident with sys_id: ' + incident_sys_id);
                }}
                
            }} catch (error) {{
                gs.error('Error sending incident attachment event: ' + error.message);
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
                f"Attachment Business Rule created in Service Now: {json.loads(response.text)}"
            )

            return response
        except Exception as e:
            logger.error(
                f"Error while creating Attachment Business Rule in Service Now: {str(e)}"
            )
            return None

    def _create_attachment_business_rule_ir(
        self,
        outbound_rest_message_name,
        outbound_rest_message_request_function_name,
        resource_prefix,
        apigw_api_key_property_name,
    ):
        """Create Business Rule to trigger Incident events for attachment changes.

        Args:
            outbound_rest_message_name (str): Name of the outbound REST message
            outbound_rest_message_request_function_name (str): Name of the request function
            resource_prefix (str): Prefix for ServiceNow resource naming

        Returns:
            Optional[requests.Response]: Response from ServiceNow API or None if error
        """
        try:
            logger.info(
                "Creating Attachment Business Rule in Service Now to publish Incident attachment events to AWS"
            )

            # Get headers for ServiceNow API requests
            headers = self.__get_request_headers()

            # Get base url for ServiceNow API requests
            base_url = self.__get_request_base_url()

            # Business rule for attachment events on incident table
            rule_payload = {
                "name": f"{resource_prefix}-attachment-business-rule",
                "collection": "sys_attachment",
                "when": "after",
                "action_insert": True,
                "active": True,
                "script": f"""
        (function executeRule(current, previous) {{
            try {{
                // Only process attachments for incident table
                gs.info('The current table name is:' + current.table_name);
                if (current.table_name != 'sn_si_incident') {{
                    return;
                }}
                
                var event_type = 'IncidentUpdated';
                var incident_sys_id = current.table_sys_id.getDisplayValue().toString();
				gs.info('The incident sys_id: ' + incident_sys_id);
                
                // Get incident record to fetch incident number
                var incident = new GlideRecord('sn_si_incident');
                if (incident.get(incident_sys_id)) {{
                    var payload = {{
                        "event_type": event_type,
                        "incident_number": incident.number.toString(),
                        "short_description": incident.short_description.toString(),
                    }};
                    
                    var outbound_rest_message_name_str = "{outbound_rest_message_name}";
                    var outbound_rest_message_request_function_name_str = "{outbound_rest_message_request_function_name}";
                    var request = new sn_ws.RESTMessageV2(outbound_rest_message_name_str, outbound_rest_message_request_function_name_str);
                    var api_key = gs.getProperty('{apigw_api_key_property_name}');
				    request.setRequestHeader('Authorization', api_key);
                    request.setRequestBody(JSON.stringify(payload));
                    
                    var response = request.executeAsync();
                    gs.info('Incident attachment event published to AWS Security Incident Response API Gateway: ' + event_type);
                    var responseBody = response.getBody();
                    var httpStatus = response.getStatusCode();
                    gs.info("Attachment Event Response: " + responseBody);
                    gs.info("Attachment Event HTTP Status: " + httpStatus);
                }} else {{
                    gs.warn('Could not find incident with sys_id: ' + incident_sys_id);
                }}
                
            }} catch (error) {{
                gs.error('Error sending incident attachment event: ' + error.message);
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
                f"Attachment Business Rule created in Service Now: {json.loads(response.text)}"
            )

            return response
        except Exception as e:
            logger.error(
                f"Error while creating Attachment Business Rule in Service Now: {str(e)}"
            )
            return None


def handler(event, context):
    """
    Custom resource handler to create ServiceNow resources.

    Creates outbound REST message and business rule in ServiceNow for integration
    with AWS Security Incident Response.

    Args:
        event (dict): CloudFormation custom resource event
        context: Lambda context object (unused)

    Returns:
        dict: CloudFormation custom resource response with Status and PhysicalResourceId
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
        client_id_param_name = os.environ.get("SERVICE_NOW_CLIENT_ID")
        client_secret_arn = os.environ.get("SERVICE_NOW_CLIENT_SECRET_ARN")
        user_id_param_name = os.environ.get("SERVICE_NOW_USER_ID")
        private_key_asset_bucket_param_name = os.environ.get("PRIVATE_KEY_ASSET_BUCKET")
        private_key_asset_key_param_name = os.environ.get("PRIVATE_KEY_ASSET_KEY")

        service_now_api_service = ServiceNowApiService(
            instance_id,
            client_id_param_name=client_id_param_name,
            client_secret_arn=client_secret_arn,
            user_id_param_name=user_id_param_name,
            private_key_asset_bucket_param_name=private_key_asset_bucket_param_name,
            private_key_asset_key_param_name=private_key_asset_key_param_name
        )

        # Create system property for API Gateway key
        apigw_api_key_property_name = f"{service_now_resource_prefix}-aws-apigw-key"
        if not service_now_api_service._create_system_property(apigw_api_key_property_name, api_auth_secret_arn):
            logger.error("Failed to create system property for API Gateway key")
            return {"Status": "FAILED", "PhysicalResourceId": "service-now-api-setup"}

        outbound_rest_message_result = (
            service_now_api_service._create_outbound_rest_message(
                webhook_url, service_now_resource_prefix
            )
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

        # Get integration module from environment variable
        integration_module = os.environ.get("INTEGRATION_MODULE", "itsm")

        # Create appropriate business rule based on integration module
        if integration_module == "ir":
            service_now_api_service._create_incident_business_rule_ir(
                service_now_api_outbound_rest_message_name,
                service_now_api_outbound_rest_message_request_function_name,
                service_now_resource_prefix,
                apigw_api_key_property_name,
            )
            # Create attachment business rule
            service_now_api_service._create_attachment_business_rule_ir(
                service_now_api_outbound_rest_message_name,
                service_now_api_outbound_rest_message_request_function_name,
                service_now_resource_prefix,
                apigw_api_key_property_name,
            )
        else:
            service_now_api_service._create_incident_business_rule_itsm(
                service_now_api_outbound_rest_message_name,
                service_now_api_outbound_rest_message_request_function_name,
                service_now_resource_prefix,
                apigw_api_key_property_name,
            )
            # Create attachment business rule
            service_now_api_service._create_attachment_business_rule_itsm(
                service_now_api_outbound_rest_message_name,
                service_now_api_outbound_rest_message_request_function_name,
                service_now_resource_prefix,
                apigw_api_key_property_name,
            )

        return {"Status": "SUCCESS", "PhysicalResourceId": "service-now-api-setup"}

    except Exception as e:
        logger.error(f"Error in custom resource handler: {str(e)}")
        return {"Status": "FAILED", "PhysicalResourceId": "service-now-api-setup"}

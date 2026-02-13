"""
End-to-end acceptance tests for ServiceNow Integration with AWS Security Incident Response.

This test suite:
1. Deploys the ServiceNow integration stack (generates keys, configures OAuth)
2. Executes bidirectional sync tests
3. Tears down the deployment

Usage:
    pytest tests/acceptance/test_service_now.py \
        --service-now-url=https://dev12345.service-now.com \
        --service-now-username=admin \
        --service-now-password=password

Prerequisites:
- AWS credentials configured with permissions to deploy CDK stacks
- ServiceNow instance with admin access
- CDK bootstrapped in the target AWS account/region
"""

import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from botocore.config import Config
import boto3
import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone

from mypy_boto3_security_ir.type_defs import CreateCaseResponseTypeDef, GetCaseResponseTypeDef

# Test configuration
# Note: The notification handler has retry logic that can take up to 2-3 minutes
# for new incidents when the webhook sends IncidentUpdated instead of IncidentCreated
# (ServiceNow async business rules don't reliably detect insert operations)
SYNC_TIMEOUT_SECONDS = 180  # 3 minutes to allow for notification handler retries
POLL_INTERVAL_SECONDS = 15
SERVICE_NOW_STACK_NAME = 'AwsSecurityIncidentResponseServiceNowIntegrationStack'

@pytest.fixture(scope="module")
def service_now_config(request) -> Dict[str, str]:
    """Get ServiceNow configuration from command line options."""
    url = request.config.getoption("--service-now-url")
    username = request.config.getoption("--service-now-username")
    password = request.config.getoption("--service-now-password")
    
    # Validate required parameters
    if not url:
        pytest.skip("--service-now-url is required for acceptance tests")
    if not username:
        pytest.skip("--service-now-username is required for acceptance tests")
    if not password:
        pytest.skip("--service-now-password is required for acceptance tests")
    
    # Extract instance ID from URL
    instance_id = url.replace("https://", "").replace("http://", "").split(".")[0]
    
    return {
        "url": url,
        "instance_id": instance_id,
        "username": username,
        "password": password,
        "integration_module": request.config.getoption("--integration-module"),
    }



class CloudFormationClient:
    def __init__(self):
        self.client = boto3.client("cloudformation")

    def is_stack_deployed(self, stack_name: str) -> bool:
        """Check if CloudFormation stack is deployed successfully."""
        try:
            response = self.client.describe_stacks(StackName=stack_name)
            status = response['Stacks'][0]['StackStatus']
            return status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']
        except self.client.exceptions.ClientError:
            return False

    def is_stack_stabilized(self, stack_name: str):
        """Wait for CloudFormation stack to stabilize."""
        response = self.client.describe_stacks(StackName=stack_name)
        status = response['Stacks'][0]['StackStatus']
        if status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
            print(f'Stack {stack_name} already {status}')
            return True
        elif status == 'CREATE_IN_PROGRESS':
            boto3.client('cloudformation').get_waiter('stack_create_complete').wait(
                StackName=stack_name)
            return True
        elif status == 'UPDATE_IN_PROGRESS':
            boto3.client('cloudformation').get_waiter('stack_update_complete').wait(
                StackName=stack_name)
            return True
        else:
            return False

class KeyGenerator:
    """Generate RSA key pair and JKS keystore for JWT OAuth."""

    # Default keystore password - used for both keystore and key entry
    # This is the well-known default JKS keystore password, not a real secret
    DEFAULT_KEYSTORE_PASSWORD = "changeit"  # nosec B105 # pragma: allowlist secret
    DEFAULT_KEY_ALIAS = "awssirkey"

    @staticmethod
    def generate_jks_keystore(
        temp_dir: Path,
        keystore_password: str = DEFAULT_KEYSTORE_PASSWORD,
        key_alias: str = DEFAULT_KEY_ALIAS,
    ) -> Tuple[bytes, bytes, str, str]:
        """Generate RSA key pair in JKS format using keytool.
        
        ServiceNow's JWT OAuth requires JKS format certificates. This method:
        1. Generates a self-signed certificate with private key using keytool
        2. Exports the private key to PEM format for Lambda to sign JWTs
        3. Returns the JKS bytes for uploading to ServiceNow
        
        Args:
            temp_dir: Directory to store temporary files
            keystore_password: Password for the JKS keystore
            key_alias: Alias for the key entry in the keystore
            
        Returns:
            Tuple of (jks_bytes, private_key_pem, keystore_password, key_alias)
        """
        jks_path = temp_dir / "keystore.jks"
        p12_path = temp_dir / "keystore.p12"
        private_key_path = temp_dir / "private.key"
        
        # Step 1: Generate self-signed certificate with keytool
        print("Generating JKS keystore with keytool...")
        keytool_cmd = [
            "keytool", "-genkeypair",
            "-alias", key_alias,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "365",
            "-keystore", str(jks_path),
            "-storepass", keystore_password,
            "-keypass", keystore_password,
            "-dname", "CN=test.example.com,OU=AWS Security IR,O=Test,L=Seattle,ST=Washington,C=US",
        ]
        
        result = subprocess.run(keytool_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"keytool genkeypair failed: {result.stderr}")
        
        # Step 2: Convert JKS to PKCS12 format (needed to extract private key)
        print("Converting JKS to PKCS12...")
        convert_cmd = [
            "keytool", "-importkeystore",
            "-srckeystore", str(jks_path),
            "-destkeystore", str(p12_path),
            "-deststoretype", "PKCS12",
            "-srcstorepass", keystore_password,
            "-deststorepass", keystore_password,
            "-srcalias", key_alias,
            "-destalias", key_alias,
        ]
        
        result = subprocess.run(convert_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"keytool importkeystore failed: {result.stderr}")
        
        # Step 3: Extract private key using openssl
        print("Extracting private key with openssl...")
        openssl_cmd = [
            "openssl", "pkcs12",
            "-in", str(p12_path),
            "-out", str(private_key_path),
            "-nocerts",
            "-nodes",
            "-passin", f"pass:{keystore_password}",
        ]
        
        result = subprocess.run(openssl_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"openssl pkcs12 failed: {result.stderr}")
        
        # Read the generated files
        jks_bytes = jks_path.read_bytes()
        private_key_pem = private_key_path.read_bytes()
        
        print(f"Generated JKS keystore ({len(jks_bytes)} bytes) and private key")
        
        return jks_bytes, private_key_pem, keystore_password, key_alias

    @staticmethod
    def generate_key_pair() -> Tuple[bytes, bytes]:
        """Generate RSA private key and self-signed X.509 certificate (PEM format).
        
        This is the legacy method kept for compatibility. For ServiceNow JWT OAuth,
        use generate_jks_keystore() instead.
        
        Returns:
            Tuple of (private_key_pem, certificate_pem)
        """
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Serialize private key to PEM
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        # Generate self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Washington"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Seattle"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AWS Security IR Integration Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        
        certificate_pem = cert.public_bytes(serialization.Encoding.PEM)
        
        return private_key_pem, certificate_pem


class ServiceNowOAuthSetup:
    """Set up OAuth application in ServiceNow for JWT authentication."""

    # Default timeout for HTTP requests (30 seconds)
    REQUEST_TIMEOUT = 30

    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip("/")
        self.auth = (username, password)
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self.created_resources = []

    def upload_certificate(self, certificate_pem: bytes) -> str:
        """Upload X.509 certificate to ServiceNow (PEM format - legacy).
        
        Returns:
            sys_id of the created certificate record
        """
        print('Uploading Certificate (PEM)')
        endpoint = f"{self.url}/api/now/table/sys_certificate"
        payload = {
            "name": f"AWS Security IR Test Certificate {uuid.uuid4().hex[:8]}",
            "format": "PEM",
            "type": "trust_store",
            "pem_certificate": certificate_pem.decode("utf-8"),
        }
        
        response = requests.post(
            endpoint, auth=self.auth, headers=self.headers, json=payload, timeout=self.REQUEST_TIMEOUT
        )
        response.raise_for_status()
        sys_id = response.json()["result"]["sys_id"]
        self.created_resources.append(("sys_certificate", sys_id))
        return sys_id

    def upload_jks_certificate(self, jks_bytes: bytes, keystore_password: str, key_alias: str) -> str:
        """Upload JKS keystore to ServiceNow for JWT OAuth.
        
        NOTE: JKS upload via API is problematic in ServiceNow. This method attempts
        to upload but may fail with "Couldn't find Crypto Module" errors.
        Consider using upload_certificate() with PEM format instead.
        
        Args:
            jks_bytes: The JKS keystore file contents
            keystore_password: Password for the keystore
            key_alias: Alias of the key entry in the keystore
            
        Returns:
            sys_id of the created certificate record
        """
        import base64
        
        print('Uploading JKS Certificate to ServiceNow...')
        cert_name = f"AWS Security IR Test JKS {uuid.uuid4().hex[:8]}"
        
        # ServiceNow expects JKS content as base64 in the key_store field
        jks_base64 = base64.b64encode(jks_bytes).decode('utf-8')
        
        endpoint = f"{self.url}/api/now/table/sys_certificate"
        payload = {
            "name": cert_name,
            "type": "jks",  # JKS type for Java KeyStore
            "active": "true",
            "key_store_password": keystore_password,
            "key_store": jks_base64,  # Base64-encoded JKS content
        }
        
        response = requests.post(
            endpoint, auth=self.auth, headers=self.headers, json=payload, timeout=self.REQUEST_TIMEOUT
        )
        
        if response.status_code != 201:
            print(f"JKS certificate creation failed: {response.status_code} - {response.text}")
            response.raise_for_status()
        
        cert_sys_id = response.json()["result"]["sys_id"]
        self.created_resources.append(("sys_certificate", cert_sys_id))
        print(f"Created JKS certificate record with sys_id: {cert_sys_id}")
        
        return cert_sys_id

    def get_table_columns(self, table_name: str) -> list:
        """Get column names for a ServiceNow table.
        
        Args:
            table_name: Name of the table to query
            
        Returns:
            List of column names
        """
        endpoint = f"{self.url}/api/now/table/sys_dictionary"
        params = {
            "sysparm_query": f"name={table_name}",
            "sysparm_fields": "element,column_label,internal_type",
            "sysparm_limit": 100,
        }
        
        response = requests.get(
            endpoint, auth=self.auth, headers=self.headers, params=params
        )
        
        if response.status_code == 200:
            results = response.json().get("result", [])
            columns = [(r.get("element"), r.get("column_label"), r.get("internal_type")) for r in results if r.get("element")]
            return columns
        return []

    def create_service_account_user(self, username: str = "aws_integration") -> Optional[Dict[str, str]]:
        """Create a service account user for JWT OAuth authentication.
        
        ServiceNow doesn't allow JWT bearer tokens to authenticate as 'admin',
        so we need a dedicated service account user with appropriate roles.
        
        IMPORTANT: The user must NOT have the 'admin' role, as ServiceNow blocks
        JWT bearer grants to admin users. Instead, we grant specific roles needed
        for the integration.
        
        Args:
            username: The username for the service account (default: aws_integration per documentation)
            
        Returns:
            Dict with 'username' and 'sys_id' if created or already exists, None on failure.
            The sys_id is required for JWT OAuth because ServiceNow's oauth_jwt.sub_claim
            defaults to 'sys_id' and cannot be changed via API.
        """
        print(f"Creating service account user '{username}'...")
        
        # Check if user already exists
        user_endpoint = f"{self.url}/api/now/table/sys_user"
        response = requests.get(
            user_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"user_name={username}", "sysparm_limit": 1}
        )
        response.raise_for_status()
        
        users = response.json().get("result", [])
        if users:
            user_sys_id = users[0]["sys_id"]
            print(f"Service account user '{username}' already exists with sys_id: {user_sys_id}")
            # Update user to ensure web_service_access_only is false
            requests.patch(
                f"{user_endpoint}/{user_sys_id}",
                auth=self.auth,
                headers=self.headers,
                json={"web_service_access_only": "false", "active": "true"}
            )
            # Ensure the user has all required roles
            self.ensure_user_has_required_roles(username)
            return {"user_name": username, "sys_id": user_sys_id}
        
        # Create the service account user
        # NOTE: web_service_access_only must be false to allow full API access
        payload = {
            "user_name": username,
            "first_name": "AWS",
            "last_name": "Security IR Integration",
            "email": f"{username}@example.com",
            "active": "true",
            "web_service_access_only": "false",  # Must be false for full API access
        }
        
        response = requests.post(
            user_endpoint,
            auth=self.auth,
            headers=self.headers,
            json=payload
        )
        
        if response.status_code == 201:
            user_sys_id = response.json()["result"]["sys_id"]
            self.created_resources.append(("sys_user", user_sys_id))
            print(f"Created service account user '{username}' with sys_id: {user_sys_id}")
            
            # Grant all required roles to the new user
            self.ensure_user_has_required_roles(username)
            return {"user_name": username, "sys_id": user_sys_id}
        else:
            print(f"Failed to create service account user: {response.status_code} - {response.text}")
            return None

    def ensure_user_has_required_roles(self, username: str) -> bool:
        """Ensure the user has all roles required for the integration.
        
        The user needs roles for:
        - Incident management (itil, sn_incident_write, sn_incident_read)
        - REST message creation (web_service_admin, rest_service)
        - Business rule creation (personalize_rules, personalize)
        - Discovery credentials (discovery_admin, credential_admin)
        - OAuth (oauth_user)
        
        NOTE: Do NOT grant 'admin' role - ServiceNow blocks JWT bearer grants to admin users.
        
        Args:
            username: The username to grant roles to
            
        Returns:
            True if all roles were granted successfully
        """
        assert username != "admin", "ServiceNow blocks JWT bearer grants to admin users"
        assert username != "", "Username cannot be empty"

        print(f"Ensuring user '{username}' has all required roles...")
        
        # Get the user's sys_id
        user_endpoint = f"{self.url}/api/now/table/sys_user"
        response = requests.get(
            user_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"user_name={username}", "sysparm_limit": 1}
        )
        response.raise_for_status()
        
        users = response.json().get("result", [])
        if not users:
            print(f"Warning: User '{username}' not found in ServiceNow")
            return False
        
        user_sys_id = users[0]["sys_id"]
        
        # Roles required for the integration - aligned with SERVICE_NOW.md documentation
        # NOTE: 'admin' is intentionally excluded - OAuth blocks JWT grants to admin users
        required_roles = [
            # ITSM Mode - incident table access
            "itil",  # Base ITIL role - grants read/write access to incident table
            # REST/Web services (per documentation)
            "rest_api_explorer",  # or custom role with permissions to create Outbound REST Message
            "web_service_admin",  # or custom role with permissions to create Outbound REST Message
            # Business rules (per documentation)
            "business_rule_admin",  # for performing operations on Business Rules
            # Incident management (per documentation)
            "incident_manager",  # for performing operations on Incidents
            "snc_internal",  # ServiceNow internal role
            # IR Mode - Security Incident Response roles (per documentation)
            "sn_si.analyst",  # for performing operations on Security Incidents
            "sn_si.basic",  # for performing operations on Security Incidents
            "sn_si.external",  # for performing operations on Security Incidents
            "sn_si.integration_user",  # for performing operations on Security Incidents
            "sn_si.manager",  # for performing operations on Security Incidents
            "sn_si.read",  # for performing operations on Security Incidents
            # Credentials (per documentation)
            "credential_admin",  # for storing the sensitive APIKey as discovery_credential
        ]
        
        role_endpoint = f"{self.url}/api/now/table/sys_user_role"
        has_role_endpoint = f"{self.url}/api/now/table/sys_user_has_role"
        
        success = True
        for role_name in required_roles:
            # Get role sys_id
            response = requests.get(
                role_endpoint,
                auth=self.auth,
                headers=self.headers,
                params={"sysparm_query": f"name={role_name}", "sysparm_limit": 1}
            )
            
            roles = response.json().get("result", [])
            if not roles:
                print(f"   Role not found: {role_name}")
                continue
            
            role_sys_id = roles[0]["sys_id"]
            
            # Check if user already has the role
            response = requests.get(
                has_role_endpoint,
                auth=self.auth,
                headers=self.headers,
                params={"sysparm_query": f"user={user_sys_id}^role={role_sys_id}", "sysparm_limit": 1}
            )
            
            if response.json().get("result", []):
                continue  # Already has role
            
            # Grant the role
            response = requests.post(
                has_role_endpoint,
                auth=self.auth,
                headers=self.headers,
                json={"user": user_sys_id, "role": role_sys_id}
            )
            
            if response.status_code == 201:
                sys_id = response.json()["result"]["sys_id"]
                self.created_resources.append(("sys_user_has_role", sys_id))
                print(f"   Added role: {role_name}")
            else:
                print(f"   Failed to add role {role_name}: {response.status_code}")
                success = False
        
        return success

    def create_custom_integration_role(self, role_name: str = "aws_sir_integration_admin") -> Optional[str]:
        """Create a custom role for the AWS Security IR integration.
        
        This role will be granted write access to the tables needed by the setup handler:
        - sys_rest_message (Outbound REST Message)
        - sys_rest_message_fn (REST Message HTTP Methods)
        - sys_script (Business Rules)
        - discovery_credentials (Discovery Credentials)
        
        Args:
            role_name: Name for the custom role
            
        Returns:
            sys_id of the created role, or existing role's sys_id if it already exists
        """
        print(f"Creating custom integration role: {role_name}")
        
        role_endpoint = f"{self.url}/api/now/table/sys_user_role"
        
        # Check if role already exists
        response = requests.get(
            role_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"name={role_name}", "sysparm_limit": 1}
        )
        
        existing = response.json().get("result", [])
        if existing:
            print(f"  Role '{role_name}' already exists: {existing[0]['sys_id']}")
            return existing[0]["sys_id"]
        
        # Create the role
        payload = {
            "name": role_name,
            "description": "Custom role for AWS Security IR integration - grants write access to REST message, business rule, and credential tables",
        }
        
        response = requests.post(
            role_endpoint,
            auth=self.auth,
            headers=self.headers,
            json=payload
        )
        
        if response.status_code == 201:
            role_sys_id = response.json()["result"]["sys_id"]
            self.created_resources.append(("sys_user_role", role_sys_id))
            print(f"  Created role '{role_name}': {role_sys_id}")
            return role_sys_id
        else:
            print(f"  Failed to create role: {response.status_code} - {response.text}")
            return None

    def create_acl_for_table(self, table_name: str, operation: str, role_sys_id: str) -> Optional[str]:
        """Create an ACL granting a role access to a table operation.
        
        Args:
            table_name: The table to grant access to (e.g., 'sys_rest_message')
            operation: The operation to grant (e.g., 'create', 'write', 'read', 'delete')
            role_sys_id: sys_id of the role to grant access to
            
        Returns:
            sys_id of the created ACL, or None if creation failed
        """
        acl_endpoint = f"{self.url}/api/now/table/sys_security_acl"
        acl_role_endpoint = f"{self.url}/api/now/table/sys_security_acl_role"
        
        # Check if ACL already exists for this table/operation with our role
        response = requests.get(
            acl_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={
                "sysparm_query": f"name={table_name}^operation={operation}^type=record",
                "sysparm_limit": 10
            }
        )
        
        existing_acls = response.json().get("result", [])
        
        # Check if any existing ACL already has our role
        for acl in existing_acls:
            acl_sys_id = acl["sys_id"]
            # Check if this ACL has our role
            role_check = requests.get(
                acl_role_endpoint,
                auth=self.auth,
                headers=self.headers,
                params={"sysparm_query": f"sys_security_acl={acl_sys_id}^sys_user_role={role_sys_id}"}
            )
            if role_check.json().get("result", []):
                print(f"    ACL for {table_name}.{operation} already has role assigned")
                return acl_sys_id
        
        # Create new ACL
        acl_payload = {
            "name": table_name,
            "operation": operation,
            "type": "record",
            "active": "true",
            "admin_overrides": "true",  # Allow admin to still override
            "description": f"AWS SIR Integration - {operation} access to {table_name}",
        }
        
        response = requests.post(
            acl_endpoint,
            auth=self.auth,
            headers=self.headers,
            json=acl_payload
        )
        
        if response.status_code != 201:
            print(f"    Failed to create ACL for {table_name}.{operation}: {response.status_code} - {response.text}")
            return None
        
        acl_sys_id = response.json()["result"]["sys_id"]
        self.created_resources.append(("sys_security_acl", acl_sys_id))
        print(f"    Created ACL for {table_name}.{operation}: {acl_sys_id}")
        
        # Assign the role to the ACL
        role_assignment_payload = {
            "sys_security_acl": acl_sys_id,
            "sys_user_role": role_sys_id,
        }
        
        response = requests.post(
            acl_role_endpoint,
            auth=self.auth,
            headers=self.headers,
            json=role_assignment_payload
        )
        
        if response.status_code == 201:
            role_assignment_sys_id = response.json()["result"]["sys_id"]
            self.created_resources.append(("sys_security_acl_role", role_assignment_sys_id))
            print(f"    Assigned role to ACL: {role_assignment_sys_id}")
        else:
            print(f"    Failed to assign role to ACL: {response.status_code} - {response.text}")
        
        return acl_sys_id

    def setup_integration_acls(self, username: str) -> bool:
        """Set up custom ACLs to allow the integration user to create webhook resources.
        
        ServiceNow's out-of-box ACLs on sys_rest_message, sys_script, etc. only allow
        admin role to write. Since JWT OAuth cannot authenticate as admin, we need to
        create custom ACLs that grant a custom role write access to these tables.
        
        This method:
        1. Creates a custom role (aws_sir_integration_admin)
        2. Creates ACLs granting that role write access to required tables
        3. Assigns the custom role to the integration user
        
        Args:
            username: The integration user to grant permissions to
            
        Returns:
            True if all ACLs were created successfully
        """
        print("Setting up custom ACLs for integration user...")
        
        # Tables that the setup handler needs to write to
        # These have admin_overrides=true with no roles, so only admin can write by default
        required_tables = [
            "sys_rest_message",       # Outbound REST Message
            "sys_rest_message_fn",    # REST Message HTTP Methods  
            "sys_rest_message_fn_parameters",  # REST Message Function Parameters
            "sys_script",             # Business Rules
            "discovery_credentials",  # Discovery Credentials for API key storage
        ]
        
        # Operations needed for each table
        operations = ["create", "write", "read", "delete"]
        
        # Step 1: Create custom role
        role_sys_id = self.create_custom_integration_role()
        if not role_sys_id:
            print("  Failed to create custom role")
            return False
        
        # Step 2: Create ACLs for each table/operation
        print("  Creating ACLs for required tables...")
        success = True
        for table in required_tables:
            for operation in operations:
                acl_sys_id = self.create_acl_for_table(table, operation, role_sys_id)
                if not acl_sys_id:
                    success = False
        
        # Step 3: Assign custom role to integration user
        print(f"  Assigning custom role to user '{username}'...")
        
        # Get user sys_id
        user_endpoint = f"{self.url}/api/now/table/sys_user"
        response = requests.get(
            user_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"user_name={username}", "sysparm_limit": 1}
        )
        
        users = response.json().get("result", [])
        if not users:
            print(f"  User '{username}' not found")
            return False
        
        user_sys_id = users[0]["sys_id"]
        
        # Check if user already has the role
        has_role_endpoint = f"{self.url}/api/now/table/sys_user_has_role"
        response = requests.get(
            has_role_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"user={user_sys_id}^role={role_sys_id}", "sysparm_limit": 1}
        )
        
        if response.json().get("result", []):
            print(f"  User already has custom role")
        else:
            # Assign role to user
            response = requests.post(
                has_role_endpoint,
                auth=self.auth,
                headers=self.headers,
                json={"user": user_sys_id, "role": role_sys_id}
            )
            
            if response.status_code == 201:
                sys_id = response.json()["result"]["sys_id"]
                self.created_resources.append(("sys_user_has_role", sys_id))
                print(f"  Assigned custom role to user: {sys_id}")
            else:
                print(f"  Failed to assign role to user: {response.status_code}")
                success = False
        
        print(f"  ACL setup {'completed successfully' if success else 'completed with errors'}")
        return success

    def assign_auth_scope_to_oauth_entity(self, oauth_entity_sys_id: str, scope_name: str = "useraccount") -> bool:
        """Assign an authentication scope to an OAuth entity via its profile.
        
        This creates a record in the oauth_m2m_scope_profile table to link
        the OAuth entity's profile to the specified scope (e.g., 'useraccount').
        
        The relationship is:
        - oauth_entity (or oauth_jwt) -> oauth_entity_profile (via oauth_entity field)
        - oauth_entity_scope (contains scopes like 'useraccount')
        - oauth_m2m_scope_profile (links profile to scope)
        
        The 'useraccount' scope grants the access token the same rights as the
        user account that authorized the token.
        
        Args:
            oauth_entity_sys_id: sys_id of the OAuth entity (oauth_jwt record)
            scope_name: Name of the scope to assign (default: 'useraccount')
            
        Returns:
            True if the scope was assigned successfully
        """
        print(f"Assigning '{scope_name}' scope to OAuth entity...")
        
        # Step 1: Find the oauth_entity_profile for this oauth_entity
        profile_endpoint = f"{self.url}/api/now/table/oauth_entity_profile"
        response = requests.get(
            profile_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"oauth_entity={oauth_entity_sys_id}", "sysparm_limit": 1}
        )
        
        if response.status_code != 200:
            print(f"  Failed to query oauth_entity_profile: {response.status_code}")
            return False
        
        profiles = response.json().get("result", [])
        if not profiles:
            print(f"  No oauth_entity_profile found for oauth_entity {oauth_entity_sys_id}")
            # Profile should be auto-created, but if not, we can create one
            print(f"  Creating oauth_entity_profile...")
            response = requests.post(
                profile_endpoint,
                auth=self.auth,
                headers=self.headers,
                json={
                    "oauth_entity": oauth_entity_sys_id,
                    "name": f"Default Profile",
                    "default": "true"
                }
            )
            if response.status_code == 201:
                profile_sys_id = response.json()["result"]["sys_id"]
                self.created_resources.append(("oauth_entity_profile", profile_sys_id))
                print(f"  Created oauth_entity_profile: {profile_sys_id}")
            else:
                print(f"  Failed to create profile: {response.status_code} - {response.text}")
                return False
        else:
            profile_sys_id = profiles[0]["sys_id"]
            print(f"  Found oauth_entity_profile: {profile_sys_id}")
        
        # Step 2: Find the oauth_entity_scope for the scope name
        scope_endpoint = f"{self.url}/api/now/table/oauth_entity_scope"
        response = requests.get(
            scope_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"name={scope_name}", "sysparm_limit": 1}
        )
        
        if response.status_code != 200:
            print(f"  Failed to query oauth_entity_scope: {response.status_code}")
            return False
        
        scopes = response.json().get("result", [])
        if not scopes:
            print(f"  Scope '{scope_name}' not found in oauth_entity_scope, creating it...")
            response = requests.post(
                scope_endpoint,
                auth=self.auth,
                headers=self.headers,
                json={"name": scope_name, "oauth_entity": oauth_entity_sys_id}
            )
            if response.status_code == 201:
                scope_sys_id = response.json()["result"]["sys_id"]
                self.created_resources.append(("oauth_entity_scope", scope_sys_id))
                print(f"  Created oauth_entity_scope '{scope_name}': {scope_sys_id}")
            else:
                print(f"  Failed to create scope: {response.status_code} - {response.text}")
                return False
        else:
            scope_sys_id = scopes[0]["sys_id"]
            print(f"  Found oauth_entity_scope '{scope_name}': {scope_sys_id}")
        
        # Step 3: Check if the mapping already exists in oauth_entity_profile_scope
        m2m_endpoint = f"{self.url}/api/now/table/oauth_entity_profile_scope"
        response = requests.get(
            m2m_endpoint,
            auth=self.auth,
            headers=self.headers,
            params={
                "sysparm_query": f"oauth_entity_profile={profile_sys_id}^oauth_entity_scope={scope_sys_id}",
                "sysparm_limit": 1
            }
        )
        
        if response.status_code == 200 and response.json().get("result", []):
            print(f"  Profile already has '{scope_name}' scope assigned")
            return True
        
        # Step 4: Create the m2m relationship
        response = requests.post(
            m2m_endpoint,
            auth=self.auth,
            headers=self.headers,
            json={
                "oauth_entity_profile": profile_sys_id,
                "oauth_entity_scope": scope_sys_id
            }
        )

        print(f"Created m2m relationship: {response.json()}")

        if response.status_code == 201:
            m2m_sys_id = response.json()["result"]["sys_id"]
            self.created_resources.append(("oauth_entity_profile_scope", m2m_sys_id))
            print(f"  Assigned '{scope_name}' scope to profile: {m2m_sys_id}")
            return True
        else:
            print(f"  Failed to assign scope: {response.status_code} - {response.text}")
            return False

    def create_oauth_application(
        self,
        certificate_sys_id: str,
        service_account_username: str = "aws_integration",
        keystore_password: str = None,
    ) -> Dict[str, str]:
        """Create OAuth JWT API endpoint for external clients in ServiceNow.
        
        In ServiceNow Zurich, the oauth_jwt table extends oauth_entity. When creating
        a JWT API endpoint, we create an oauth_jwt record directly which includes
        all the oauth_entity fields plus JWT-specific configuration.
        
        The key insight is that ServiceNow requires client_secret in the token request
        even for JWT Bearer flow, so we must set and return a known client_secret.
        
        Args:
            certificate_sys_id: sys_id of the uploaded certificate (PEM)
            service_account_username: Username for JWT sub claim lookup
            keystore_password: Not used for PEM certificates
        
        Returns:
            Dict with client_id, client_secret, oauth_jwt_sys_id, and kid
        """
        client_id = f"aws-sir-{uuid.uuid4().hex[:8]}"
        client_secret = uuid.uuid4().hex
        kid = client_id  # Use client_id as kid for simplicity
        app_name = f"AWS Security IR JWT App {uuid.uuid4().hex[:8]}"
        
        # Step 1: Create oauth_jwt record (which extends oauth_entity)
        # This creates both the OAuth application and JWT configuration in one record
        print('Creating oauth_jwt record (extends oauth_entity)...')
        oauth_jwt_endpoint = f"{self.url}/api/now/table/oauth_jwt"
        oauth_jwt_payload = {
            # oauth_entity fields
            "name": app_name,
            "client_id": client_id,
            "client_secret": client_secret,
            "active": "true",
            "access_token_lifespan": "3600",
            "refresh_token_lifespan": "8640000",
            # oauth_jwt specific fields
            # IMPORTANT: ServiceNow defaults sub_claim to "sys_id" and this cannot be reliably
            # changed via API. Therefore, we must:
            # 1. Set user_field to "sys_id" so ServiceNow looks up users by sys_id
            # 2. Put the user's sys_id (not username) in the JWT sub claim
            "user_field": "sys_id",  # Look up user by sys_id field (matches sub_claim default)
            "sub_claim": "sys_id",  # JWT sub claim contains sys_id (ServiceNow default)
            "clock_skew": "300",  # 5 minutes clock skew tolerance
            "enable_jti_verification": "true",  # Enable JTI verification (per documentation)
            "jti_claim": "jti",  # JTI claim field name (per documentation)
            "jwks_cache_lifespan": "720",  # JWKS cache lifespan (per documentation)
            "inbound_grant_type": "jwt",  # Accept JWT bearer tokens
        }
        
        response = requests.post(
            oauth_jwt_endpoint, auth=self.auth, headers=self.headers, json=oauth_jwt_payload
        )
        
        if response.status_code != 201:
            print(f"oauth_jwt creation failed: {response.status_code} - {response.text}")
            response.raise_for_status()
        
        oauth_jwt_sys_id = response.json()["result"]["sys_id"]
        self.created_resources.append(("oauth_jwt", oauth_jwt_sys_id))
        print(f"Created oauth_jwt with sys_id: {oauth_jwt_sys_id}, client_id: {client_id}")
        
        # Step 2: Create jwt_verifier_map to link oauth_jwt to certificate
        print('Creating jwt_verifier_map...')
        jwt_verifier_endpoint = f"{self.url}/api/now/table/jwt_verifier_map"
        jwt_verifier_payload = {
            "name": f"AWS SIR Verifier {uuid.uuid4().hex[:8]}",
            "oauth_jwt": oauth_jwt_sys_id,
            "sys_certificate": certificate_sys_id,
            "kid": kid,  # Key ID must match the 'kid' in JWT header
        }
        
        response = requests.post(
            jwt_verifier_endpoint, auth=self.auth, headers=self.headers, json=jwt_verifier_payload
        )
        
        if response.status_code == 201:
            jwt_verifier_sys_id = response.json()["result"]["sys_id"]
            self.created_resources.append(("jwt_verifier_map", jwt_verifier_sys_id))
            print(f"Created jwt_verifier_map with sys_id: {jwt_verifier_sys_id}, kid: {kid}")
        else:
            print(f"jwt_verifier_map creation failed: {response.status_code} - {response.text}")
            response.raise_for_status()
        
        # Note: For inbound JWT bearer grants, the 'useraccount' scope is automatic.
        # ServiceNow returns scope=useraccount in the token response, granting the
        # access token the same rights as the user identified by the JWT sub claim.
        
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "oauth_jwt_sys_id": oauth_jwt_sys_id,
            "kid": kid,
        }

    def verify_business_rule(self, business_rule_name: str) -> Dict[str, Any]:
        """Verify that a business rule exists and is active.
        
        Args:
            business_rule_name: Name of the business rule to verify
            
        Returns:
            Dict with business rule details or None if not found
        """
        endpoint = f"{self.url}/api/now/table/sys_script"
        response = requests.get(
            endpoint,
            params={"sysparm_query": f"name={business_rule_name}", "sysparm_fields": "sys_id,name,active,when,collection,script"},
            auth=self.auth,
            headers=self.headers
        )
        
        results = response.json().get("result", [])
        if not results:
            return None
        
        rule = results[0]
        return {
            "sys_id": rule.get("sys_id"),
            "name": rule.get("name"),
            "active": rule.get("active") == "true",
            "when": rule.get("when"),
            "collection": rule.get("collection"),
            "script_length": len(rule.get("script", "")),
        }

    def cleanup(self):
        """Clean up all created resources from ServiceNow."""
        print('Cleaning up all ServiceNow Resources')
        for table, sys_id in reversed(self.created_resources):
            try:
                endpoint = f"{self.url}/api/now/table/{table}/{sys_id}"
                requests.delete(endpoint, auth=self.auth, headers=self.headers)
                print(f"Deleted {table}/{sys_id}")
            except Exception as e:
                print(f"Warning: Failed to delete {table}/{sys_id}: {e}")


class JWTBearerAuth:
    """JWT Bearer authentication handler for ServiceNow OAuth.
    
    This class extends requests.auth.AuthBase to provide JWT Bearer token
    authentication compatible with pysnc's ServiceNowClient.
    """
    
    def __init__(self, token: str):
        self.token = token
    
    def __call__(self, request):
        request.headers['Authorization'] = f"Bearer {self.token}"
        return request


class ServiceNowClient:
    """Client for interacting with ServiceNow using pysnc."""

    def __init__(self, url: str, username: str, password: str, integration_module: str = "itsm"):
        from pysnc import ServiceNowClient as SnowClient
        
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.table = "incident" if integration_module == "itsm" else "sn_si_incident"
        self.client = SnowClient(self.url, (username, password)) # Usage of basic auth is to help developers easily test -- basic auth is not preferred in production usecases.
        self.auth = (username, password)
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self._oauth_token = None  # For JWT OAuth clients

    @classmethod
    def from_jwt_oauth(
        cls,
        url: str,
        client_id: str,
        client_secret: str,
        user_sys_id: str,
        private_key: str,
        integration_module: str = "itsm"
    ) -> "ServiceNowClient":
        """Create a ServiceNowClient using JWT OAuth authentication.
        
        This factory method creates a client that authenticates as the specified
        user using JWT OAuth, which is the same authentication method used by
        the Lambda functions in production.
        
        Args:
            url: ServiceNow instance URL
            client_id: OAuth client ID
            client_secret: OAuth client secret
            user_sys_id: ServiceNow user sys_id (32-character GUID)
            private_key: PEM-encoded private key for JWT signing
            integration_module: 'itsm' or 'ir'
            
        Returns:
            ServiceNowClient configured with JWT OAuth authentication
        """
        from pysnc import ServiceNowClient as SnowClient
        from requests.auth import AuthBase
        import jwt as pyjwt
        
        url = url.rstrip("/")
        
        # Create JWT assertion
        payload = {
            "iss": client_id,
            "sub": user_sys_id,  # Must be the user's sys_id, not username
            "aud": client_id,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "jti": str(uuid.uuid4())
        }
        
        encoded_jwt = pyjwt.encode(payload, private_key, algorithm="RS256")
        
        # Exchange JWT for OAuth token
        token_url = f"{url}/oauth_token.do"
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': encoded_jwt,
            'client_id': client_id,
            'client_secret': client_secret
        }
        
        response = requests.post(token_url, headers=headers, data=data)
        if response.status_code != 200:
            raise Exception(f"Failed to get OAuth token: {response.status_code} - {response.text}")
        
        token_data = response.json()
        oauth_token = token_data['access_token']
        
        # Create a pre-configured requests session with the OAuth token
        # pysnc accepts a requests.Session object directly
        session = requests.Session()
        session.headers.update({
            'Authorization': f'Bearer {oauth_token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Create instance with OAuth authentication using the session
        instance = cls.__new__(cls)
        instance.url = url
        instance.username = user_sys_id
        instance.password = None  # No password for OAuth
        instance.table = "incident" if integration_module == "itsm" else "sn_si_incident"
        instance.client = SnowClient(url, session)  # Pass session directly
        instance._oauth_token = oauth_token
        instance.auth = None  # No basic auth
        instance.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {oauth_token}"
        }
        
        return instance

    @classmethod
    def from_ssm_parameters(
        cls,
        url: str,
        integration_module: str = "itsm",
        aws_profile: str = None
    ) -> "ServiceNowClient":
        """Create a ServiceNowClient using JWT OAuth credentials from SSM Parameter Store.
        
        This factory method retrieves OAuth credentials from AWS SSM Parameter Store
        and creates a client that authenticates as the aws_integration user.
        
        Args:
            url: ServiceNow instance URL
            integration_module: 'itsm' or 'ir'
            aws_profile: Optional AWS profile name to use
            
        Returns:
            ServiceNowClient configured with JWT OAuth authentication
        """
        # Create boto3 session with optional profile
        if aws_profile:
            session = boto3.Session(profile_name=aws_profile)
        else:
            session = boto3.Session()
        
        # Use the default region from environment or session
        region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        
        ssm_client = session.client("ssm", region_name=region)
        secrets_client = session.client("secretsmanager", region_name=region)
        s3_resource = session.resource("s3", region_name=region)
        
        def get_param(name: str) -> str:
            response = ssm_client.get_parameter(Name=name, WithDecryption=True)
            return response["Parameter"]["Value"]
        
        def get_secret(arn: str) -> str:
            response = secrets_client.get_secret_value(SecretId=arn)
            return response["SecretString"]
        
        # Get OAuth parameters
        client_id = get_param("/SecurityIncidentResponse/serviceNowClientId")
        client_secret_arn = get_param("/SecurityIncidentResponse/serviceNowClientSecretArn")
        client_secret = get_secret(client_secret_arn)
        user_sys_id = get_param("/SecurityIncidentResponse/serviceNowUserId")
        bucket = get_param("/SecurityIncidentResponse/privateKeyAssetBucket")
        key = get_param("/SecurityIncidentResponse/privateKeyAssetKey")
        
        # Get private key from S3
        response = s3_resource.Object(bucket, key).get()
        private_key = response['Body'].read().decode('utf-8')
        response['Body'].close()
        
        print(f"Creating JWT OAuth client for user sys_id '{user_sys_id}' with client_id '{client_id}'")
        
        return cls.from_jwt_oauth(
            url=url,
            client_id=client_id,
            client_secret=client_secret,
            user_sys_id=user_sys_id,
            private_key=private_key,
            integration_module=integration_module
        )

    def verify_table_permissions(self, table_name: str = None) -> Dict[str, bool]:
        """Verify the user has read and write permissions on the incident table.
        
        Args:
            table_name: Table to check permissions for (defaults to self.table)
            
        Returns:
            Dict with 'can_read' and 'can_write' boolean flags
        """
        if table_name is None:
            table_name = self.table
            
        print(f"Verifying permissions for user '{self.username}' on table '{table_name}'...")
        
        permissions = {"can_read": False, "can_write": False}
        
        # Determine auth method - use OAuth headers if available, otherwise basic auth
        if self._oauth_token:
            auth = None
            headers = self.headers  # Already includes Authorization header
        else:
            auth = self.auth
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
        
        # Test read permission by querying the table
        try:
            endpoint = f"{self.url}/api/now/table/{table_name}"
            response = requests.get(
                endpoint,
                auth=auth,
                headers=headers,
                params={"sysparm_limit": 1}
            )
            if response.status_code == 200:
                permissions["can_read"] = True
                print(f"  ✓ User has READ permission on {table_name}")
            else:
                print(f"  ✗ User lacks READ permission on {table_name}: {response.status_code}")
        except Exception as e:
            print(f"  ✗ Error checking READ permission: {e}")
        
        # Test write permission by attempting to create a test record
        try:
            endpoint = f"{self.url}/api/now/table/{table_name}"
            test_payload = {
                "short_description": "Permission test - will be deleted",
                "description": "Testing write permissions",
            }
            response = requests.post(
                endpoint,
                auth=auth,
                headers=headers,
                json=test_payload
            )
            if response.status_code in [200, 201]:
                permissions["can_write"] = True
                print(f"  ✓ User has WRITE permission on {table_name}")
                # Clean up test record
                test_sys_id = response.json()["result"]["sys_id"]
                requests.delete(
                    f"{endpoint}/{test_sys_id}",
                    auth=auth,
                    headers=headers
                )
            else:
                print(f"  ✗ User lacks WRITE permission on {table_name}: {response.status_code}")
        except Exception as e:
            print(f"  ✗ Error checking WRITE permission: {e}")
        
        return permissions

    def create_incident(self, short_description: str, description: str) -> Dict[str, Any]:
        """Create an incident in ServiceNow."""
        gr = self.client.GlideRecord(self.table)
        gr.initialize()
        gr.short_description = short_description
        gr.description = description
        gr.impact = "2"
        gr.urgency = "2"
        
        sys_id = gr.insert()
        if not sys_id:
            raise Exception("Failed to create incident in ServiceNow")
        
        return gr.serialize()

    def get_incident(self, incident_number: str) -> Optional[Dict[str, Any]]:
        """Get incident by number."""
        gr = self.client.GlideRecord(self.table)
        gr.add_query("number", incident_number)
        gr.query()
        
        if gr.next():
            return gr.serialize()
        return None

    def get_incident_by_description(self, description_contains: str) -> Optional[Dict[str, Any]]:
        """Find incident by short_description content (title field used by integration)."""
        gr = self.client.GlideRecord(self.table)
        gr.add_query("short_description", "LIKE", description_contains)
        gr.query()
        
        if gr.next():
            return gr.serialize()
        return None

    def delete_incident(self, sys_id: str):
        """Delete an incident by sys_id."""
        gr = self.client.GlideRecord(self.table)
        if gr.get(sys_id):
            gr.delete()


class SecurityIRClient:
    """Client for interacting with AWS Security Incident Response."""

    def __init__(self):
        self.client = boto3.client("security-ir")
        self.account_id = boto3.client("sts").get_caller_identity()["Account"]
        self.region = boto3.session.Session().region_name or "us-east-1"

    def create_case(self, title: str, description: str) -> CreateCaseResponseTypeDef:
        """Create a self-managed Security IR case."""
        response = self.client.create_case(
            title=title,
            description=description,
            resolverType="Self",
            engagementType="Investigation",
            reportedIncidentStartDate=datetime.now(timezone.utc),
            impactedAccounts=[self.account_id],
            impactedAwsRegions=[{"region": self.region}],
            impactedServices=["Amazon EC2"],  # Required field
            threatActorIpAddresses=[{"ipAddress": "192.0.2.1", "userAgent": "test-agent"}],
            watchers=[],  # Empty list of watchers
        )
        return response

    def get_case(self, case_id: str) -> GetCaseResponseTypeDef | None:
        """Get case by ID."""
        try:
            response = self.client.get_case(caseId=case_id)
            return response
        except self.client.exceptions.ResourceNotFoundException:
            return None

    def list_cases(self) -> list:
        """List all cases."""
        response = self.client.list_cases()
        return response.get("items", [])

    def close_case(self, case_id: str):
        """Close a Security IR case."""
        try:
            self.client.close_case(caseId=case_id)
        except Exception as e:
            print(f"Warning: Failed to close case {case_id}: {e}")


class CDKDeployer:
    """Deploy and destroy CDK stacks."""

    def __init__(self, project_root: Path):
        self.project_root = project_root

        # Configure retry with adaptive mode for throttling handling
        retry_config = Config(
            retries={
                'total_max_attempts': 10,
                'mode': 'adaptive'
            }
        )

        # Boto Clients
        self.s3_client = boto3.client('s3')
        self.lambda_client = boto3.client('lambda')
        self.events_client = boto3.client('events')
        self.logs_client = boto3.client('logs', config=retry_config)

        # Internal Clients
        self.cloudformation_client = CloudFormationClient()

        # Deployment Target Metadata
        self.__is_deployed = self.cloudformation_client.is_stack_deployed(SERVICE_NOW_STACK_NAME)
        account = boto3.client('sts').get_caller_identity()['Account']
        self.bucket_name = f"service-now-key-{account}"

    def wait_for_stabilization(self) -> None:
        if not self.cloudformation_client.is_stack_stabilized(SERVICE_NOW_STACK_NAME):
            raise Exception(f"Stack {SERVICE_NOW_STACK_NAME} could not stabilize")

    def get_resource_prefix(self) -> Optional[str]:
        """Get the SERVICE_NOW_RESOURCE_PREFIX from the deployed stack.
        
        This is the API Gateway REST API ID used as a prefix for all ServiceNow resources.
        
        Returns:
            The resource prefix (API Gateway ID) or None if not found
        """
        try:
            cfn = boto3.client('cloudformation')
            paginator = cfn.get_paginator('list_stack_resources')
            
            for page in paginator.paginate(StackName=SERVICE_NOW_STACK_NAME):
                for resource in page['StackResourceSummaries']:
                    # Find the ServiceNow API Gateway
                    if 'ServiceNowWebhookApi' in resource['LogicalResourceId'] and resource['ResourceType'] == 'AWS::ApiGateway::RestApi':
                        return resource['PhysicalResourceId']
            
            print("Warning: Could not find API Gateway resource in stack")
            return None
        except Exception as e:
            print(f"Error getting resource prefix: {e}")
            return None

    def get_webhook_url(self) -> Optional[str]:
        """Get the webhook URL from CloudFormation stack outputs."""
        try:
            cfn = boto3.client('cloudformation')
            response = cfn.describe_stacks(StackName=SERVICE_NOW_STACK_NAME)
            outputs = response['Stacks'][0].get('Outputs', [])
            for output in outputs:
                if 'WebhookUrl' in output['OutputKey']:
                    return output['OutputValue']
        except Exception as e:
            print(f"Error getting webhook URL: {e}")
        return None

    def get_api_auth_token(self) -> Optional[str]:
        """Get the API auth token from Secrets Manager.
        
        Gets the secret ARN from the CloudFormation stack resources to ensure
        we get the correct secret (not a stale one from a previous deployment).
        """
        try:
            # Get the secret ARN from the stack resources
            cfn = boto3.client('cloudformation')
            paginator = cfn.get_paginator('list_stack_resources')
            secret_arn = None
            
            for page in paginator.paginate(StackName=SERVICE_NOW_STACK_NAME):
                for resource in page['StackResourceSummaries']:
                    # Look for the ApiAuthSecret resource (not the policy or rotation schedule)
                    if resource['LogicalResourceId'] == 'ApiAuthSecret8046CF97':
                        secret_arn = resource['PhysicalResourceId']
                        break
                if secret_arn:
                    break
            
            if not secret_arn:
                print("Error: ApiAuthSecret not found in stack resources")
                return None
            
            print(f"Using API auth secret: {secret_arn}")
            secrets = boto3.client('secretsmanager')
            secret_response = secrets.get_secret_value(SecretId=secret_arn)
            secret_dict = json.loads(secret_response['SecretString'])
            return secret_dict.get('token')
        except Exception as e:
            print(f"Error getting API auth token: {e}")
        return None

    @property
    def is_deployed(self) -> bool:
        """Check if the stack is deployed."""
        return self.__is_deployed

    def _create_s3_bucket_and_upload_key(self, private_key_path: str) -> str:
        """Create S3 bucket and upload private key.
        
        Returns:
            Bucket name
        """

        from botocore.exceptions import ClientError

        region = boto3.Session().region_name or 'us-east-1'

        max_retries = 5
        for attempt in range(max_retries):
            try:
                if region == 'us-east-1':
                    self.s3_client.create_bucket(Bucket=self.bucket_name)
                else:
                    self.s3_client.create_bucket(
                        Bucket=self.bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                print(f"Created S3 bucket: {self.bucket_name}")
                break
            except (self.s3_client.exceptions.BucketAlreadyOwnedByYou, 
                    self.s3_client.exceptions.BucketAlreadyExists):
                print(f"Using existing S3 bucket: {self.bucket_name}")
                break
            except ClientError as e:
                if e.response['Error']['Code'] == 'OperationAborted' and attempt < max_retries - 1:
                    wait_time = 10 * (attempt + 1)
                    print(f"Bucket operation in progress, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})...")
                    time.sleep(wait_time)
                else:
                    raise
        
        # Enable encryption
        try:
            self.s3_client.put_bucket_encryption(
                Bucket=self.bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'aws:kms',
                            'KMSMasterKeyID': 'alias/aws/s3'
                        }
                    }]
                }
            )
        except Exception:
            pass  # Encryption may already be enabled
        
        # Upload private key
        self.s3_client.upload_file(private_key_path, self.bucket_name, 'private.key')
        print(f"Uploaded private key to s3://{self.bucket_name}/private.key")
        
        return self.bucket_name

    def deploy(
        self,
        instance_id: str,
        client_id: str,
        client_secret: str,
        user_sys_id: str,
        private_key_path: str,
        integration_module: str,
    ) -> bool:
        """Deploy the ServiceNow integration stack."""
        # First, create S3 bucket and upload private key
        bucket_name = self._create_s3_bucket_and_upload_key(private_key_path)
        
        # Deploy using CDK directly with --require-approval never
        # Use --output to avoid conflicts with other CDK processes
        cmd = [
            "npx", "cdk", "deploy",
            "--app", "python3 app_service_now.py",
            "--output", "cdk.out.acceptance-test",
            "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
            SERVICE_NOW_STACK_NAME,
            "--require-approval", "never",
            "--parameters", f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel=debug",
            "--parameters", f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:integrationModule={integration_module}",
            "--parameters", f"{SERVICE_NOW_STACK_NAME}:serviceNowInstanceId={instance_id}",
            "--parameters", f"{SERVICE_NOW_STACK_NAME}:serviceNowClientId={client_id}",
            "--parameters", f"{SERVICE_NOW_STACK_NAME}:serviceNowClientSecret={client_secret}",
            "--parameters", f"{SERVICE_NOW_STACK_NAME}:serviceNowUserId={user_sys_id}",
            "--parameters", f"{SERVICE_NOW_STACK_NAME}:privateKeyBucket={bucket_name}",
            "--parameters", f"{SERVICE_NOW_STACK_NAME}:integrationModule={integration_module}",
        ]
        
        # Set environment to auto-accept npx prompts and silence node warnings
        env = os.environ.copy()
        env["npm_config_yes"] = "true"
        env["JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION"] = "1"
        
        print(f"Running CDK deploy command...")
        result = subprocess.run(
            cmd,
            cwd=self.project_root,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minute timeout for deployment
            env=env,
        )
        
        if result.returncode != 0:
            print(f"Deployment failed (exit code {result.returncode}):")
            print(f"STDOUT:\n{result.stdout}")
            print(f"STDERR:\n{result.stderr}")
            return False
        
        print(f"Deployment successful:\n{result.stdout}")
        self.__is_deployed = True
        return True

    def destroy(self) -> bool:
        """Destroy the ServiceNow integration stack."""
        env = os.environ.copy()
        env["npm_config_yes"] = "true"
        env["JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION"] = "1"
        
        cmd = [
            "npx", "cdk", "destroy",
            "--app", "python3 app_service_now.py",
            "--output", "cdk.out.acceptance-test",
            "--all",
            "--force",
        ]
        
        result = subprocess.run(
            cmd,
            cwd=self.project_root,
            capture_output=True,
            text=True,
            timeout=1800,
            env=env,
        )
        
        if result.returncode != 0:
            print(f"Destroy failed:\nstdout: {result.stdout}\nstderr: {result.stderr}")
            return False
        
        print(f"Destroy successful:\n{result.stdout}")
        
        # Clean up S3 bucket
        if self.bucket_name:
            try:
                # Delete all object versions first (for versioned buckets)
                paginator = self.s3_client.get_paginator('list_object_versions')
                for page in paginator.paginate(Bucket=self.bucket_name):
                    # Delete versions
                    if 'Versions' in page:
                        for version in page['Versions']:
                            self.s3_client.delete_object(
                                Bucket=self.bucket_name,
                                Key=version['Key'],
                                VersionId=version['VersionId']
                            )
                    # Delete delete markers
                    if 'DeleteMarkers' in page:
                        for marker in page['DeleteMarkers']:
                            self.s3_client.delete_object(
                                Bucket=self.bucket_name,
                                Key=marker['Key'],
                                VersionId=marker['VersionId']
                            )
                # Delete bucket
                self.s3_client.delete_bucket(Bucket=self.bucket_name)
                print(f"Deleted S3 bucket: {self.bucket_name}")
            except Exception as e:
                print(f"Warning: Failed to delete S3 bucket {self.bucket_name}: {e}")
        self.__is_deployed = False
        return True

    def get_function_arn_from_purpose_tag(self, tag_value: str) -> str | None:
        # Find the poller Lambda function
        paginator = self.lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page['Functions']:
                tags = self.lambda_client.list_tags(Resource=function['FunctionArn']).get('Tags', {})
                if tags.get('purpose', '') == tag_value:
                    return function['FunctionName']
        return None

    def get_rule_arn_from_purpose_tag(self, tag_value: str) -> str | None:
        paginator = self.events_client.get_paginator('list_rules')
        for page in paginator.paginate():
            for rule in page['Rules']:
                tags = self.events_client.list_tags_for_resource(ResourceARN=rule['Arn']).get('Tags', {})
                for tag in tags:
                    if tag.get('Key', '') == 'purpose' and tag.get('Value','') == tag_value:
                        return rule['Arn']
        return None

    def get_log_group_from_purpose_tag(self, tag_value) -> str | None:
        paginator = self.logs_client.get_paginator('describe_log_groups')
        for page in paginator.paginate(logGroupNamePrefix='AwsSecurityIncidentRespon'):
            for log_group in page['logGroups']:
                tags = self.logs_client.list_tags_log_group(logGroupName=log_group['logGroupName']).get('tags', {})
                if tags.get('purpose', '') == tag_value:
                    return log_group['logGroupName']
        return None

    def invoke_poller_lambda(self):
        """Manually invoke the poller Lambda to trigger sync."""
        poller_function = self.get_function_arn_from_purpose_tag('security-ir-poller')
        assert poller_function is not None and len(poller_function) > 0, "Security IR poller Lambda function not found!"

        rule_arn = self.get_rule_arn_from_purpose_tag('security-ir-poller-rule')
        assert rule_arn is not None, "Security IR poller EventBridge rule not found!"

        if not rule_arn:
            print("WARNING: Poller rule not found!")
            return

        # Invoke the poller Lambda with a mock EventBridge event
        print(f"Manually invoking poller Lambda: {poller_function}")
        try:
            response = self.lambda_client.invoke(
                FunctionName=poller_function,
                InvocationType='RequestResponse',
                Payload=json.dumps({
                    "resources": [rule_arn],
                    "source": "aws.events",
                    "detail-type": "Scheduled Event"
                })
            )
            payload = json.loads(response['Payload'].read())
            print(f"Poller Lambda response: {payload}")

            # Check for errors
            if 'FunctionError' in response:
                print(f"Poller Lambda error: {response['FunctionError']}")
        except Exception as e:
            print(f"Error invoking poller Lambda: {e}")

    def check_lambda_logs(self, tag, minutes):
        """Check CloudWatch logs for a Lambda function."""
        log_group = self.get_log_group_from_purpose_tag(tag)
        assert log_group is not None, f"Log group with purpose tag '{tag}' not found!"

        try:
            # Get recent log events
            end_time = int(time.time() * 1000)
            start_time = end_time - (minutes * 60 * 1000)


            response = self.logs_client.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                limit=50
            )

            events = response.get('events', [])
            if events:
                print(f"Found {len(events)} log events:")
                for event in events[-20:]:  # Show last 20 events
                    print(f"  {event['message'][:200]}")
            else:
                print("No recent log events found")
        except self.logs_client.exceptions.ResourceNotFoundException:
            print(f"Log group {log_group} not found")
        except Exception as e:
            print(f"Error checking logs: {e}")


@pytest.fixture(scope="module")
def deployed_integration(service_now_config, tmp_path_factory):
    """Deploy the integration and yield config, then tear down.
    
    NOTE: The setup handler Lambda cannot create webhook resources (business rules,
    REST messages, discovery credentials) automatically because:
    
    1. ServiceNow's out-of-box ACLs on sys_rest_message, sys_script, etc. have
       admin_overrides=true with NO specific roles configured, meaning only users
       with the 'admin' role can write to these tables.
    
    2. ServiceNow blocks JWT bearer grants to users with the 'admin' role for
       security reasons, so the setup handler Lambda (using JWT OAuth) cannot
       authenticate as admin.
    
    3. Creating custom ACLs to grant permissions requires the 'security_admin' role
       with elevated privileges, which cannot be elevated via REST API - only
       through the ServiceNow UI.
    
    As a workaround, this test creates the webhook resources directly using admin
    basic auth credentials after the CDK stack is deployed.
    """
    project_root = Path(__file__).parent.parent.parent.parent
    deployer = CDKDeployer(project_root)
    if deployer.is_deployed:
        deployer.destroy()

    temp_dir = tmp_path_factory.mktemp("keys")

    # Generate RSA key pair (PEM format - works better with ServiceNow API)
    print("Generating RSA key pair...")
    private_key_pem, certificate_pem = KeyGenerator.generate_key_pair()

    # Save private key to temp file for Lambda to use
    private_key_path = temp_dir / "private.key"
    private_key_path.write_bytes(private_key_pem)

    # Set up OAuth in ServiceNow
    print("Setting up OAuth in ServiceNow...")
    oauth_setup = ServiceNowOAuthSetup(
        service_now_config["url"],
        service_now_config["username"],
        service_now_config["password"],
    )

    try:
        # Create a service account user for JWT OAuth authentication
        # ServiceNow doesn't allow JWT bearer tokens to authenticate as 'admin'
        # Using 'aws_integration' as recommended in SERVICE_NOW.md documentation
        print("Creating service account user for JWT OAuth...")
        service_account_info = oauth_setup.create_service_account_user("aws_integration")
        if not service_account_info:
            raise Exception("Failed to create service account user")
        
        # Extract username and sys_id from the returned dict
        # The sys_id is required for JWT OAuth because ServiceNow's oauth_jwt.sub_claim
        # defaults to 'sys_id' and cannot be changed via API
        service_account_username = service_account_info["user_name"]
        service_account_sys_id = service_account_info["sys_id"]
        print(f"Service account: username='{service_account_username}', sys_id='{service_account_sys_id}'")

        # Upload PEM certificate to ServiceNow
        certificate_sys_id = oauth_setup.upload_certificate(certificate_pem)
        
        # Create OAuth application (no keystore_password for PEM)
        oauth_config = oauth_setup.create_oauth_application(
            certificate_sys_id,
            service_account_username,
        )
    except Exception as e:
        print(f"OAuth setup failed: {e}")
        oauth_setup.cleanup()
        pytest.fail(f"Failed to set up OAuth in ServiceNow: {e}")

    # Deploy CDK stack with service account user's sys_id (not username)
    # The Setup Lambda expects the sys_id because ServiceNow's oauth_jwt.sub_claim
    # defaults to 'sys_id' and cannot be changed via API
    print("Deploying CDK stack...")

    deploy_success = deployer.deploy(
        instance_id=service_now_config["instance_id"],
        client_id=oauth_config["client_id"],
        client_secret=oauth_config["client_secret"],
        user_sys_id=service_account_sys_id,  # Use sys_id, not username - required for JWT OAuth
        private_key_path=str(private_key_path),
        integration_module=service_now_config["integration_module"],
    )

    if not deploy_success:
        oauth_setup.cleanup()
        pytest.fail("Failed to deploy CDK stack")

    # Wait for stack to stabilize
    print("Waiting for CloudFormation stack to stabilize...")

    deployer.wait_for_stabilization()

    # The Setup Lambda now successfully creates ServiceNow webhook resources
    # (business rule, REST message, discovery credential) using JWT OAuth.
    # We just need to verify the resources exist and update the credential/REST message
    # with the current deployment's webhook URL and API key.
    print("Creating ServiceNow webhook resources...")
    webhook_url = deployer.get_webhook_url()
    api_auth_token = deployer.get_api_auth_token()
    
    if not webhook_url or not api_auth_token:
        oauth_setup.cleanup()
        pytest.fail("Failed to get webhook URL or API auth token from deployed stack")
    
    table = "incident" if service_now_config["integration_module"] == "itsm" else "sn_si_incident"

    yield {
        **service_now_config,
        "project_root": project_root,
        "deployer": deployer,
    }

    if 'SKIP_DESTROY' not in os.environ:
        deployer.destroy()
        oauth_setup.cleanup()
    else: 
        print('Skipping Destroy for debugging')
    


class TestSecurityIRToServiceNow:
    """Test AWS Security IR case replication to ServiceNow."""
    def test_security_ir_case_replicates_to_service_now(self, deployed_integration):
        """
        Create a self-managed Security IR case and verify it replicates to ServiceNow.
        
        Flow:
        1. Create case in AWS Security Incident Response
        2. Wait for sync to occur
        3. Verify incident appears in ServiceNow with correct details
        """

        # Assume: CDK is Deployed
        deployer: CDKDeployer = deployed_integration['deployer']
        assert deployer.is_deployed, "CDK stack must be deployed first"

        test_id = uuid.uuid4().hex[:8]
        case_title = f"E2E Test Case - {test_id}"
        case_description = f"Acceptance test case created at {datetime.now(timezone.utc).isoformat()} - ID: {test_id}"
        
        sir_client = SecurityIRClient()
        snow_client = ServiceNowClient(
            deployed_integration["url"],
            deployed_integration["username"],
            deployed_integration["password"],
            deployed_integration["integration_module"],
        )
        
        created_case = None
        created_incident = None
        
        try:
            # Act: Create Security IR case
            print(f"Creating Security IR case: {case_title}")
            response = sir_client.create_case(case_title, case_description)
            case_id = response["caseId"]
            created_case = case_id
            print(f"Created Security IR case: {case_id}")
            
            # Manually invoke the poller to trigger sync immediately
            print("Manually invoking poller Lambda...")
            deployer.invoke_poller_lambda()
            
            # Wait for sync and poll for ServiceNow incident
            print("Waiting for sync to ServiceNow...")
            incident = None
            start_time = time.time()
            poll_count = 0
            
            while time.time() - start_time < SYNC_TIMEOUT_SECONDS:
                poll_count += 1
                incident = snow_client.get_incident_by_description(test_id)
                if incident:
                    created_incident = incident["sys_id"]
                    break
                elapsed = int(time.time() - start_time)
                print(f"  Poll {poll_count}: No incident found yet ({elapsed}s elapsed)")
                
                # Invoke poller again every 60 seconds
                if poll_count % 6 == 0:
                    print("  Re-invoking poller Lambda...")
                    deployer.invoke_poller_lambda()
                    
                time.sleep(POLL_INTERVAL_SECONDS)
            
            # If sync failed, check logs for debugging
            if incident is None:
                print("\n=== DEBUGGING: Checking Lambda logs ===")
                deployer.check_lambda_logs('security-ir-poller-logs', minutes=10)
                deployer.check_lambda_logs("service-now-client-logs", minutes=10)
            
            # Assert
            assert incident is not None, (
                f"ServiceNow incident not found within {SYNC_TIMEOUT_SECONDS}s. "
                f"Expected incident with description containing: {test_id}"
            )
            
            assert case_title in incident.get("short_description", ""), (
                f"Incident title mismatch. Expected '{case_title}' in "
                f"'{incident.get('short_description')}'"
            )
            
            print(f"Successfully verified ServiceNow incident: {incident['number']}")
            
        finally:
            # Cleanup
            if created_case and 'SKIP_DESTROY' not in os.environ:
                print(f"Cleaning up Security IR case: {created_case}")
                sir_client.close_case(created_case)
            if created_incident and 'SKIP_DESTROY' not in os.environ:
                print(f"Cleaning up ServiceNow incident: {created_incident}")
                snow_client.delete_incident(created_incident)


class TestServiceNowToSecurityIR:
    """Test ServiceNow incident replication to AWS Security IR."""

    def test_business_rule_exists(self, deployed_integration):
        """
        Verify that the setup Lambda created the business rule successfully.
        
        This test ensures:
        1. Business rule exists in ServiceNow
        2. Business rule is active
        3. Business rule is configured correctly (async, correct table)
        """
        print("\n" + "="*80)
        print("Verifying ServiceNow Business Rule Setup")
        print("="*80)
        
        # Create admin client to query ServiceNow
        admin_client = ServiceNowOAuthSetup(
            deployed_integration["url"],
            deployed_integration["username"],
            deployed_integration["password"],
        )
        
        # Get the resource prefix from the deployed stack
        deployer: CDKDeployer = deployed_integration['deployer']
        resource_prefix = deployer.get_resource_prefix()
        
        if not resource_prefix:
            pytest.skip("Could not determine resource prefix from deployed stack")
        
        # Business rule name matches Lambda naming: {resource_prefix}-business-rule
        business_rule_name = f"{resource_prefix}-business-rule"
        
        print(f"\nChecking for business rule: {business_rule_name}")
        print(f"  (Resource prefix from stack: {resource_prefix})")
        rule_info = admin_client.verify_business_rule(business_rule_name)
        
        # Assert business rule exists
        assert rule_info is not None, (
            f"Business rule '{business_rule_name}' not found in ServiceNow. "
            f"The setup Lambda may have failed to create it."
        )
        
        print(f"✓ Business rule found:")
        print(f"  - sys_id: {rule_info['sys_id']}")
        print(f"  - Active: {rule_info['active']}")
        print(f"  - When: {rule_info['when']}")
        print(f"  - Collection: {rule_info['collection']}")
        print(f"  - Script length: {rule_info['script_length']} chars")
        
        # Assert business rule is active
        assert rule_info['active'], (
            f"Business rule '{business_rule_name}' exists but is NOT active. "
            f"Incidents will not trigger webhooks."
        )
        
        # Assert business rule is configured for 'after' execution
        # 'after' fires synchronously after the transaction commits
        assert rule_info['when'] == 'after', (
            f"Business rule 'when' is '{rule_info['when']}', expected 'after'. "
            f"The business rule should fire after the transaction commits."
        )
        
        # Assert business rule is on the correct table
        expected_table = "incident" if deployed_integration["integration_module"] == "itsm" else "sn_si_incident"
        assert rule_info['collection'] == expected_table, (
            f"Business rule is on table '{rule_info['collection']}', expected '{expected_table}'"
        )
        
        print(f"\n✓ Business rule is correctly configured and active")
        print("="*80 + "\n")

    def test_service_now_incident_replicates_to_security_ir(self, deployed_integration):
        """
        Create an incident in ServiceNow and verify it replicates to Security IR.
        
        Flow:
        1. Create incident in ServiceNow using integration user (aws_integration via JWT OAuth)
        2. Wait for sync to occur (via webhook -> EventBridge -> Security IR Client)
        3. Verify case appears in AWS Security Incident Response
        
        Note: The incident must be created by aws_integration user because ServiceNow
        has a custom ACL that restricts incident visibility to opened_by, caller_id,
        or watch_list members. Since the Lambda notification handler authenticates
        as aws_integration, it can only see incidents where aws_integration is one
        of these fields.
        """
        # Arrange
        test_id = uuid.uuid4().hex[:8]
        incident_title = f"E2E Test Incident - {test_id}"
        incident_description = f"Acceptance test incident created at {datetime.now(timezone.utc).isoformat()} - ID: {test_id}"
        
        sir_client = SecurityIRClient()
        
        # Create ServiceNow client using JWT OAuth as aws_integration user
        # This ensures the incident is created by the same user that will query it
        # (the Lambda notification handler also authenticates as aws_integration)
        print(f"Creating ServiceNow client with JWT OAuth as 'aws_integration'...")
        snow_client = ServiceNowClient.from_ssm_parameters(
            url=deployed_integration["url"],
            integration_module=deployed_integration["integration_module"],
        )
        
        # Also create admin client for cleanup (admin can delete any incident)
        admin_client = ServiceNowClient(
            deployed_integration["url"],
            deployed_integration["username"],  # admin
            deployed_integration["password"],
            deployed_integration["integration_module"],
        )
        
        # Verify permissions
        permissions = snow_client.verify_table_permissions()
        assert permissions["can_read"], "aws_integration must have READ permission on incident table"
        assert permissions["can_write"], "aws_integration must have WRITE permission on incident table"
        
        created_incident = None
        created_case_id = None
        
        try:
            # Act: Create ServiceNow incident as aws_integration user
            print(f"Creating ServiceNow incident as 'aws_integration': {incident_title}")
            incident = snow_client.create_incident(incident_title, incident_description)
            created_incident = incident["sys_id"]
            incident_number = incident["number"]
            print(f"Created ServiceNow incident: {incident_number} (sys_id: {created_incident})")
            
            # Verify aws_integration can read the incident it just created
            print(f"Verifying aws_integration can read incident {incident_number}...")
            read_back = snow_client.get_incident(incident_number)
            if read_back:
                print(f"  ✓ aws_integration can read incident {incident_number}")
            else:
                print(f"  ✗ aws_integration CANNOT read incident {incident_number}")
                raise Exception("aws_integration cannot read the incident it just created - ACL issue persists")
            
            # Wait for sync and poll for Security IR case
            print("Waiting for sync to Security IR...")
            found_case = None
            start_time = time.time()
            poll_count = 0
            
            while time.time() - start_time < SYNC_TIMEOUT_SECONDS:
                poll_count += 1
                cases = sir_client.list_cases()
                print(f"  Poll {poll_count}: Found {len(cases)} cases")
                for case in cases:
                    case_detail = sir_client.get_case(case["caseId"])
                    if case_detail and test_id in case_detail.get("title", ""):
                        found_case = case_detail
                        created_case_id = case["caseId"]
                        break
                if found_case:
                    break
                elapsed = int(time.time() - start_time)
                print(f"  Poll {poll_count}: No matching case found yet ({elapsed}s elapsed)")
                time.sleep(POLL_INTERVAL_SECONDS)
            
            # Assert
            assert found_case is not None, (
                f"Security IR case not found within {SYNC_TIMEOUT_SECONDS}s. "
                f"Expected case with title containing: {test_id}"
            )
            
            assert incident_title in found_case.get("title", ""), (
                f"Case title mismatch. Expected '{incident_title}' in "
                f"'{found_case.get('title')}'"
            )
            
            print(f"Successfully verified Security IR case: {created_case_id}")
            
        finally:
            # Cleanup - use admin client which can delete any incident
            if created_incident and 'SKIP_DESTROY' not in os.environ:
                print(f"Cleaning up ServiceNow incident: {created_incident}")
                admin_client.delete_incident(created_incident)
            if created_case_id and 'SKIP_DESTROY' not in os.environ:
                print(f"Cleaning up Security IR case: {created_case_id}")
                sir_client.close_case(created_case_id)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

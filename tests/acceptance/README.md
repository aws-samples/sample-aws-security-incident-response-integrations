# ServiceNow Acceptance Tests

End-to-end acceptance tests for ServiceNow integration with AWS Security Incident Response.

## Overview

These tests deploy the full ServiceNow integration stack, verify bidirectional synchronization, and tear down resources automatically.

## Prerequisites

- AWS credentials configured with permissions to deploy CDK stacks
- ServiceNow instance with admin access
- CDK bootstrapped in target AWS account/region
- Python virtual environment with dependencies installed
- `keytool` and `openssl` available (for JKS keystore generation)

## Execution

### Basic Usage

```bash
pytest tests/acceptance/test_service_now.py \
    --service-now-url=https://dev12345.service-now.com \
    --service-now-username=admin \
    --service-now-password=<password>
```

### With Integration Module

```bash
pytest tests/acceptance/test_service_now.py \
    --service-now-url=https://dev12345.service-now.com \
    --service-now-username=admin \
    --service-now-password=<password> \
    --integration-module=itsm
```

### Skip Cleanup (for debugging)

```bash
SKIP_DESTROY=1 pytest tests/acceptance/test_service_now.py \
    --service-now-url=https://dev12345.service-now.com \
    --service-now-username=admin \
    --service-now-password=<password>
```

## Parameters

### Required Command-Line Arguments

- `--service-now-url`: ServiceNow instance URL (e.g., https://dev12345.service-now.com)
- `--service-now-username`: ServiceNow admin username
- `--service-now-password`: ServiceNow admin password

### Optional Command-Line Arguments

- `--integration-module`: ServiceNow module to use (`itsm` or `ir`, default: `itsm`)

### Environment Variables

- `SKIP_DESTROY`: Set to any value to skip stack destruction after tests (useful for debugging)

## Test Flow

Before running individual tests, CDK stacks are deployed with OAuth configuration. Unless configured to skip cleanup, after all tests are run these stacks are cleaned up.

### Test 1: Security IR → ServiceNow

1. Create AWS Security IR case
2. Manually invoke poller Lambda
3. Verify incident created in ServiceNow
4. Cleanup resources

### Test 2: ServiceNow → Security IR

1. Create ServiceNow incident
2. Wait for webhook to trigger sync
3. Verify case created in AWS Security IR
4. Cleanup resources

## Configuration

- **Sync Timeout**: 180 seconds (3 minutes to allow for notification handler retries)
- **Poll Interval**: 15 seconds
- **Stack Name**: `AwsSecurityIncidentResponseServiceNowIntegrationStack`

### AWS Credentials

You can configure your AWS credentials via the standard [AWS CLI Environment Variables](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).
Examples of these environment variables are `AWS_PROFILE`, `AWS_REGION`, or `AWS_ACCESS_KEY_ID`.

## ServiceNow Setup

The tests automatically configure ServiceNow with:

### Service Account User

A service account user (`aws_integration`) is created with the following roles:

**ITSM Mode (incident table):**
- `itil` - Base ITIL role for incident read/write access

**IR Mode (sn_si_incident table):**
- `sn_si.analyst` - Security Incident operations
- `sn_si.basic` - Basic Security Incident access
- `sn_si.external` - External Security Incident access
- `sn_si.integration_user` - Integration user access
- `sn_si.manager` - Security Incident management
- `sn_si.read` - Security Incident read access

**Common roles (both modes):**
- `rest_api_explorer`, `web_service_admin` - REST/Web services access
- `business_rule_admin` - Business rule management
- `incident_manager` - Incident operations
- `snc_internal` - ServiceNow internal role
- `credential_admin` - Discovery credentials management

**Note**: The `admin` role is intentionally excluded because ServiceNow blocks JWT bearer grants to admin users.

### OAuth Configuration

- JKS keystore generated with RSA key pair
- X.509 certificate uploaded to ServiceNow
- OAuth JWT API endpoint created with JWT bearer grant type
- JWT verifier map linking OAuth entity to certificate

### Webhook Resources

The Setup Lambda automatically creates:
- Discovery credential storing API Gateway auth token
- Outbound REST Message pointing to webhook URL
- REST Message HTTP Method (POST function)
- REST Message Function Parameters
- Async Business Rule triggering on incident create/update
- Attachment Business Rule triggering on attachment changes

## Notes

- Tests automatically generate RSA key pairs for JWT OAuth using `keytool` and `openssl`
- The business rule uses `async` timing to fire after transaction commits
- A 3-second delay is added in the business rule to ensure transaction visibility
- All resources are cleaned up automatically unless `SKIP_DESTROY` is set

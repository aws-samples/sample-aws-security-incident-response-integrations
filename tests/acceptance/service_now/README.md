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

### AWS Authentication

The acceptance tests use `boto3` to interact with AWS services (CloudFormation, Lambda, Security IR, SSM, etc.). Boto3 resolves credentials through the standard [AWS CLI credential chain](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-authentication.html), so any method supported by the AWS CLI will work.

#### Using a Named Profile

If you have profiles configured in `~/.aws/credentials` or `~/.aws/config`, set the `AWS_PROFILE` environment variable:

```bash
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1

pytest tests/acceptance/service_now/test_service_now.py \
    --service-now-url=https://dev12345.service-now.com \
    --service-now-username=admin \
    --service-now-password=<password>
```

#### Using IAM Access Keys

Export your access key and secret key directly:

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=<your-secret-key>
export AWS_REGION=us-east-1

pytest tests/acceptance/service_now/test_service_now.py \
    --service-now-url=https://dev12345.service-now.com \
    --service-now-username=admin \
    --service-now-password=<password>
```

If using temporary credentials (e.g., from `aws sts assume-role`), also set:

```bash
export AWS_SESSION_TOKEN=<your-session-token>
```

#### Using AWS IAM Identity Center (SSO)

If your organization uses IAM Identity Center, log in first and then set the profile:

```bash
aws sso login --profile my-sso-profile
export AWS_PROFILE=my-sso-profile
```

#### Verifying Your Credentials

Before running the tests, confirm that your credentials are valid and point to the correct account:

```bash
aws sts get-caller-identity
```

#### Required Permissions

The following IAM policy covers the permissions needed to run the acceptance tests. It includes CDK deployment, S3 key management, Lambda invocation, log inspection, and Security IR case lifecycle operations.

Replace `<account-id>` and `<region>` with your values before attaching the policy.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CDKDeployAndDestroy",
            "Effect": "Allow",
            "Action": [
                "cloudformation:CreateStack",
                "cloudformation:UpdateStack",
                "cloudformation:DeleteStack",
                "cloudformation:DescribeStacks",
                "cloudformation:DescribeStackEvents",
                "cloudformation:GetTemplate",
                "cloudformation:ListStackResources",
                "cloudformation:CreateChangeSet",
                "cloudformation:DescribeChangeSet",
                "cloudformation:ExecuteChangeSet",
                "cloudformation:DeleteChangeSet",
                "cloudformation:GetTemplateSummary"
            ],
            "Resource": [
                "arn:aws:cloudformation:<region>:<account-id>:stack/AwsSecurityIncidentResponseServiceNowIntegrationStack/*",
                "arn:aws:cloudformation:<region>:<account-id>:stack/AwsSecurityIncidentResponseSampleIntegrationsCommonStack/*",
                "arn:aws:cloudformation:<region>:<account-id>:stack/CDKToolkit/*"
            ]
        },
        {
            "Sid": "CDKStagingBucket",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::cdk-*-assets-<account-id>-<region>",
                "arn:aws:s3:::cdk-*-assets-<account-id>-<region>/*"
            ]
        },
        {
            "Sid": "PrivateKeyBucket",
            "Effect": "Allow",
            "Action": [
                "s3:CreateBucket",
                "s3:DeleteBucket",
                "s3:PutEncryptionConfiguration",
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:ListBucket",
                "s3:ListBucketVersions"
            ],
            "Resource": [
                "arn:aws:s3:::service-now-key-<account-id>",
                "arn:aws:s3:::service-now-key-<account-id>/*"
            ]
        },
        {
            "Sid": "LambdaInvokeAndList",
            "Effect": "Allow",
            "Action": [
                "lambda:InvokeFunction",
                "lambda:ListFunctions",
                "lambda:ListTags"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudWatchLogs",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:FilterLogEvents",
                "logs:ListTagsLogGroup"
            ],
            "Resource": "arn:aws:logs:<region>:<account-id>:log-group:AwsSecurityIncidentRespon*"
        },
        {
            "Sid": "EventBridge",
            "Effect": "Allow",
            "Action": [
                "events:ListRules",
                "events:ListTagsForResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "SSMParameterStore",
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:<region>:<account-id>:parameter/SecurityIncidentResponse/*"
        },
        {
            "Sid": "SecretsManager",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:<region>:<account-id>:secret:*"
        },
        {
            "Sid": "SecurityIncidentResponse",
            "Effect": "Allow",
            "Action": [
                "security-ir:CreateCase",
                "security-ir:GetCase",
                "security-ir:ListCases",
                "security-ir:CloseCase"
            ],
            "Resource": "*"
        },
        {
            "Sid": "STSIdentity",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CDKPassRoleForDeployment",
            "Effect": "Allow",
            "Action": [
                "iam:PassRole"
            ],
            "Resource": "arn:aws:iam::<account-id>:role/cdk-*"
        },
        {
            "Sid": "CDKBootstrapLookup",
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:<region>:<account-id>:parameter/cdk-bootstrap/*"
        }
    ]
}
```

> **Note:** CDK deployment also requires the CDK bootstrap roles (e.g., `cdk-<qualifier>-deploy-role-*`) to exist in the account. If you use a custom bootstrap policy, ensure the `iam:PassRole` resource ARN matches your role naming convention. See [CDK Bootstrapping Documentation](../../../documentation/CDK_BOOTSTRAP_POLICY.md) for details.

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

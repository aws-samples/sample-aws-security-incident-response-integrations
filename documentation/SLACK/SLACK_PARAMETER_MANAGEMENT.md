# Slack Parameter Management Guide

## Overview

The Slack integration for AWS Security Incident Response uses AWS Systems Manager (SSM) Parameter Store to securely manage Slack credentials and configuration. This guide covers parameter setup, validation, rotation, and security best practices.

## Architecture

### Parameter Storage

All Slack credentials are stored in SSM Parameter Store with the following characteristics:

- **Encryption**: Sensitive parameters (bot token, signing secret) use SecureString type with AWS KMS encryption
- **Access Control**: IAM policies restrict parameter access to specific Lambda functions
- **Audit Trail**: CloudTrail logs all parameter access and modifications
- **Tagging**: Parameters are tagged for management and rotation tracking

### Parameters

| Parameter Name | Type | Description | Format |
|---------------|------|-------------|--------|
| `/SecurityIncidentResponse/slackBotToken` | SecureString | Slack Bot User OAuth Token | `xoxb-XXXXXXXXX-XXXXXXXXX-XXXXXXXXXXXXXXXX` |
| `/SecurityIncidentResponse/slackSigningSecret` | SecureString | Slack App Signing Secret | 32-character hexadecimal string |
| `/SecurityIncidentResponse/slackWorkspaceId` | String | Slack Workspace ID | `T1234567890` (9-11 chars) |

## Setup Methods

### Method 1: CDK Deployment (Recommended)

The simplest way to set up parameters is during CDK deployment:

```bash
./deploy_integrations_solution.py slack \
  --bot-token "xoxb-YOUR-BOT-TOKEN-HERE" \
  --signing-secret "YOUR-SIGNING-SECRET-HERE" \
  --workspace-id "T1234567890" \
  --log-level error
```

This method:
- Creates parameters automatically during stack deployment
- Validates parameter formats using CloudFormation constraints
- Sets up proper encryption and IAM permissions
- Tags parameters for management

### Method 2: Manual Setup Script

For manual parameter management or rotation, use the dedicated script:

```bash
# Initial setup
python scripts/slack_parameter_setup.py setup \
  --bot-token "xoxb-..." \
  --signing-secret "..." \
  --workspace-id "T1234567890" \
  --region us-east-1

# Validate existing parameters
python scripts/slack_parameter_setup.py validate --region us-east-1

# Rotate credentials
python scripts/slack_parameter_setup.py rotate \
  --bot-token "xoxb-NEW-TOKEN" \
  --signing-secret "NEW-SECRET" \
  --workspace-id "T1234567890" \
  --region us-east-1
```

## Parameter Validation

### Automatic Validation

The CDK stack includes CloudFormation parameter constraints that validate:

1. **Bot Token Format**:
   - Must start with `xoxb-`
   - Pattern: `xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+`
   - Example: `xoxb-NUMBERS-NUMBERS-ALPHANUMERIC`

2. **Signing Secret Format**:
   - Must be exactly 32 hexadecimal characters
   - Pattern: `[a-f0-9]{32}`
   - Example: `32-CHARACTER-HEXADECIMAL-STRING`

3. **Workspace ID Format**:
   - Must be 9-11 uppercase alphanumeric characters
   - Pattern: `[A-Z0-9]{9,11}`
   - Example: `T1234567890`

### Manual Validation

Use the validation script to check existing parameters:

```bash
python scripts/slack_parameter_setup.py validate --region us-east-1
```

Output example:
```
🔍 Validating existing Slack parameters...

✅ Bot token parameter exists: /SecurityIncidentResponse/slackBotToken
   Last modified: 2025-01-15 10:30:00
✅ Signing secret parameter exists: /SecurityIncidentResponse/slackSigningSecret
   Last modified: 2025-01-15 10:30:00
✅ Workspace ID parameter exists: /SecurityIncidentResponse/slackWorkspaceId
   Last modified: 2025-01-15 10:30:00
```

## Parameter Rotation

### When to Rotate

Rotate Slack credentials when:

- **Security Incident**: Suspected credential compromise
- **Regular Schedule**: Every 90 days as a best practice
- **Team Changes**: When team members with access leave
- **Slack App Regeneration**: When regenerating tokens in Slack App settings

### Rotation Process

1. **Generate New Credentials in Slack**:
   - Go to your Slack App settings
   - Navigate to "OAuth & Permissions"
   - Regenerate the Bot User OAuth Token
   - Navigate to "Basic Information"
   - Regenerate the Signing Secret

2. **Update Parameters**:
   ```bash
   python scripts/slack_parameter_setup.py rotate \
     --bot-token "xoxb-NEW-TOKEN" \
     --signing-secret "NEW-SECRET" \
     --workspace-id "T1234567890" \
     --region us-east-1
   ```

3. **Verify Integration**:
   - Lambda functions automatically pick up new parameters
   - Test by creating a new AWS Security IR case
   - Verify Slack channel creation and notifications

### Zero-Downtime Rotation

The rotation process is designed for zero downtime:

- Parameters are updated atomically
- Lambda functions cache parameters with TTL
- New invocations automatically use updated credentials
- No redeployment required

## IAM Permissions

### Lambda Function Permissions

Each Lambda function has specific SSM parameter access:

**Slack Client Lambda**:
```json
{
  "Effect": "Allow",
  "Action": ["ssm:GetParameter"],
  "Resource": [
    "arn:aws:ssm:REGION:ACCOUNT:parameter/SecurityIncidentResponse/slackBotToken",
    "arn:aws:ssm:REGION:ACCOUNT:parameter/SecurityIncidentResponse/slackWorkspaceId"
  ]
}
```

**Slack Events Bolt Handler Lambda**:
```json
{
  "Effect": "Allow",
  "Action": ["ssm:GetParameter"],
  "Resource": [
    "arn:aws:ssm:REGION:ACCOUNT:parameter/SecurityIncidentResponse/slackBotToken",
    "arn:aws:ssm:REGION:ACCOUNT:parameter/SecurityIncidentResponse/slackSigningSecret"
  ]
}
```

**Slack Command Handler Lambda**:
```json
{
  "Effect": "Allow",
  "Action": ["ssm:GetParameter"],
  "Resource": [
    "arn:aws:ssm:REGION:ACCOUNT:parameter/SecurityIncidentResponse/slackBotToken",
    "arn:aws:ssm:REGION:ACCOUNT:parameter/SecurityIncidentResponse/slackSigningSecret"
  ]
}
```

### Administrator Permissions

For parameter management, administrators need:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:PutParameter",
        "ssm:GetParameter",
        "ssm:DeleteParameter",
        "ssm:AddTagsToResource",
        "ssm:ListTagsForResource"
      ],
      "Resource": [
        "arn:aws:ssm:*:*:parameter/SecurityIncidentResponse/slack*"
      ]
    }
  ]
}
```

## Security Best Practices

### 1. Credential Protection

- **Never commit credentials**: Keep tokens out of version control
- **Use environment variables**: For local testing, use environment variables
- **Rotate regularly**: Implement 90-day rotation schedule
- **Monitor access**: Review CloudTrail logs for parameter access

### 2. Access Control

- **Least privilege**: Grant only necessary permissions to Lambda functions
- **Resource-specific**: Use specific parameter ARNs in IAM policies
- **Separate environments**: Use different parameters for dev/staging/prod
- **Audit regularly**: Review IAM policies and parameter access patterns

### 3. Encryption

- **SecureString type**: All sensitive parameters use SecureString
- **KMS encryption**: Parameters encrypted with AWS KMS
- **In-transit encryption**: TLS for all API calls
- **At-rest encryption**: SSM Parameter Store encryption

### 4. Monitoring

- **CloudTrail logging**: All parameter operations logged
- **CloudWatch alarms**: Alert on unauthorized access attempts
- **Parameter versioning**: SSM maintains parameter version history
- **Audit trail**: Tags track rotation dates and operators

## Troubleshooting

### Common Issues

#### 1. Parameter Not Found

**Symptom**: Lambda function fails with "Parameter not found" error

**Solution**:
```bash
# Verify parameters exist
python scripts/slack_parameter_setup.py validate --region us-east-1

# If missing, set up parameters
python scripts/slack_parameter_setup.py setup \
  --bot-token "xoxb-..." \
  --signing-secret "..." \
  --workspace-id "T1234567890"
```

#### 2. Invalid Parameter Format

**Symptom**: CloudFormation deployment fails with constraint violation

**Solution**:
- Verify bot token starts with `xoxb-`
- Verify signing secret is 32 hexadecimal characters
- Verify workspace ID is 9-11 uppercase alphanumeric characters

#### 3. Access Denied

**Symptom**: Lambda function cannot read parameters

**Solution**:
- Check IAM role has `ssm:GetParameter` permission
- Verify parameter ARN matches in IAM policy
- Check KMS key permissions if using custom KMS key

#### 4. Stale Credentials

**Symptom**: Slack API returns authentication errors

**Solution**:
```bash
# Rotate parameters with new credentials
python scripts/slack_parameter_setup.py rotate \
  --bot-token "xoxb-NEW-TOKEN" \
  --signing-secret "NEW-SECRET" \
  --workspace-id "T1234567890"
```

### Debugging

Enable debug logging to troubleshoot parameter issues:

```bash
# Deploy with debug logging
./deploy_integrations_solution.py slack \
  --bot-token "xoxb-..." \
  --signing-secret "..." \
  --workspace-id "T1234567890" \
  --log-level debug
```

Check CloudWatch Logs for parameter access:
```bash
aws logs tail /aws/lambda/SlackClient --follow
```

## Compliance and Auditing

### Audit Trail

All parameter operations are logged in CloudTrail:

```bash
# Query parameter access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=/SecurityIncidentResponse/slackBotToken \
  --max-results 50
```

### Compliance Requirements

The parameter management system supports:

- **SOC 2**: Encryption at rest and in transit
- **PCI DSS**: Secure credential storage and rotation
- **HIPAA**: Audit logging and access controls
- **GDPR**: Data protection and access tracking

### Reporting

Generate parameter rotation reports:

```bash
# List parameters with metadata
aws ssm describe-parameters \
  --parameter-filters "Key=Name,Values=/SecurityIncidentResponse/slack" \
  --query 'Parameters[*].[Name,LastModifiedDate,Version]' \
  --output table
```

## Advanced Topics

### Custom KMS Keys

To use a custom KMS key for parameter encryption:

1. Create a KMS key
2. Update the CDK stack to specify the KMS key
3. Grant Lambda functions access to the KMS key

### Parameter Versioning

SSM maintains parameter version history:

```bash
# Get parameter history
aws ssm get-parameter-history \
  --name /SecurityIncidentResponse/slackBotToken \
  --query 'Parameters[*].[Version,LastModifiedDate]' \
  --output table
```

### Automated Rotation

Implement automated rotation using AWS Lambda:

1. Create a Lambda function to rotate credentials
2. Schedule with EventBridge (e.g., every 90 days)
3. Use Slack API to regenerate tokens
4. Update SSM parameters automatically

## References

- [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
- [Slack API Authentication](https://api.slack.com/authentication)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Parameter Rotation Best Practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)

# Slack Parameter Management

This directory contains scripts for managing SSM parameters for the Slack integration with AWS Security Incident Response.

## Overview

The `slack_parameter_setup.py` script provides secure parameter management with:

- **Parameter Validation**: Validates Slack credentials format before storage
- **Parameter Rotation**: Supports rotating credentials without redeployment
- **Encryption**: All sensitive parameters stored as SecureString in SSM
- **Audit Trail**: Tags parameters with rotation timestamps

## Prerequisites

- AWS CLI configured with appropriate credentials
- Python 3.x with boto3 installed
- IAM permissions for SSM Parameter Store operations

## Installation

```bash
# Install required dependencies
pip install boto3
```

## Usage

### Initial Parameter Setup

Set up Slack parameters for the first time:

```bash
python scripts/slack_parameter_setup.py setup \
  --bot-token "xoxb-YOUR-BOT-TOKEN-HERE" \
  --signing-secret "YOUR-SIGNING-SECRET-HERE" \
  --workspace-id "T1234567890" \
  --region us-east-1
```

### Rotate Existing Parameters

Update parameters with new credentials (e.g., after token rotation in Slack):

```bash
python scripts/slack_parameter_setup.py rotate \
  --bot-token "xoxb-NEW-TOKEN-HERE" \
  --signing-secret "NEW-SIGNING-SECRET-HERE" \
  --workspace-id "T1234567890" \
  --region us-east-1
```

### Validate Existing Parameters

Check if all required parameters exist and are properly configured:

```bash
python scripts/slack_parameter_setup.py validate \
  --region us-east-1
```

## Parameter Details

### Slack Bot Token (`/SecurityIncidentResponse/slackBotToken`)

- **Format**: `xoxb-XXXXXXXXX-XXXXXXXXX-XXXXXXXXXXXXXXXX`
- **Type**: SecureString (encrypted)
- **Purpose**: OAuth token for Slack Bot API access
- **Scopes Required**:
  - `channels:manage` - Create and manage channels
  - `channels:read` - Read channel information
  - `chat:write` - Post messages to channels
  - `files:read` - Read file information
  - `files:write` - Upload files to channels
  - `users:read` - Read user information
  - `channels:join` - Join channels

### Slack Signing Secret (`/SecurityIncidentResponse/slackSigningSecret`)

- **Format**: 32-character hexadecimal string
- **Type**: SecureString (encrypted)
- **Purpose**: Verify webhook requests from Slack
- **Location**: Found in Slack App settings under "Basic Information"

### Slack Workspace ID (`/SecurityIncidentResponse/slackWorkspaceId`)

- **Format**: 9-11 uppercase alphanumeric characters (e.g., `T1234567890`)
- **Type**: String
- **Purpose**: Identify target Slack workspace
- **Location**: Found in Slack workspace URL or via API

## Security Best Practices

1. **Never commit credentials**: Keep tokens and secrets out of version control
2. **Use IAM roles**: Grant least-privilege access to SSM parameters
3. **Rotate regularly**: Update credentials periodically using the rotate command
4. **Monitor access**: Use CloudTrail to audit parameter access
5. **Encrypt at rest**: All sensitive parameters use SecureString type

## Parameter Rotation Process

When rotating Slack credentials:

1. Generate new credentials in Slack App settings
2. Run the `rotate` command with new credentials
3. The script validates new credentials before updating
4. Parameters are updated atomically
5. Lambda functions automatically pick up new values on next invocation

## Troubleshooting

### Parameter Already Exists Error

If you see "Parameter already exists" during setup:
- Use the `rotate` command instead to update existing parameters
- Or delete the existing parameters and run setup again

### Validation Errors

Common validation errors:

- **Bot Token**: Must start with `xoxb-` and follow the correct format
- **Signing Secret**: Must be exactly 32 hexadecimal characters
- **Workspace ID**: Must be 9-11 uppercase alphanumeric characters

### Permission Errors

If you encounter permission errors:
- Ensure your AWS credentials have `ssm:PutParameter` and `ssm:GetParameter` permissions
- Check that you have access to the `/SecurityIncidentResponse/*` parameter namespace

## Integration with CDK Deployment

The CDK stack automatically creates these parameters during deployment using CloudFormation parameters. However, you can use this script to:

- Rotate credentials after initial deployment
- Validate parameter configuration
- Update parameters without redeploying the stack

## Example IAM Policy

Minimum IAM permissions required to run this script:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ssm:PutParameter",
        "ssm:GetParameter",
        "ssm:AddTagsToResource"
      ],
      "Resource": [
        "arn:aws:ssm:*:*:parameter/SecurityIncidentResponse/slack*"
      ]
    }
  ]
}
```

## Support

For issues or questions:
- Check the main project documentation
- Review CloudWatch Logs for Lambda function errors
- Verify Slack App configuration matches parameter values

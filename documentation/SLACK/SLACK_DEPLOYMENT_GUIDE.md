# Slack Integration Deployment Guide

This guide provides step-by-step instructions for deploying the AWS Security Incident Response Slack integration, including prerequisites, deployment steps, post-deployment configuration, and verification.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Steps](#deployment-steps)
- [Post-Deployment Configuration](#post-deployment-configuration)
- [Verification and Testing](#verification-and-testing)
- [Troubleshooting Deployment Issues](#troubleshooting-deployment-issues)
- [Rollback Procedures](#rollback-procedures)

## Prerequisites

### AWS Requirements

1. **AWS Account**: Active AWS account with appropriate permissions
2. **IAM Permissions**: Permissions to create and manage:
   - CloudFormation stacks
   - Lambda functions
   - API Gateway
   - EventBridge rules
   - DynamoDB tables
   - SSM parameters
   - IAM roles and policies
   - CloudWatch Logs

3. **AWS CLI**: Installed and configured
   ```bash
   aws --version
   aws configure list
   ```

4. **AWS CDK**: Installed globally
   ```bash
   npm install -g aws-cdk
   cdk --version
   ```

### Slack Requirements

1. **Slack Workspace**: Admin access to a Slack workspace
2. **Slack App**: Created and configured (see [Creating a Slack App](#creating-a-slack-app))
3. **Bot Token**: Slack Bot User OAuth Token (starts with `xoxb-`)
4. **Signing Secret**: Slack App Signing Secret (32 hex characters)
5. **Workspace ID**: Slack Workspace ID (starts with `T`)

### Development Environment

1. **Python 3.x**: Python 3.8 or later
   ```bash
   python3 --version
   ```

2. **Python Dependencies**: Install required packages
   ```bash
   pip install -r requirements.txt
   ```

3. **Git**: For cloning the repository
   ```bash
   git --version
   ```

## Pre-Deployment Checklist

Before deploying, ensure you have:

- [ ] AWS CLI configured with appropriate credentials
- [ ] AWS CDK installed and bootstrapped in your account
- [ ] Python 3.x installed
- [ ] Project dependencies installed (`pip install -r requirements.txt`)
- [ ] Slack app created with required permissions
- [ ] Slack Bot User OAuth Token (xoxb-...)
- [ ] Slack App Signing Secret
- [ ] Slack Workspace ID
- [ ] Reviewed and understood the architecture
- [ ] Planned for monitoring and alerting
- [ ] Backup plan for rollback if needed

## Creating a Slack App

### Step 1: Create the App

1. Go to https://api.slack.com/apps
2. Click "Create New App"
3. Select "From scratch"
4. Enter app name: `AWS Security IR Integration`
5. Select your workspace
6. Click "Create App"

### Step 2: Configure Bot Token Scopes

1. In the left sidebar, click "OAuth & Permissions"
2. Scroll to "Scopes" section
3. Under "Bot Token Scopes", add the following scopes:

   | Scope | Purpose |
   |-------|---------|
   | `channels:manage` | Create and manage public channels |
   | `channels:read` | View basic channel information |
   | `channels:join` | Join public channels |
   | `chat:write` | Send messages as the bot |
   | `files:read` | View files shared in channels |
   | `files:write` | Upload files to channels |
   | `users:read` | View users in the workspace |
   | `users:read.email` | View user email addresses |
   | `groups:read` | View private channel information |
   | `groups:write` | Manage private channels |
   | `im:read` | View direct messages |
   | `mpim:read` | View group direct messages |
   | `commands` | Add slash commands |

### Step 3: Install App to Workspace

1. Scroll to the top of the "OAuth & Permissions" page
2. Click "Install to Workspace"
3. Review the permissions
4. Click "Allow"
5. **Copy the "Bot User OAuth Token"** (starts with `xoxb-`)
6. Save this token securely - you'll need it for deployment

### Step 4: Get Signing Secret

1. In the left sidebar, click "Basic Information"
2. Scroll to "App Credentials"
3. **Copy the "Signing Secret"**
4. Save this secret securely - you'll need it for deployment

### Step 5: Get Workspace ID

1. In your Slack workspace, click on the workspace name in the top-left
2. Select "Settings & administration" > "Workspace settings"
3. The Workspace ID is in the URL: `https://app.slack.com/client/T1234567890/...`
4. Copy the ID that starts with `T` (e.g., `T1234567890`)

## Deployment Steps

### Step 1: Validate Parameters

Before deployment, validate your Slack credentials:

```bash
# Validate bot token format (should start with xoxb-)
echo "xoxb-YOUR-BOT-TOKEN" | grep -E '^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$'

# Validate signing secret format (should be 32 hex characters)
echo "YOUR-32-CHARACTER-SIGNING-SECRET" | grep -E '^[a-f0-9]{32}$'

# Validate workspace ID format (should be 9-11 uppercase alphanumeric)
echo "T1234567890" | grep -E '^[A-Z0-9]{9,11}$'
```

### Step 2: Review Deployment Command

```bash
./deploy-integrations-solution.py slack --help
```

Expected output:
```
usage: deploy-integrations-solution slack [-h] --bot-token BOT_TOKEN 
                                          --signing-secret SIGNING_SECRET 
                                          --workspace-id WORKSPACE_ID 
                                          [--region REGION]
                                          [--skip-verification]
                                          [--log-level {info,debug,error}]

options:
  -h, --help            show this help message and exit
  --bot-token BOT_TOKEN
                        Slack Bot User OAuth Token (xoxb-...)
  --signing-secret SIGNING_SECRET
                        Slack App Signing Secret
  --workspace-id WORKSPACE_ID
                        Slack Workspace ID
  --region REGION       AWS region for deployment (default: us-east-1)
  --skip-verification   Skip post-deployment verification checks
  --log-level {info,debug,error}
                        Log level for Lambda functions
```

### Step 3: Deploy the Integration

```bash
./deploy-integrations-solution.py slack \
  --bot-token "xoxb-YOUR-BOT-TOKEN-HERE" \
  --signing-secret "YOUR-SIGNING-SECRET-HERE" \
  --workspace-id "T1234567890" \
  --region "us-east-1" \
  --log-level error
```

**Deployment Options**:

- `--region`: AWS region (default: us-east-1)
- `--skip-verification`: Skip automatic verification after deployment
- `--log-level`: Lambda log level (info, debug, or error)

### Step 4: Monitor Deployment

The deployment process will:

1. Deploy the Common Stack (if not already deployed)
   - EventBridge custom event bus
   - DynamoDB table for incident mapping
   - Lambda layers for shared code

2. Deploy the Slack Integration Stack
   - Slack Client Lambda function
   - Slack Events Bolt Handler Lambda function
   - Slack Command Handler Lambda function
   - API Gateway for Slack webhooks
   - EventBridge rules for event routing
   - SSM parameters for credentials
   - IAM roles and policies

3. Run automatic verification (unless `--skip-verification` is used)

### Step 5: Review Deployment Outputs

After successful deployment, note the following outputs:

- **SlackWebhookUrl**: API Gateway endpoint for Slack webhooks
- **SlackClientLambdaArn**: ARN of the Slack Client Lambda function
- **SlackEventsBoltHandlerLambdaLogGroup**: CloudWatch Logs group name
- **SlackCommandHandlerLambdaArn**: ARN of the Slack Command Handler Lambda

Save these values for configuration and troubleshooting.

## Post-Deployment Configuration

### Step 1: Configure Slack Event Subscriptions

1. **Get API Gateway Endpoint**:
   - From deployment outputs, copy the `SlackWebhookUrl`
   - Example: `https://abc123.execute-api.us-east-1.amazonaws.com/prod/slack/events`

2. **Enable Event Subscriptions**:
   - Go to https://api.slack.com/apps
   - Select your app
   - Click "Event Subscriptions" in the left sidebar
   - Toggle "Enable Events" to **On**

3. **Configure Request URL**:
   - Paste your API Gateway endpoint in "Request URL"
   - Wait for verification (you should see a green checkmark)
   - If verification fails, see [Troubleshooting](#troubleshooting-deployment-issues)

4. **Subscribe to Bot Events**:
   - Scroll to "Subscribe to bot events"
   - Click "Add Bot User Event"
   - Add these events:
     - `message.channels` - Listen for messages in public channels
     - `message.groups` - Listen for messages in private channels
     - `member_joined_channel` - Track when users join channels
     - `member_left_channel` - Track when users leave channels
     - `file_shared` - Track file uploads

5. **Save Changes**:
   - Click "Save Changes"
   - **Important**: Slack will prompt you to reinstall the app
   - Click "reinstall your app"

### Step 2: Configure Slack Slash Commands

1. **Create Slash Command**:
   - In your Slack app settings, click "Slash Commands"
   - Click "Create New Command"

2. **Configure Command**:
   - **Command**: `/security-ir`
   - **Request URL**: Your API Gateway endpoint (same as Event Subscriptions)
   - **Short Description**: `Manage AWS Security Incident Response cases`
   - **Usage Hint**: `[status|update-status|update-description|update-title|close|incident-details] [args]`

3. **Save Command**:
   - Click "Save"
   - Reinstall app if prompted

### Step 3: Verify Slack Configuration

1. **Check App Installation**:
   - In Slack, go to "Apps" in the left sidebar
   - Verify "AWS Security IR Integration" is listed and active

2. **Test Slash Command**:
   - In any channel, type `/security-ir`
   - Command should autocomplete
   - Even without a case, it should be recognized

## Verification and Testing

### Automatic Verification

If you didn't skip verification during deployment, the script automatically checks:

- CloudFormation stack status
- Lambda function states
- SSM parameters
- API Gateway endpoint
- EventBridge rules
- DynamoDB table

### Manual Verification

Run the verification script manually:

```bash
python3 scripts/verify_slack_deployment.py --region us-east-1
```

Expected output:
```
======================================================================
AWS Security Incident Response - Slack Integration Verification
======================================================================

🔍 Checking CloudFormation stack: AwsSecurityIncidentResponseSlackIntegrationStack
✅ Stack status: CREATE_COMPLETE

🔍 Checking Lambda functions
✅ Slack Client: Active
✅ Slack Command Handler: Active

🔍 Checking SSM parameters
✅ /SecurityIncidentResponse/slackBotToken: Exists
✅ /SecurityIncidentResponse/slackSigningSecret: Exists
✅ /SecurityIncidentResponse/slackWorkspaceId: Exists

🔍 Checking API Gateway
✅ Slack Webhook URL: https://abc123.execute-api.us-east-1.amazonaws.com/prod/slack/events

🔍 Checking EventBridge rules
✅ slack-client-rule: Enabled

🔍 Checking DynamoDB table
✅ DynamoDB table (incidents-table): Active

======================================================================
VERIFICATION SUMMARY
======================================================================
✅ All checks passed (6/6)
```

### Integration Testing

#### Test 1: Create AWS Security IR Case

```bash
aws security-ir create-case \
  --title "Test Security Incident" \
  --description "Testing Slack integration" \
  --severity "High" \
  --region us-east-1
```

**Expected Results**:
- New Slack channel created: `aws-security-incident-response-case-<caseId>`
- Initial notification posted with case details
- Case watchers added to channel

#### Test 2: Bidirectional Comment Sync

1. **Slack to AWS SIR**:
   - Post a message in the incident channel
   - Verify it appears as a comment in AWS Security IR:
     ```bash
     aws security-ir list-comments --case-id <caseId>
     ```

2. **AWS SIR to Slack**:
   - Add a comment in AWS Security IR:
     ```bash
     aws security-ir create-comment \
       --case-id <caseId> \
       --body "Test comment from AWS SIR"
     ```
   - Verify it appears as a message in Slack

#### Test 3: Slash Commands

1. **Status Command**:
   ```
   /security-ir status
   ```
   Expected: Current case status and details

2. **Update Status Command**:
   ```
   /security-ir update-status Investigating
   ```
   Expected: Case status updated, confirmation message

3. **Incident Details Command**:
   ```
   /security-ir incident-details
   ```
   Expected: Incident details with key information

#### Test 4: Attachment Sync

1. **Upload file to Slack**:
   - Upload a file to the incident channel
   - Verify it syncs to AWS Security IR

2. **Add attachment to AWS SIR**:
   - Add an attachment to the case
   - Verify it appears in Slack channel

### Verification Checklist

- [ ] CloudFormation stacks deployed successfully
- [ ] Lambda functions are active
- [ ] SSM parameters exist and are accessible
- [ ] API Gateway endpoint is accessible
- [ ] EventBridge rules are enabled
- [ ] DynamoDB table is active
- [ ] Slack Event Subscriptions URL verified
- [ ] Slash command configured and working
- [ ] Test case creates Slack channel
- [ ] Messages sync from Slack to AWS SIR
- [ ] Comments sync from AWS SIR to Slack
- [ ] Slash commands return expected results
- [ ] Attachments sync bidirectionally

## Troubleshooting Deployment Issues

### Issue: CloudFormation Stack Fails

**Symptoms**: Stack creation fails with error

**Solutions**:
1. Check CloudFormation events:
   ```bash
   aws cloudformation describe-stack-events \
     --stack-name AwsSecurityIncidentResponseSlackIntegrationStack \
     --max-items 20
   ```

2. Verify IAM permissions
3. Check parameter formats
4. Review error messages in CloudFormation console

### Issue: Parameter Validation Fails

**Symptoms**: Deployment fails with constraint violation

**Solutions**:
1. Verify bot token format: `xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+`
2. Verify signing secret: 32 hexadecimal characters
3. Verify workspace ID: 9-11 uppercase alphanumeric characters

### Issue: Lambda Deployment Fails

**Symptoms**: Lambda function creation fails

**Solutions**:
1. Check Lambda service limits
2. Verify IAM role permissions
3. Check Lambda layer sizes
4. Review CloudWatch Logs for errors

### Issue: API Gateway Verification Fails

**Symptoms**: Slack shows "Your URL didn't respond"

**Solutions**:
1. Test endpoint manually:
   ```bash
   curl -X POST <SlackWebhookUrl> \
     -H "Content-Type: application/json" \
     -d '{"type":"url_verification","challenge":"test123"}'
   ```

2. Check Lambda logs:
   ```bash
   aws logs tail /aws/lambda/SlackEventsBoltHandler --follow
   ```

3. Verify API Gateway configuration
4. Check Lambda permissions

For more troubleshooting, see [SLACK_TROUBLESHOOTING.md](SLACK_TROUBLESHOOTING.md).

## Rollback Procedures

### Rollback to Previous Version

If you need to rollback after an update:

```bash
aws cloudformation update-stack \
  --stack-name AwsSecurityIncidentResponseSlackIntegrationStack \
  --use-previous-template \
  --parameters UsePreviousValue=true
```

### Complete Removal

To completely remove the Slack integration:

```bash
# Delete Slack integration stack
aws cloudformation delete-stack \
  --stack-name AwsSecurityIncidentResponseSlackIntegrationStack

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete \
  --stack-name AwsSecurityIncidentResponseSlackIntegrationStack

# Optionally delete common stack if no other integrations are using it
aws cloudformation delete-stack \
  --stack-name AwsSecurityIncidentResponseSampleIntegrationsCommonStack
```

### Clean Up SSM Parameters

```bash
aws ssm delete-parameter --name /SecurityIncidentResponse/slackBotToken
aws ssm delete-parameter --name /SecurityIncidentResponse/slackSigningSecret
aws ssm delete-parameter --name /SecurityIncidentResponse/slackWorkspaceId
```

## Best Practices

### Deployment

1. **Test in Non-Production First**: Deploy to a test environment before production
2. **Use Version Control**: Track all configuration changes
3. **Document Custom Changes**: Keep records of any customizations
4. **Plan Maintenance Windows**: Schedule deployments during low-activity periods

### Security

1. **Rotate Credentials Regularly**: Rotate bot token and signing secret every 90 days
2. **Use Least Privilege**: Grant only necessary permissions
3. **Enable CloudTrail**: Monitor all API activity
4. **Review IAM Policies**: Regularly audit IAM roles and policies

### Monitoring

1. **Set Up CloudWatch Alarms**: Monitor error rates and latency
2. **Review Logs Regularly**: Check CloudWatch Logs for issues
3. **Track Metrics**: Monitor Lambda invocations and API Gateway requests
4. **Test Regularly**: Perform periodic integration tests

### Maintenance

1. **Keep Dependencies Updated**: Regularly update Lambda layers
2. **Review Documentation**: Keep deployment docs up to date
3. **Backup Configuration**: Maintain backups of SSM parameters
4. **Plan for Scaling**: Monitor usage and plan for growth

## Related Resources

- [Slack Integration Overview](SLACK.md)
- [Slack Troubleshooting Guide](SLACK_TROUBLESHOOTING.md)
- [Slack Parameter Management](SLACK_PARAMETER_MANAGEMENT.md)
- [AWS Security Incident Response Documentation](https://docs.aws.amazon.com/security-incident-response/)
- [Slack API Documentation](https://api.slack.com/)
- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)

## Support

For issues or questions:

1. Check the [Troubleshooting Guide](SLACK_TROUBLESHOOTING.md)
2. Review CloudWatch Logs for errors
3. Consult AWS Support
4. Visit Slack API support: https://api.slack.com/support

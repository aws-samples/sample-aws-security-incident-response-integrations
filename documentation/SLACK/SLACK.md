# AWS Security Incident Response Slack Integration

This document provides an overview of the AWS Security Incident Response Slack integration, including its architecture, deployment, configuration, and usage.

## Overview

The Slack integration for AWS Security Incident Response enables bidirectional communication between AWS Security Incident Response and Slack. This allows security incidents to be synchronized between both systems in real-time, with dedicated Slack channels created for each incident.

## Deployment

### Prerequisites

Before deploying the Slack integration, you need:

1. **Slack Workspace**: Admin access to a Slack workspace
2. **Slack App**: A Slack app configured with the required permissions
3. **AWS Account**: Permissions to deploy CloudFormation stacks and create AWS resources
4. **Python 3.x**: For running the deployment script
5. **AWS CDK**: Installed and configured (`npm install -g aws-cdk`)

### Creating a Slack App

1. **Create a New Slack App**:
   - Go to https://api.slack.com/apps
   - Click "Create New App"
   - Select "From scratch"
   - Enter an app name (e.g., "AWS Security IR Integration")
   - Select your workspace
   - Click "Create App"

2. **Configure OAuth & Permissions**:
   - In the left sidebar, click "OAuth & Permissions"
   - Scroll to "Scopes" section
   - Add the following **Bot Token Scopes**:
     - `channels:manage` - Create and manage channels
     - `channels:read` - View basic channel information
     - `chat:write` - Send messages as the bot
     - `files:read` - View files shared in channels
     - `files:write` - Upload files to channels
     - `users:read` - View users in the workspace
     - `users:read.email` - View user email addresses
     - `channels:join` - Join public channels
     - `groups:read` - View private channel information
     - `groups:write` - Manage private channels
     - `im:read` - View direct messages
     - `mpim:read` - View group direct messages
     - `commands` - Add slash commands

3. **Install App to Workspace**:
   - Scroll to the top of the "OAuth & Permissions" page
   - Click "Install to Workspace"
   - Review the permissions and click "Allow"
   - **Copy the "Bot User OAuth Token"** (starts with `xoxb-`)
   - Save this token securely - you'll need it for deployment

4. **Get Signing Secret**:
   - In the left sidebar, click "Basic Information"
   - Scroll to "App Credentials"
   - **Copy the "Signing Secret"**
   - Save this secret securely - you'll need it for deployment

5. **Get Workspace ID**:
   - In your Slack workspace, click on the workspace name in the top-left
   - Select "Settings & administration" > "Workspace settings"
   - The Workspace ID is shown in the URL: `https://app.slack.com/client/T1234567890/...`
   - The ID starts with `T` (e.g., `T1234567890`)

### Deployment Command

Use the deployment script to deploy the Slack integration:

```bash
./deploy-integrations-solution.py slack --help
```

You should see the following output:

```
usage: deploy-integrations-solution slack [-h] --bot-token BOT_TOKEN --signing-secret SIGNING_SECRET --workspace-id WORKSPACE_ID [--log-level {info,debug,error}]

options:
  -h, --help            show this help message and exit
  --bot-token BOT_TOKEN
                        Slack Bot User OAuth Token (xoxb-...)
  --signing-secret SIGNING_SECRET
                        Slack App Signing Secret
  --workspace-id WORKSPACE_ID
                        Slack Workspace ID
  --log-level {info,debug,error}
                        Log level for Lambda functions
```

Deploy the integration with a single command:

```bash
./deploy-integrations-solution.py slack \
  --bot-token "xoxb-YOUR-BOT-TOKEN-HERE" \
  --signing-secret "YOUR-SIGNING-SECRET-HERE" \
  --workspace-id "T1234567890" \
  --log-level error
```

### Deployment Parameters

The Slack integration stack requires the following parameters during deployment:

| Parameter | Description | Type | Required | Format | Example |
|-----------|-------------|------|----------|--------|---------|
| `slackBotToken` | Slack Bot User OAuth Token | String | Yes | `xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+` | `xoxb-NUMBERS-NUMBERS-ALPHANUMERIC` |
| `slackSigningSecret` | Slack App Signing Secret for webhook verification | String | Yes | 32 hexadecimal characters | `a1b2c3d4e5f6...` |
| `slackWorkspaceId` | Slack Workspace ID | String | Yes | `[A-Z0-9]{9,11}` | `T1234567890` |
| `logLevel` | Log level for Lambda functions | String | No | `info`, `debug`, or `error` | `error` (default) |

**Parameter Validation**: The deployment script validates all parameters using CloudFormation constraints to ensure they match the required formats before deployment.

### Deployment Process

The deployment script performs the following steps:

1. **Validates Parameters**: Checks that all required parameters are provided and match the expected formats
2. **Deploys Common Stack**: Creates shared resources (EventBridge, DynamoDB, Lambda layers)
3. **Deploys Slack Stack**: Creates Slack-specific resources (Lambda functions, API Gateway, IAM roles)
4. **Creates SSM Parameters**: Stores credentials securely in AWS Systems Manager Parameter Store
5. **Configures Permissions**: Sets up IAM roles with least-privilege access
6. **Outputs Configuration**: Displays the API Gateway endpoint URL for Slack configuration

### Expected Output

After successful deployment, you'll see:

```
✅ Slack integration deployed successfully!

📝 Next steps:
   1. Configure your Slack app's Event Subscriptions URL with the API Gateway endpoint
   2. Configure your Slack app's Slash Commands with the /security-ir command
   3. Install the Slack app to your workspace
   4. Test the integration by creating a test AWS Security IR case
```

## Post-Deployment Configuration

### Configure Slack Event Subscriptions

1. **Get API Gateway Endpoint**:
   - Go to AWS Console > CloudFormation
   - Select `AwsSecurityIncidentResponseSlackIntegrationStack`
   - Click the "Outputs" tab
   - Copy the `SlackEventsApiEndpoint` value (e.g., `https://abc123.execute-api.us-east-1.amazonaws.com/prod/slack/events`)

2. **Enable Event Subscriptions in Slack**:
   - Go to https://api.slack.com/apps
   - Select your app
   - In the left sidebar, click "Event Subscriptions"
   - Toggle "Enable Events" to **On**
   - In "Request URL", paste your API Gateway endpoint
   - Wait for the URL to be verified (you should see a green checkmark)

3. **Subscribe to Bot Events**:
   - Scroll to "Subscribe to bot events"
   - Click "Add Bot User Event"
   - Add the following events:
     - `message.channels` - Listen for messages in public channels
     - `message.groups` - Listen for messages in private channels
     - `member_joined_channel` - Track when users join channels
     - `member_left_channel` - Track when users leave channels
     - `file_shared` - Track file uploads
   - Click "Save Changes"
   - **Important**: Slack will prompt you to reinstall the app. Click "reinstall your app"

### Configure Slack Slash Commands

1. **Create Slash Command**:
   - In your Slack app settings, click "Slash Commands" in the left sidebar
   - Click "Create New Command"
   - Enter the following details:
     - **Command**: `/security-ir`
     - **Request URL**: Your API Gateway endpoint (same as Event Subscriptions)
     - **Short Description**: `Manage AWS Security Incident Response cases`
     - **Usage Hint**: `[status|update-status|update-description|update-title|close|summarize] [args]`
   - Click "Save"

2. **Reinstall App** (if prompted):
   - Click "Install App" in the left sidebar
   - Click "Reinstall to Workspace"
   - Review permissions and click "Allow"

### Verify Installation

1. **Check Slack App**:
   - In your Slack workspace, go to "Apps" in the left sidebar
   - You should see your AWS Security IR Integration app listed
   - The app should show as "Active"

2. **Test Slash Command**:
   - In any Slack channel, type `/security-ir`
   - You should see the command autocomplete
   - The command should be recognized (even if it returns an error without a case)

## Testing the Integration

### Create a Test Case

1. **Create AWS Security IR Case**:
   ```bash
   aws security-ir create-case \
     --title "Test Security Incident" \
     --description "Testing Slack integration" \
     --severity "High"
   ```

2. **Verify Slack Channel Creation**:
   - A new channel should be created: `aws-security-incident-response-case-<caseId>`
   - The channel should contain an initial notification with case details
   - Case watchers should be automatically added to the channel

3. **Test Bidirectional Sync**:
   - Post a message in the Slack channel
   - Verify it appears as a comment in AWS Security IR
   - Add a comment in AWS Security IR
   - Verify it appears as a message in the Slack channel

4. **Test Slash Commands**:
   - In the incident channel, type `/security-ir status`
   - Verify you receive the current case status
   - Try other commands like `/security-ir summarize`

### Validation Checklist

- [ ] Slack channel created for new AWS Security IR case
- [ ] Initial notification posted to channel with case details
- [ ] Case watchers added to Slack channel
- [ ] Messages in Slack sync to AWS Security IR as comments
- [ ] Comments in AWS Security IR sync to Slack as messages
- [ ] Slash commands work and return expected results
- [ ] File uploads in Slack sync to AWS Security IR
- [ ] Attachments in AWS Security IR sync to Slack

## Architecture

### Integration Overview

```
┌─────────────────┐                  ┌────────────────┐                  ┌─────────────┐
│                 │                  │                │                  │             │
│  AWS Security   │◄─── Updates ────►│   EventBridge  │◄─── Updates ────►│  Slack      │
│  Incident       │                  │   Event Bus    │                  │  Workspace  │
│  Response       │                  │                │                  │             │
│                 │                  │                │                  │             │
└─────────────────┘                  └────────────────┘                  └─────────────┘
        ▲                                    ▲                                 ▲
        │                                    │                                 │
        │                                    │                                 │
        ▼                                    ▼                                 ▼
┌─────────────────┐                  ┌────────────────┐                  ┌─────────────┐
│                 │                  │                │                  │             │
│  Security IR    │                  │  Slack         │                  │  API        │
│  Client Lambda  │                  │  Client Lambda │                  │  Gateway    │
│                 │                  │                │                  │             │
│                 │                  │                │                  │             │
└─────────────────┘                  └────────────────┘                  └─────────────┘
                                             ▲                                 ▲
                                             │                                 │
                                             │                                 │
                                             ▼                                 ▼
                                     ┌────────────────┐                  ┌─────────────┐
                                     │                │                  │             │
                                     │  Slack Events  │                  │  Slack      │
                                     │  Bolt Handler  │◄─────────────────│  Webhooks   │
                                     │  Lambda        │                  │             │
                                     │                │                  │             │
                                     └────────────────┘                  └─────────────┘
                                             ▲
                                             │
                                             │
                                             ▼
                                     ┌────────────────┐
                                     │                │
                                     │  Slack Command │
                                     │  Handler Lambda│
                                     │                │
                                     │                │
                                     └────────────────┘
```

### Integration Flow

There are two bidirectional flows in the integration between Slack and AWS Security Incident Response (SIR).

#### Flow 1: AWS Security Incident Response to Slack

1. The **Security IR Poller Lambda** periodically polls for incidents generated by SIR
2. It stores the incident details in DynamoDB and publishes Create, Update, or Delete events to EventBridge
3. The **Slack Client Lambda** subscribes to these EventBridge events
4. For new cases, it creates a dedicated Slack channel and stores the `slackChannelId` in DynamoDB
5. For updates, it queries DynamoDB for the `slackChannelId` and posts updates to the specific channel
6. It syncs comments, attachments, and status changes to the Slack channel

#### Flow 2: Slack to AWS Security Incident Response

1. Users post messages or use slash commands in Slack incident channels
2. Slack sends webhook events to **API Gateway**
3. **API Gateway** routes events to the **Slack Events Bolt Handler Lambda**
4. The Bolt Handler processes events:
   - User messages are synced to AWS SIR as case comments
   - Channel membership changes are logged as system comments
   - File uploads are synced as attachments
   - Slash commands are routed to the **Slack Command Handler Lambda**
5. The **Slack Command Handler Lambda** executes AWS SIR API operations
6. Results are posted back to the Slack channel

## Resources

### AWS Resources

The Slack integration stack creates the following AWS resources:

#### Lambda Functions

1. **Slack Client Lambda** (`SecurityIncidentResponseSlackClient`)
   - Processes events from AWS Security Incident Response
   - Creates Slack channels for new incidents
   - Posts updates, comments, and attachments to Slack
   - Timeout: 15 minutes
   - Memory: 512 MB

2. **Slack Events Bolt Handler Lambda** (`SlackEventsBoltHandler`)
   - Processes all Slack events using Bolt framework
   - Handles messages, channel events, and file uploads
   - Routes slash commands to Command Handler
   - Timeout: 30 seconds
   - Memory: 512 MB

3. **Slack Command Handler Lambda** (`SlackCommandHandler`)
   - Processes `/security-ir` slash commands
   - Executes AWS SIR API operations
   - Returns results to users in Slack
   - Timeout: 30 seconds
   - Memory: 256 MB

#### API Gateway

- **Slack Events API** (`SlackEventsApi`)
  - REST API endpoint for Slack webhooks
  - Path: `/slack/events`
  - Handles Event Subscriptions and Slash Commands
  - Configured with request validation and rate limiting

#### EventBridge Rules

1. **Slack Client Rule** (`slack-client-rule`)
   - Captures events from AWS Security Incident Response
   - Triggers the Slack Client Lambda
   - Event pattern: Case Created, Case Updated, Comment Added, Attachment Added

2. **Slack Events Rule** (`slack-events-rule`)
   - Captures events from Slack
   - Logs events to CloudWatch

#### SSM Parameters

- `/SecurityIncidentResponse/slackBotToken` (SecureString)
- `/SecurityIncidentResponse/slackSigningSecret` (SecureString)
- `/SecurityIncidentResponse/slackWorkspaceId` (String)

#### IAM Roles

- Custom roles for each Lambda function with least privilege permissions
- Specific SSM parameter access per function
- EventBridge publish permissions
- DynamoDB read/write permissions

#### DynamoDB Table

- Uses a shared table from the common stack to store incident-to-channel mapping
- Schema includes `slackChannelId`, `slackChannelCaseDescription`, `slackChannelCaseTitle`, etc.

#### Lambda Layers

1. **Domain Layer**: Slack domain models and data structures
2. **Mappers Layer**: Slack data transformation logic
3. **Wrappers Layer**: Slack Bolt framework wrapper
4. **Slack Bolt Layer**: Slack SDK and Bolt framework dependencies

## Available Slash Commands

The `/security-ir` command supports the following subcommands:

| Command | Description | Usage | Example |
|---------|-------------|-------|---------|
| `status` | Get current case status and details | `/security-ir status` | Returns case ID, status, severity, title |
| `update-status` | Update case status | `/security-ir update-status <status>` | `/security-ir update-status Resolved` |
| `update-description` | Update case description | `/security-ir update-description <text>` | `/security-ir update-description Updated findings` |
| `update-title` | Update case title | `/security-ir update-title <text>` | `/security-ir update-title Critical Security Issue` |
| `close` | Close the case | `/security-ir close` | Closes the case and updates channel |
| `summarize` | Get case summary | `/security-ir summarize` | Returns summary with key events |

**Note**: All commands must be used within an incident channel (channel name starts with `aws-security-incident-response-case-`).

## Features

### Automatic Channel Creation

- Dedicated channel created for each AWS Security IR case
- Channel naming: `aws-security-incident-response-case-<caseId>`
- Case watchers automatically added to channel
- Initial notification with case details posted

### Bidirectional Comment Sync

- User messages in Slack sync to AWS SIR as case comments
- Comments in AWS SIR sync to Slack as messages
- User attribution preserved
- Duplicate detection prevents loops

### Attachment Synchronization

- Files uploaded to Slack channels sync to AWS SIR
- Attachments added to AWS SIR sync to Slack
- File metadata preserved (filename, type, size)
- Size limit handling with appropriate notifications

### Channel Membership Tracking

- System comments added when users join/leave channels
- Tagged with `[Slack Update]` to prevent notification loops
- Includes user name and timestamp

### Error Handling

- Exponential backoff retry logic for all Slack operations
- Failed operations logged as system comments in AWS SIR
- Dead-letter queues for failed events
- CloudWatch alarms for monitoring

## Troubleshooting

For detailed troubleshooting information, please refer to the [Slack Troubleshooting Guide](SLACK_TROUBLESHOOTING.md).

### Quick Troubleshooting

**Issue**: Slack channel not created for new case
- Check Slack Client Lambda logs in CloudWatch
- Verify bot token is valid
- Ensure bot has `channels:manage` permission

**Issue**: Messages not syncing from Slack to AWS SIR
- Verify Event Subscriptions URL is configured correctly
- Check Slack Events Bolt Handler Lambda logs
- Ensure bot is a member of the channel

**Issue**: Slash commands not working
- Verify slash command is configured with correct Request URL
- Check Slack Command Handler Lambda logs
- Ensure command is used in an incident channel

## Security Considerations

- All credentials stored securely in SSM Parameter Store with encryption
- IAM roles follow principle of least privilege
- Slack request signature verification for all webhooks
- API Gateway rate limiting and request validation
- CloudWatch logging enabled for all Lambda functions
- No sensitive data logged (tokens, passwords, PII)
- Regular credential rotation recommended (every 90 days)

## Frequently Asked Questions

### General Questions

**Q: How long does it take for changes to sync between systems?**  
A: Changes typically sync within seconds. The integration uses event-driven architecture to ensure near real-time updates.

**Q: Can I customize the channel naming convention?**  
A: Yes, you can modify the channel prefix by updating the SSM parameter `/SecurityIncidentResponse/slackChannelPrefix`.

**Q: What happens if the integration fails?**  
A: The integration includes error handling and dead-letter queues. Failed events are stored and can be reprocessed. CloudWatch alarms will notify you of failures.

**Q: Can I use this with Slack Enterprise Grid?**  
A: Yes, the integration supports Slack Enterprise Grid. Use the workspace ID of the specific workspace you want to integrate with.

### Technical Questions

**Q: What permissions are required in Slack?**  
A: The bot needs permissions to create channels, send messages, read messages, manage files, and read user information. See the "Creating a Slack App" section for the complete list.

**Q: How are credentials stored?**  
A: Slack credentials are stored in AWS Systems Manager Parameter Store as SecureString parameters with KMS encryption.

**Q: Can I deploy multiple integrations to different Slack workspaces?**  
A: Yes, you can deploy the stack multiple times with different parameters to connect to different Slack workspaces.

**Q: How do I rotate Slack credentials?**  
A: Use the parameter rotation script: `python scripts/slack_parameter_setup.py rotate --bot-token <new-token> --signing-secret <new-secret> --workspace-id <workspace-id>`. See the [Parameter Management Guide](SLACK_PARAMETER_MANAGEMENT.md) for details.

## Related Resources

- [AWS Security Incident Response Documentation](https://docs.aws.amazon.com/security-incident-response/)
- [Slack API Documentation](https://api.slack.com/)
- [Slack Bolt Framework Documentation](https://slack.dev/bolt-python/concepts)
- [Slack Event Subscriptions](https://api.slack.com/events-api)
- [Slack Slash Commands](https://api.slack.com/interactivity/slash-commands)
- [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)

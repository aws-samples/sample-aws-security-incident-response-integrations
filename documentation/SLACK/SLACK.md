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

### Bootstrap environment
If you haven't already performed a `cdk bootstrap` on your AWS account, run the following command either via an EC2 instance or local terminal as seen in the next i.e. [Install the necessary tools](#install-the-necessary-tools) section:

**Recommended: Use least-privilege bootstrap policy**

For enhanced security, use the least-privilege CDK bootstrap policy that restricts permissions to only the AWS services required by this solution. See the detailed policy and instructions in [CDK_BOOTSTRAP_POLICY.md](CDK_BOOTSTRAP_POLICY.md).

**Alternative: Use default bootstrap (less secure)**
```bash
cdk bootstrap
```

**Why to bootstrap?**
Bootstrap is a prerequisite to deployment. You cannot deploy the solution which is a CDK application into an AWS account and region (an "environment") until that environment has been bootstrapped. Trying to deploy without bootstrapping will result in an error. Performing `cdk bootstrap` on an environment allows you to provision the foundational resources (like an S3 bucket and IAM roles) that the AWS CDK needs to manage and deploy the solution's infrastructure. 

### Install the necessary tools

#### Using AWS Console (EC2 instance)

1. Navigate to EC2 in AWS Console
2. Launch a new instance
   1. Provide any `Name`
   2. Keep the **default** settings for `Application and OS images`:
      1. Keep the **default** `Amazon Linux` OS
      2. Keep the **default**, Free tier eligible AMI - `Amazon Linux 2023 kernel-6.1 AMI`
         ![EC2-OS](../images/ec2-os.png)
   3. In `Instance type`:
      1. Select `t2.xlarge`
         ![EC2-Instance-type](../images/ec2-instance-type.png)
   4. In `Key pair`, either select an existing key pair from the drop down or create a new one:
         ![EC2-key-pair](../images/ec2-key-pair.png)
   5. Keep everything else as **default**
   6. Click on `Launch Instance`
3. Once the instance is up and running, select the instance and click on `Connect`. Then, connect using `EC2 Instance Connect`:
      ![EC2-instance-connect](../images/ec2-instance-connect.png)
4. Once connected, simply copy and paste the following set of commands:
   ```
   sudo yum install git -y
   sudo yum install docker
   sudo yum install openssl
   sudo yum install -y nodejs
   sudo npm install -g aws-cdk
   node -v
   npm -v
   npx -v
   sudo yum install python3 python3-pip -y
   git clone https://github.com/aws-samples/sample-aws-security-incident-response-integrations.git
   cd sample-aws-security-incident-response-integrations/
   pip install -r requirements.txt
   chmod +x deploy_integrations_solution.py
   sudo systemctl start docker.service
   sudo chmod 666 /var/run/docker.sock
   ```
5. In the EC2 instance, configure aws credentials. Provide the `AWS Access Key ID`, `AWS Secret Access Key` and `AWS Session Token` when prompted:
   ```
   export AWS_ACCESS_KEY_ID=<AWS Access Key ID>
   export AWS_SECRET_ACCESS_KEY=<AWS Secret Access Key>
   export AWS_SESSION_TOKEN=<AWS Session Token>
   ```
6.  Now, run the `deploy` command from the following [Deployment Command](#deployment-command) section

#### Using local terminal instance

1. Open a new Terminal session
2. Copy and paste the following set of commands:
   ```
   sudo yum install git -y
   sudo yum install docker
   sudo yum install openssl
   sudo yum install -y nodejs
   sudo npm install -g aws-cdk
   node -v
   npm -v
   npx -v
   sudo yum install python3 python3-pip -y
   git clone https://github.com/aws-samples/sample-aws-security-incident-response-integrations.git
   cd sample-aws-security-incident-response-integrations/
   pip install -r requirements.txt
   chmod +x deploy_integrations_solution.py
   sudo systemctl start docker.service
   sudo chmod 666 /var/run/docker.sock
   ```
3. In the local instance, configure aws credentials. Provide the `AWS Access Key ID`, `AWS Secret Access Key` and `AWS Session Token` when prompted:
   ```
   export AWS_ACCESS_KEY_ID=<AWS Access Key ID>
   export AWS_SECRET_ACCESS_KEY=<AWS Secret Access Key>
   export AWS_SESSION_TOKEN=<AWS Session Token>
   ```
4. Create the least-privilege bootstrap policy:
   ```bash
   aws iam create-policy --policy-name CDKBootstrapPolicy --policy-document file://cdk-bootstrap-policy.json
   ```
5. Now, run the `deploy` command from the following [Deployment Command](#deployment-command) section

### Deployment Command

Use the deployment script to deploy the Slack integration:

```bash
./deploy_integrations_solution.py slack --help
```

You should see the following output:

```
usage: deploy_integrations_solution slack [-h] --bot-token BOT_TOKEN 
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

Deploy the integration with a single command:

```bash
./deploy_integrations_solution.py slack \
  --bot-token "xoxb-YOUR-BOT-TOKEN-HERE" \
  --signing-secret "YOUR-SIGNING-SECRET-HERE" \
  --workspace-id "T1234567890" \
  --region "us-east-1" \
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

🔍 Running deployment verification...

📝 Next steps:
   1. Configure your Slack app's Event Subscriptions URL with the API Gateway endpoint
   2. Configure your Slack app's Slash Commands with the /security-ir command
   3. Install the Slack app to your workspace
   4. Test the integration by creating a test AWS Security IR case
```

**Note**: The deployment includes automatic verification unless you use `--skip-verification`. The verification script checks all deployed resources and provides a comprehensive status report.

## Post-Deployment Configuration

### Configure Slack Event Subscriptions

1. **Get API Gateway Endpoint**:
   - Go to AWS Console > CloudFormation
   - Select `AwsSecurityIncidentResponseSlackIntegrationStack`
   - Click the "Outputs" tab
   - Copy the `SlackWebhookUrl` value (e.g., `https://abc123.execute-api.us-east-1.amazonaws.com/prod/slack/events`)

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
     - **Usage Hint**: `[status|update-status|update-description|update-title|close|incident-details] [args]`
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
   - Try other commands like `/security-ir incident-details`

### Validation Checklist

- [ ] Slack channel created for new AWS Security IR case
- [ ] Initial notification posted to channel with case details
- [ ] Case watchers added to Slack channel
- [ ] Messages in Slack sync to AWS Security IR as comments
- [ ] Comments in AWS Security IR sync to Slack as messages
- [ ] Slash commands work and return expected results
- [ ] File uploads in Slack sync to AWS Security IR
- [ ] Attachments in AWS Security IR sync to Slack

## User Scenarios and Workflows

The Slack integration provides seamless bidirectional synchronization between AWS Security Incident Response and Slack. Here are the key user scenarios and workflows:

### 1. New Security IR Case → Slack Channel Creation

**Scenario**: When a new AWS Security Incident Response case is created

**Workflow**:
1. A new case is created in AWS Security Incident Response (via console, API, or automation)
2. The Security IR Poller Lambda detects the new case within 1 minute
3. A dedicated Slack channel is automatically created with the naming convention: `aws-security-incident-response-case-<caseId>`
4. An initial notification is posted to the channel containing:
   - Case ID and title
   - Severity and status
   - Description
   - Creation timestamp
   - Direct link to the case in AWS console
5. Case watchers are automatically added to the Slack channel (if they exist in the workspace)
6. Channel topic is set with case status and severity for quick reference

### 2. Security IR Comments → Slack Messages

**Scenario**: When a comment is added to an AWS Security IR case

**Workflow**:
1. A comment is added to the case in AWS Security Incident Response
2. The Security IR Poller Lambda detects the new comment within 1 minute
3. The comment is automatically posted as a message in the corresponding Slack channel
4. The message includes author name, content, timestamp, and `[AWS Security IR Update]` tag

### 3. Security IR Watchers/Permissions → Slack Channel Members

**Scenario**: When new watchers or permissions are added to an AWS Security IR case

**Workflow**:
1. A new watcher is added to the case in AWS Security Incident Response
2. The Security IR Poller Lambda detects the permission change
3. The system attempts to find the user in the Slack workspace by email address
4. **If user exists in Slack workspace**: User is automatically added to the Slack channel with notification
5. **If user does not exist in Slack workspace**: A notification alert is posted in the channel with instructions for manual invitation

### 4. Slack Messages → Security IR Comments

**Scenario**: When a message is posted in a Slack incident channel

**Workflow**:
1. A user posts a message in the incident Slack channel
2. Slack sends a webhook event to the API Gateway endpoint
3. The Slack Events Bolt Handler Lambda processes the message
4. The message is automatically added as a comment to the corresponding AWS Security IR case
5. The comment includes `[Slack Update]` tag, author's real name, message content, and timestamp

### 5. Slack Attachments → Security IR Attachments

**Scenario**: When files are uploaded to a Slack incident channel

**Workflow**:
1. A user uploads a file to the Slack incident channel
2. Slack sends a `file_shared` event to the API Gateway endpoint
3. The Slack Events Bolt Handler Lambda processes the file event
4. The file is downloaded from Slack using the bot token
5. The file is uploaded to the corresponding AWS Security IR case as an attachment
6. File metadata is preserved (filename, size, MIME type)
7. A confirmation message is posted in Slack: `📎 File uploaded to AWS Security IR case`

**File Handling**:
- **Size Limit**: Maximum 100MB per file
- **Supported Formats**: All file types supported by both platforms
- **Error Handling**: Large files or upload failures generate warning messages
- **Duplicate Prevention**: Files are checked against existing attachments

### 6. Slash Commands for Case Management

**Available Commands**: The `/security-ir` command supports the following subcommands in incident channels:

#### `/security-ir status`
**Purpose**: Get current case status and details
**Usage**: `/security-ir status`
**Expected Outcome**:
```
📋 Case Status
ID: case-12345678-abcd-1234-efgh-123456789012
Status: In Progress
Severity: High
Title: Suspicious API Activity Detected
Description: Unusual API calls detected from unknown IP addresses
Created: 2024-01-15 14:30:00 UTC
Last Updated: 2024-01-15 16:30:00 UTC
Watchers: 3 users
```

#### `/security-ir update-status <status>`
**Purpose**: Update case status
**Usage**: `/security-ir update-status <Open|In Progress|Resolved|Closed>`
**Examples**:
- `/security-ir update-status Resolved`
- `/security-ir update-status "In Progress"`
**Expected Outcome**:
```
✅ Case status updated to "Resolved"
Updated by: @john.doe
Timestamp: 2024-01-15 17:00:00 UTC
```
**Error Cases**:
- Invalid status: `❌ Invalid status. Valid options: Open, In Progress, Resolved, Closed`
- Missing status: `❌ Please specify a status. Usage: /security-ir update-status <status>`

#### `/security-ir update-description <text>`
**Purpose**: Update case description
**Usage**: `/security-ir update-description <new description>`
**Example**: `/security-ir update-description Updated findings after further analysis`
**Expected Outcome**:
```
✅ Case description updated
New description: "Updated findings after further analysis"
Updated by: @jane.smith
Timestamp: 2024-01-15 17:15:00 UTC
```

#### `/security-ir update-title <text>`
**Purpose**: Update case title
**Usage**: `/security-ir update-title <new title>`
**Example**: `/security-ir update-title Critical Security Breach - Resolved`
**Expected Outcome**:
```
✅ Case title updated
Old title: "Suspicious API Activity Detected"
New title: "Critical Security Breach - Resolved"
Updated by: @security.team
Timestamp: 2024-01-15 17:30:00 UTC
```

#### `/security-ir close`
**Purpose**: Close the case
**Usage**: `/security-ir close`
**Expected Outcome**:
```
🔒 Case closed successfully
Case ID: case-12345678-abcd-1234-efgh-123456789012
Closed by: @incident.manager
Timestamp: 2024-01-15 18:00:00 UTC
Channel will remain active for reference
```
**Additional Actions**:
- Case status is set to "Closed" in AWS Security IR
- Channel topic is updated to reflect closed status
- System comment added to AWS Security IR case

#### `/security-ir incident-details`
**Purpose**: Get incident details with key information
**Usage**: `/security-ir incident-details`
**Expected Outcome**:
```
📊 Case Summary
Case ID: case-12345678-abcd-1234-efgh-123456789012
Title: Suspicious API Activity Detected
Status: Resolved → Closed
Severity: High
Duration: 3 hours 30 minutes

Key Events:
• 14:30 - Case created
• 15:45 - Analysis completed (John Doe)
• 16:30 - Mitigation applied (Jane Smith)
• 17:00 - Status updated to Resolved
• 18:00 - Case closed

Comments: 8 total (5 from AWS Security IR, 3 from Slack)
Attachments: 2 files
Watchers: 3 users
```

#### Command Error Handling

**Invalid Channel**: Commands used outside incident channels
```
❌ This command can only be used in AWS Security IR incident channels
Channel name must start with: aws-security-incident-response-case-
```

**Permission Errors**: User lacks permissions
```
❌ You don't have permission to modify this case
Contact your administrator or case owner for access
```

**API Errors**: AWS Security IR service issues
```
❌ Unable to update case due to service error
Error ID: api-error-20240115-180500
Please try again or contact support
```

**Network Errors**: Connectivity issues
```
⚠️ Temporary connectivity issue
Your request is being processed. Please check case status in a few moments
Error ID: network-error-20240115-180600
```

### 7. Security IR Attachments → Slack Files

**Scenario**: When attachments are added to an AWS Security IR case

**Workflow**:
1. An attachment is added to the AWS Security IR case
2. The Security IR Poller Lambda detects the new attachment
3. The file is downloaded from AWS Security IR
4. The file is uploaded to the corresponding Slack channel
5. A message is posted with the file and context: `📎 New attachment from AWS Security IR case`

**File Handling**:
- **Size Limit**: Maximum 100MB per file (Slack limitation)
- **Large File Handling**: Files over 100MB generate a download link message instead
- **Metadata Preservation**: Original filename, size, and type are maintained
- **Error Recovery**: Failed uploads are retried with exponential backoff

### Integration Benefits

- **Real-time Collaboration**: Security teams can collaborate in Slack while maintaining official records in AWS Security IR
- **Centralized Communication**: All incident-related discussions happen in dedicated channels
- **Audit Trail**: Complete bidirectional sync ensures no information is lost
- **Workflow Integration**: Teams can use familiar Slack interface while leveraging AWS Security IR capabilities
- **Automated Notifications**: Key stakeholders are automatically informed of updates
- **Mobile Access**: Teams can manage incidents from Slack mobile apps

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
│  Poller Lambda  │                  │  Client Lambda │                  │  Gateway    │
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

1. The **Security IR Poller Lambda** (from common stack) periodically polls for incidents generated by SIR
2. It stores the incident details in DynamoDB and publishes Create, Update, or Delete events to EventBridge
3. The **Slack Client Lambda** subscribes to these EventBridge events via the `slack-client-rule`
4. For new cases, it creates a dedicated Slack channel using the Slack Bolt framework and stores the `slackChannelId` in DynamoDB
5. For updates, it queries DynamoDB for the `slackChannelId` and posts updates to the specific channel
6. It syncs comments, attachments, and status changes to the Slack channel with duplicate detection

#### Flow 2: Slack to AWS Security Incident Response

1. Users post messages or use slash commands in Slack incident channels
2. Slack sends webhook events to **API Gateway** (`/slack/events` endpoint)
3. **API Gateway** routes events to the **Slack Events Bolt Handler Lambda**
4. The Bolt Handler processes events using the Slack Bolt framework:
   - User messages are synced to AWS SIR as case comments with `[Slack Update]` tag
   - Channel membership changes are tracked and logged
   - File uploads are downloaded and synced as attachments (with size limits)
   - Slash commands are routed asynchronously to the **Slack Command Handler Lambda**
5. The **Slack Command Handler Lambda** executes AWS SIR API operations (status updates, case modifications)
6. Results are posted back to the Slack channel using response URLs

## Resources

### AWS Resources

The Slack integration stack creates the following AWS resources:

#### Lambda Functions

1. **Slack Client Lambda** (`SecurityIncidentResponseSlackClient`)
   - Processes events from AWS Security Incident Response via EventBridge
   - Creates Slack channels for new incidents using Slack Bolt framework
   - Posts updates, comments, and attachments to Slack with exponential backoff retry
   - Handles bidirectional comment and attachment synchronization
   - Timeout: 15 minutes (for large attachment downloads)
   - Memory: 512 MB
   - Runtime: Python 3.13

2. **Slack Events Bolt Handler Lambda** (`SlackEventsBoltHandler`)
   - Processes all Slack events using Slack Bolt framework
   - Handles messages, channel events, file uploads, and member changes
   - Routes slash commands asynchronously to Command Handler
   - Performs Slack signature verification for security
   - Timeout: 30 seconds (Slack requirement)
   - Memory: 512 MB
   - Runtime: Python 3.13

3. **Slack Command Handler Lambda** (`SlackCommandHandler`)
   - Processes `/security-ir` slash commands (status, update-status, update-description, etc.)
   - Executes AWS SIR API operations with proper error handling
   - Returns results to users via Slack response URLs
   - Includes user permission validation
   - Timeout: 30 seconds (Slack requirement)
   - Memory: 256 MB
   - Runtime: Python 3.13

#### API Gateway

- **Slack Webhook API** (`SlackWebhookApi`)
  - REST API endpoint for Slack webhooks
  - Path: `/slack/events`
  - Handles Event Subscriptions and Slash Commands
  - Configured with CORS, throttling (100 req/sec, 200 burst), and access logging
  - Signature verification handled in Lambda (not API Gateway)
  - CloudWatch Logs integration with 1-week retention

#### EventBridge Rules

1. **Slack Client Rule** (`slack-client-rule`)
   - Captures events from AWS Security Incident Response (source: `security-ir`)
   - Triggers the Slack Client Lambda
   - Event pattern: CaseCreated, CaseUpdated, CommentAdded, AttachmentAdded

2. **Slack Notifications Rule** (`SlackNotificationsRule`)
   - Captures events from Slack Events Handler (source: `slack`)
   - Logs events to CloudWatch for monitoring and debugging
   - Helps track bidirectional sync operations

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

1. **Domain Layer**: Shared domain models and data structures for incident management
2. **Mappers Layer**: Data transformation logic between AWS SIR and Slack formats
3. **Wrappers Layer**: Slack Bolt framework wrapper with common functionality
4. **Slack Bolt Layer**: Slack SDK and Bolt framework dependencies (slack-bolt, slack-sdk)

All layers are compatible with Python 3.13 runtime and shared across Lambda functions for consistency.

## Available Slash Commands

The `/security-ir` command supports the following subcommands:

| Command | Description | Usage | Example |
|---------|-------------|-------|---------|
| `status` | Get current case status and details | `/security-ir status` | Returns case ID, status, severity, title |
| `update-status` | Update case status | `/security-ir update-status <status>` | `/security-ir update-status Resolved` |
| `update-description` | Update case description | `/security-ir update-description <text>` | `/security-ir update-description Updated findings` |
| `update-title` | Update case title | `/security-ir update-title <text>` | `/security-ir update-title Critical Security Issue` |
| `close` | Close the case | `/security-ir close` | Closes the case and updates channel |
| `incident-details` | Get incident details | `/security-ir incident-details` | Returns details with key information |

**Note**: All commands must be used within an incident channel (channel name starts with `aws-security-incident-response-case-`).

## Features

### Automatic Channel Creation

- Dedicated channel created for each AWS Security IR case
- Channel naming: `aws-security-incident-response-case-<caseId>`
- Case watchers automatically added to channel (with email lookup)
- Initial notification with case details posted using Slack blocks
- Channel topic set with case status and severity
- System comments added to AWS SIR case for tracking

### Bidirectional Comment Sync

- User messages in Slack sync to AWS SIR as case comments with `[Slack Update]` tag
- Comments in AWS SIR sync to Slack as messages (excluding system comments)
- User attribution preserved with real names from Slack API
- Comprehensive duplicate detection using message timestamps and content
- Loop prevention with system comment tagging

### Attachment Synchronization

- Files uploaded to Slack channels sync to AWS SIR with size validation (100MB limit)
- Attachments added to AWS SIR sync to Slack with download and upload handling
- File metadata preserved (filename, type, size, MIME type)
- Size limit handling with user-friendly error messages
- Retry logic with exponential backoff for failed transfers
- Duplicate attachment detection and tracking

### Channel Membership Tracking

- EventBridge events published when users join/leave channels
- User information enriched with real names from Slack API
- Membership changes logged for audit purposes
- Integration with incident response workflow tracking

### Error Handling

- Exponential backoff retry logic with jitter for all Slack operations
- Failed operations logged as system comments in AWS SIR with error details
- Dead-letter queues for failed EventBridge events
- CloudWatch alarms and comprehensive logging for monitoring
- Graceful degradation for non-critical failures (e.g., user lookup failures)

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
A: Slack credentials are stored in AWS Systems Manager Parameter Store as SecureString parameters with KMS encryption. Bot tokens and signing secrets are validated during deployment and accessed securely by Lambda functions.

**Q: Can I deploy multiple integrations to different Slack workspaces?**  
A: Yes, you can deploy the stack multiple times with different parameters to connect to different Slack workspaces.

**Q: How do I rotate Slack credentials?**  
A: Use the parameter rotation script: `python scripts/slack_parameter_setup.py rotate --bot-token <new-token> --signing-secret <new-secret> --workspace-id <workspace-id>`. The script validates formats and updates all SSM parameters atomically. See the [Parameter Management Guide](SLACK_PARAMETER_MANAGEMENT.md) for details.

## Related Resources

- [AWS Security Incident Response Documentation](https://docs.aws.amazon.com/security-incident-response/)
- [Slack API Documentation](https://api.slack.com/)
- [Slack Bolt Framework Documentation](https://slack.dev/bolt-python/concepts)
- [Slack Event Subscriptions](https://api.slack.com/events-api)
- [Slack Slash Commands](https://api.slack.com/interactivity/slash-commands)
- [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)

# AWS Security Incident Response Slack Integration - Troubleshooting Guide

This document provides detailed information on validation, troubleshooting, diagnostics, and security considerations for the AWS Security Incident Response Slack integration.

## Table of Contents

- [Outputs and Validation](#outputs-and-validation)
- [Common Issues and Solutions](#common-issues-and-solutions)
- [Diagnostic Steps](#diagnostic-steps)
- [Checklist in case of any errors](#checklist-in-case-of-any-errors)
- [Security Considerations](#security-considerations)
- [Performance Optimization](#performance-optimization)

## Outputs and Validation

After deploying the stack, you'll receive CloudFormation outputs that can be used to validate and troubleshoot the integration.

### CloudFormation Outputs

#### SlackEventsApiEndpoint

This output provides the API Gateway endpoint URL for Slack webhooks.

**Format**: `https://<api-id>.execute-api.<region>.amazonaws.com/prod/slack/events`

**How to use it**:

1. **Configure Slack Event Subscriptions**:
   - Copy this URL
   - Go to your Slack app settings > Event Subscriptions
   - Paste the URL in the "Request URL" field
   - Slack will verify the endpoint (you should see a green checkmark)

2. **Configure Slack Slash Commands**:
   - Go to your Slack app settings > Slash Commands
   - Use the same URL for the `/security-ir` command Request URL

3. **Test the Endpoint**:
   ```bash
   curl -X POST <SlackEventsApiEndpoint> \
     -H "Content-Type: application/json" \
     -d '{"type":"url_verification","challenge":"test123"}'
   ```

#### SlackClientLambdaArn

This output provides the ARN of the Slack Client Lambda function.

**How to use it for validation**:

1. **Verify Lambda Function**:
   ```bash
   aws lambda get-function --function-name <SlackClientLambdaArn>
   ```

2. **Check Lambda Logs**:
   ```bash
   FUNCTION_NAME=$(echo <SlackClientLambdaArn> | cut -d':' -f7)
   aws logs tail "/aws/lambda/$FUNCTION_NAME" --follow
   ```

3. **Monitor Invocations**:
   - Navigate to AWS Console > Lambda
   - Search for the function using the ARN
   - Check the "Monitor" tab for invocation metrics

#### SlackEventsBoltHandlerLambdaLogGroup

This output provides the CloudWatch Logs group name for the Slack Events Bolt Handler Lambda.

**How to use it**:

1. **View Recent Logs**:
   ```bash
   aws logs tail <SlackEventsBoltHandlerLambdaLogGroup> --follow
   ```

2. **Search for Errors**:
   ```bash
   aws logs filter-log-events \
     --log-group-name <SlackEventsBoltHandlerLambdaLogGroup> \
     --filter-pattern "ERROR" \
     --limit 20
   ```

3. **Create Metric Filter**:
   ```bash
   aws logs put-metric-filter \
     --log-group-name <SlackEventsBoltHandlerLambdaLogGroup> \
     --filter-name "SlackEventErrors" \
     --filter-pattern "ERROR" \
     --metric-transformations \
       metricName=ErrorCount,metricNamespace=SlackIntegration,metricValue=1
   ```

#### SlackCommandHandlerLambdaLogGroup

This output provides the CloudWatch Logs group name for the Slack Command Handler Lambda.

**How to use it**:

1. **Monitor Command Execution**:
   ```bash
   aws logs tail <SlackCommandHandlerLambdaLogGroup> --follow
   ```

2. **Track Command Usage**:
   ```bash
   aws logs filter-log-events \
     --log-group-name <SlackCommandHandlerLambdaLogGroup> \
     --filter-pattern "command" \
     --limit 50
   ```

### Validating Slack Configuration

#### Verify Slack App Installation

1. **Check App Status**:
   - Go to https://api.slack.com/apps
   - Select your app
   - Verify "Install App" shows "Installed to Workspace"

2. **Verify Bot Token**:
   - Go to "OAuth & Permissions"
   - Ensure "Bot User OAuth Token" is displayed
   - Token should start with `xoxb-`

3. **Verify Permissions**:
   - In "OAuth & Permissions", check "Scopes"
   - Ensure all required bot token scopes are present

#### Verify Event Subscriptions

1. **Check URL Verification**:
   - Go to "Event Subscriptions"
   - Verify Request URL shows a green checkmark
   - If not verified, check API Gateway and Lambda logs

2. **Verify Subscribed Events**:
   - Ensure the following events are subscribed:
     - `message.channels`
     - `message.groups`
     - `member_joined_channel`
     - `member_left_channel`
     - `file_shared`

#### Verify Slash Commands

1. **Check Command Configuration**:
   - Go to "Slash Commands"
   - Verify `/security-ir` command exists
   - Verify Request URL matches API Gateway endpoint

2. **Test Command in Slack**:
   - In any channel, type `/security-ir`
   - Command should autocomplete
   - Even without a case, it should be recognized

### Validating AWS Resources

#### Check DynamoDB Table

1. **Verify Table Exists**:
   ```bash
   aws dynamodb describe-table \
     --table-name <IncidentsTableName>
   ```

2. **Check Mapping Records**:
   ```bash
   aws dynamodb scan \
     --table-name <IncidentsTableName> \
     --filter-expression "attribute_exists(slackChannelId)"
   ```

#### Check SSM Parameters

1. **Verify Parameters Exist**:
   ```bash
   aws ssm get-parameter \
     --name /SecurityIncidentResponse/slackBotToken \
     --with-decryption
   
   aws ssm get-parameter \
     --name /SecurityIncidentResponse/slackSigningSecret \
     --with-decryption
   
   aws ssm get-parameter \
     --name /SecurityIncidentResponse/slackWorkspaceId
   ```

2. **Validate Parameter Formats**:
   ```bash
   python scripts/slack_parameter_setup.py validate
   ```

#### Check EventBridge Rules

1. **Verify Rules Exist**:
   ```bash
   aws events list-rules \
     --event-bus-name security-incident-event-bus
   ```

2. **Check Rule Targets**:
   ```bash
   aws events list-targets-by-rule \
     --rule slack-client-rule \
     --event-bus-name security-incident-event-bus
   ```

## Common Issues and Solutions

### Deployment Issues

#### Issue: CloudFormation Stack Fails to Deploy

**Symptoms**:
- CloudFormation stack creation fails
- Error message about parameter validation

**Possible Causes**:
- Invalid parameter format
- Missing required parameters
- Insufficient IAM permissions

**Solutions**:

1. **Verify Parameter Formats**:
   ```bash
   # Bot token should start with xoxb-
   echo "xoxb-YOUR-BOT-TOKEN" | grep -E '^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$'
   
   # Signing secret should be 32 hex characters
   echo "a1b2c3d4..." | grep -E '^[a-f0-9]{32}$'
   
   # Workspace ID should be 9-11 uppercase alphanumeric
   echo "T1234567890" | grep -E '^[A-Z0-9]{9,11}$'
   ```

2. **Check IAM Permissions**:
   - Ensure you have permissions to create CloudFormation stacks
   - Verify permissions for Lambda, API Gateway, EventBridge, DynamoDB, SSM

3. **Review CloudFormation Events**:
   ```bash
   aws cloudformation describe-stack-events \
     --stack-name AwsSecurityIncidentResponseSlackIntegrationStack \
     --max-items 20
   ```

#### Issue: Lambda Layer Deployment Fails

**Symptoms**:
- Stack deployment fails at Lambda layer creation
- Error about layer size or dependencies

**Solutions**:

1. **Check Layer Size**:
   - Lambda layers have a 250 MB unzipped size limit
   - Verify Slack Bolt dependencies are within limits

2. **Rebuild Layers**:
   ```bash
   cd assets/slack_bolt_layer
   pip install -r requirements.txt -t python/
   ```

### Slack Configuration Issues

#### Issue: Event Subscriptions URL Verification Fails

**Symptoms**:
- Slack shows "Your URL didn't respond with the value of the challenge parameter"
- Red X next to Request URL in Slack app settings

**Possible Causes**:
- API Gateway endpoint not accessible
- Lambda function not responding correctly
- Incorrect endpoint URL

**Solutions**:

1. **Test API Gateway Endpoint**:
   ```bash
   curl -X POST <SlackEventsApiEndpoint> \
     -H "Content-Type: application/json" \
     -d '{"type":"url_verification","challenge":"test123"}'
   ```
   Expected response: `{"challenge":"test123"}`

2. **Check Lambda Logs**:
   ```bash
   aws logs tail /aws/lambda/SlackEventsBoltHandler --follow
   ```

3. **Verify API Gateway Configuration**:
   - Go to AWS Console > API Gateway
   - Check that `/slack/events` route exists
   - Verify Lambda integration is configured

4. **Check Lambda Permissions**:
   - Ensure API Gateway has permission to invoke Lambda
   - Verify Lambda execution role has necessary permissions

#### Issue: Slash Commands Not Working

**Symptoms**:
- `/security-ir` command not recognized in Slack
- Command returns error or no response

**Possible Causes**:
- Command not configured in Slack app
- Incorrect Request URL
- Lambda function error

**Solutions**:

1. **Verify Command Configuration**:
   - Go to Slack app settings > Slash Commands
   - Ensure `/security-ir` exists
   - Verify Request URL matches API Gateway endpoint

2. **Test Command Manually**:
   - Use command in an incident channel
   - Check Slack Command Handler Lambda logs

3. **Check Lambda Timeout**:
   - Slash commands must respond within 3 seconds
   - Verify Lambda timeout is set appropriately

### Integration Issues

#### Issue: Slack Channel Not Created for New Case

**Symptoms**:
- AWS Security IR case created
- No corresponding Slack channel appears

**Possible Causes**:
- Slack Client Lambda not triggered
- Bot lacks channel creation permissions
- Invalid bot token

**Solutions**:

1. **Check EventBridge Rule**:
   ```bash
   aws events list-targets-by-rule \
     --rule slack-client-rule \
     --event-bus-name security-incident-event-bus
   ```

2. **Check Slack Client Lambda Logs**:
   ```bash
   aws logs tail /aws/lambda/SecurityIncidentResponseSlackClient --follow
   ```

3. **Verify Bot Permissions**:
   - Ensure bot has `channels:manage` scope
   - Check bot token is valid

4. **Test Bot Token**:
   ```bash
   curl -X POST https://slack.com/api/auth.test \
     -H "Authorization: Bearer <bot-token>"
   ```

#### Issue: Messages Not Syncing from Slack to AWS SIR

**Symptoms**:
- Messages posted in Slack channel
- Comments not appearing in AWS Security IR case

**Possible Causes**:
- Bot not member of channel
- Event Subscriptions not configured
- Lambda function error

**Solutions**:

1. **Verify Bot is Channel Member**:
   - Check channel members list
   - Invite bot if not present: `/invite @AWS Security IR Integration`

2. **Check Event Subscriptions**:
   - Verify `message.channels` event is subscribed
   - Check Request URL is verified

3. **Check Lambda Logs**:
   ```bash
   aws logs tail /aws/lambda/SlackEventsBoltHandler --follow
   ```

4. **Verify DynamoDB Mapping**:
   ```bash
   aws dynamodb get-item \
     --table-name <IncidentsTableName> \
     --key '{"PK":{"S":"Case#<caseId>"},"SK":{"S":"latest"}}'
   ```

#### Issue: Comments Not Syncing from AWS SIR to Slack

**Symptoms**:
- Comments added to AWS Security IR case
- Messages not appearing in Slack channel

**Possible Causes**:
- Missing `slackChannelId` in DynamoDB
- Slack Client Lambda not triggered
- Bot lacks message posting permissions

**Solutions**:

1. **Check DynamoDB Record**:
   ```bash
   aws dynamodb get-item \
     --table-name <IncidentsTableName> \
     --key '{"PK":{"S":"Case#<caseId>"},"SK":{"S":"latest"}}' \
     --query 'Item.slackChannelId'
   ```

2. **Verify EventBridge Events**:
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/events/security-incident-event-bus \
     --filter-pattern "Comment Added"
   ```

3. **Check Slack Client Lambda**:
   ```bash
   aws logs tail /aws/lambda/SecurityIncidentResponseSlackClient --follow
   ```

#### Issue: Attachments Not Syncing

**Symptoms**:
- Files uploaded to Slack or AWS SIR
- Attachments not appearing in the other system

**Possible Causes**:
- File size exceeds limits
- Bot lacks file permissions
- Lambda function error

**Solutions**:

1. **Check File Size**:
   - Slack free tier: 5 GB per file
   - AWS Security IR: Check service limits

2. **Verify Bot Permissions**:
   - Ensure bot has `files:read` and `files:write` scopes

3. **Check Lambda Logs**:
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/lambda/SlackEventsBoltHandler \
     --filter-pattern "file_shared"
   ```

### Authentication Issues

#### Issue: Slack API Returns "invalid_auth" Error

**Symptoms**:
- Lambda logs show "invalid_auth" error
- Slack operations fail

**Possible Causes**:
- Bot token expired or revoked
- Bot token not properly stored in SSM
- Bot not installed to workspace

**Solutions**:

1. **Verify Bot Token in SSM**:
   ```bash
   aws ssm get-parameter \
     --name /SecurityIncidentResponse/slackBotToken \
     --with-decryption \
     --query 'Parameter.Value'
   ```

2. **Test Bot Token**:
   ```bash
   curl -X POST https://slack.com/api/auth.test \
     -H "Authorization: Bearer <bot-token>"
   ```

3. **Regenerate and Rotate Token**:
   - Go to Slack app settings > OAuth & Permissions
   - Click "Regenerate" under Bot User OAuth Token
   - Update SSM parameter:
     ```bash
     python scripts/slack_parameter_setup.py rotate \
       --bot-token "<new-token>" \
       --signing-secret "<signing-secret>" \
       --workspace-id "<workspace-id>"
     ```

#### Issue: Webhook Signature Verification Fails

**Symptoms**:
- Lambda logs show signature verification errors
- Slack events not processed

**Possible Causes**:
- Incorrect signing secret in SSM
- Clock skew between systems
- Request replay attack prevention

**Solutions**:

1. **Verify Signing Secret**:
   ```bash
   aws ssm get-parameter \
     --name /SecurityIncidentResponse/slackSigningSecret \
     --with-decryption
   ```

2. **Check Signing Secret in Slack**:
   - Go to Slack app settings > Basic Information
   - Compare with SSM parameter value

3. **Update Signing Secret**:
   ```bash
   python scripts/slack_parameter_setup.py rotate \
     --bot-token "<bot-token>" \
     --signing-secret "<new-secret>" \
     --workspace-id "<workspace-id>"
   ```

## Diagnostic Steps

### End-to-End Testing

#### Test 1: AWS SIR to Slack Flow

1. **Create Test Case**:
   ```bash
   aws security-ir create-case \
     --title "Test Case for Slack Integration" \
     --description "Testing bidirectional sync" \
     --severity "Medium"
   ```

2. **Verify Channel Creation**:
   - Check Slack for new channel: `aws-security-incident-response-case-<caseId>`
   - Verify initial notification posted

3. **Check Logs**:
   ```bash
   aws logs tail /aws/lambda/SecurityIncidentResponseSlackClient --follow
   ```

4. **Verify DynamoDB**:
   ```bash
   aws dynamodb scan \
     --table-name <IncidentsTableName> \
     --filter-expression "attribute_exists(slackChannelId)"
   ```

#### Test 2: Slack to AWS SIR Flow

1. **Post Message in Channel**:
   - Go to incident channel in Slack
   - Post a test message

2. **Verify Comment in AWS SIR**:
   ```bash
   aws security-ir list-comments --case-id <caseId>
   ```

3. **Check Logs**:
   ```bash
   aws logs tail /aws/lambda/SlackEventsBoltHandler --follow
   ```

#### Test 3: Slash Commands

1. **Test Status Command**:
   - In incident channel, type: `/security-ir status`
   - Verify response with case details

2. **Test Update Command**:
   - Type: `/security-ir update-status Investigating`
   - Verify case status updated in AWS SIR

3. **Check Logs**:
   ```bash
   aws logs tail /aws/lambda/SlackCommandHandler --follow
   ```

### Performance Testing

#### Monitor Lambda Performance

1. **Check Execution Duration**:
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/Lambda \
     --metric-name Duration \
     --dimensions Name=FunctionName,Value=SecurityIncidentResponseSlackClient \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 300 \
     --statistics Average,Maximum
   ```

2. **Check Error Rate**:
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/Lambda \
     --metric-name Errors \
     --dimensions Name=FunctionName,Value=SecurityIncidentResponseSlackClient \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 300 \
     --statistics Sum
   ```

#### Monitor API Gateway Performance

1. **Check API Latency**:
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/ApiGateway \
     --metric-name Latency \
     --dimensions Name=ApiName,Value=SlackEventsApi \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 300 \
     --statistics Average,Maximum
   ```

2. **Check API Errors**:
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/ApiGateway \
     --metric-name 5XXError \
     --dimensions Name=ApiName,Value=SlackEventsApi \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 300 \
     --statistics Sum
   ```

## Checklist in case of any errors

- [ ] Check Lambda error rates in CloudWatch
- [ ] Review CloudWatch Logs for pattern
- [ ] Review CloudWatch alarms

## Security Considerations

### Credential Management

1. **Regular Rotation**:
   - Rotate bot token every 90 days
   - Rotate signing secret every 90 days
   - Use parameter rotation script

2. **Access Control**:
   - Limit SSM parameter access to specific IAM roles
   - Use resource-specific IAM policies
   - Enable CloudTrail logging for parameter access

3. **Monitoring**:
   - Set up CloudWatch alarms for unauthorized access
   - Review CloudTrail logs regularly
   - Monitor for unusual API activity

### Network Security

1. **API Gateway**:
   - Enable request validation
   - Configure rate limiting
   - Use AWS WAF for additional protection

2. **Lambda Functions**:
   - Deploy in VPC if required
   - Use security groups and NACLs
   - Enable VPC Flow Logs

### Data Protection

1. **Encryption**:
   - All SSM parameters use SecureString with KMS
   - DynamoDB encryption at rest enabled
   - TLS for all API communications

2. **Data Handling**:
   - Never log sensitive data (tokens, passwords, PII)
   - Sanitize user input
   - Implement proper error handling

### Compliance

1. **Audit Trail**:
   - CloudTrail logs all API calls
   - CloudWatch Logs retain for compliance period
   - DynamoDB point-in-time recovery enabled

2. **Access Logging**:
   - API Gateway access logs enabled
   - Lambda execution logs enabled
   - EventBridge event logging enabled

## Performance Optimization

### Lambda Optimization

1. **Memory Allocation**:
   - Slack Client: 512 MB (recommended)
   - Events Handler: 512 MB (recommended)
   - Command Handler: 256 MB (recommended)

2. **Timeout Configuration**:
   - Slack Client: 15 minutes (for large attachments)
   - Events Handler: 30 seconds (Slack requirement)
   - Command Handler: 30 seconds (Slack requirement)

3. **Cold Start Mitigation**:
   - Use provisioned concurrency for critical functions
   - Optimize package size
   - Use Lambda layers for shared dependencies

### DynamoDB Optimization

1. **Capacity Planning**:
   - Use on-demand billing for variable workloads
   - Monitor consumed capacity
   - Set up auto-scaling if using provisioned capacity

2. **Query Optimization**:
   - Use efficient key design (PK/SK pattern)
   - Create GSIs for common query patterns
   - Use consistent reads only when necessary

### API Gateway Optimization

1. **Caching**:
   - Enable caching for GET requests if applicable
   - Set appropriate TTL values

2. **Throttling**:
   - Configure appropriate throttle limits
   - Use usage plans for different consumers

## Advanced Troubleshooting

### Enable Debug Logging

1. **Redeploy with Debug Logging**:
   ```bash
   ./deploy-integrations-solution.py slack \
     --bot-token "<bot-token>" \
     --signing-secret "<signing-secret>" \
     --workspace-id "<workspace-id>" \
     --log-level debug
   ```

2. **View Debug Logs**:
   ```bash
   aws logs tail /aws/lambda/SecurityIncidentResponseSlackClient \
     --follow \
     --filter-pattern "DEBUG"
   ```

### Trace Requests with Correlation IDs

1. **Find Correlation ID in Logs**:
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/lambda/SlackEventsBoltHandler \
     --filter-pattern "correlation_id"
   ```

2. **Trace Across Services**:
   - Use correlation ID to trace request through Lambda, EventBridge, DynamoDB

### Analyze Dead Letter Queues

1. **Check DLQ Messages**:
   ```bash
   aws sqs receive-message \
     --queue-url <DLQ-URL> \
     --max-number-of-messages 10
   ```

2. **Reprocess Failed Events**:
   - Analyze failure reason
   - Fix underlying issue
   - Manually reprocess or redrive messages

## Getting Help

### Support Resources

1. **AWS Support**:
   - Open a support case in AWS Console
   - Include CloudFormation stack name and error details

2. **Slack API Support**:
   - Visit https://api.slack.com/support
   - Check Slack API status page

3. **Community Resources**:
   - AWS Security Incident Response documentation
   - Slack Bolt framework documentation
   - GitHub issues and discussions

### Collecting Diagnostic Information

When requesting support, collect:

1. **CloudFormation Stack Details**:
   ```bash
   aws cloudformation describe-stacks \
     --stack-name AwsSecurityIncidentResponseSlackIntegrationStack
   ```

2. **Lambda Function Logs**:
   ```bash
   aws logs tail /aws/lambda/SecurityIncidentResponseSlackClient \
     --since 1h > slack-client-logs.txt
   ```

3. **EventBridge Metrics**:
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/Events \
     --metric-name FailedInvocations \
     --dimensions Name=RuleName,Value=slack-client-rule \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 300 \
     --statistics Sum
   ```

4. **DynamoDB Table Status**:
   ```bash
   aws dynamodb describe-table \
     --table-name <IncidentsTableName>
   ```

## Related Resources

- [Slack Integration Setup Guide](SLACK.md)
- [Slack Parameter Management Guide](SLACK_PARAMETER_MANAGEMENT.md)
- [AWS Security Incident Response Documentation](https://docs.aws.amazon.com/security-incident-response/)
- [Slack API Documentation](https://api.slack.com/)
- [AWS Lambda Troubleshooting](https://docs.aws.amazon.com/lambda/latest/dg/lambda-troubleshooting.html)
- [Amazon EventBridge Troubleshooting](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-troubleshooting.html)

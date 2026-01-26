# AWS Security Incident Response Jira Integration - Troubleshooting Guide

This document provides detailed information on setup, configuration, validation, troubleshooting, and security considerations for the AWS Security Incident Response Jira integration.

## Table of Contents

- [Setup and Configuration](#setup-and-configuration)
- [Outputs and Validation](#outputs-and-validation)
  - [Using CloudFormation Outputs](#using-cloudformation-outputs)
  - [Validating Jira Configuration](#validating-jira-configuration)
- [Troubleshooting](#troubleshooting)
  - [Common Issues and Solutions](#common-issues-and-solutions)
  - [Diagnostic Steps](#diagnostic-steps)
- [Security Considerations](#security-considerations)

## Setup and Configuration

### Deployment Steps Summary

1. **Prepare Jira**:
   - Create an API token as described in the Prerequisites section
   - Identify your Jira URL and project key

2. **Deploy the Stack**:
   ```bash
   # Using the deploy_integrations_solution script
   deploy_integrations_solution jira \
     --email <your-jira-email> \
     --url <your-jira-url> \
     --token <your-jira-api-token> \
     --project-key <your-jira-project-key> \
     --log-level {info, debug, error}
   ```
   
   Note: The `--log-level` parameter is optional and defaults to `error`. Valid values are `info`, `debug`, and `error`.

3. **Configure Jira Automation**:
   - Use the SNS topic ARN from the CloudFormation outputs
   - Set up automation rules in Jira to send events to the SNS topic

4. **Verify the Setup**:
   - Check CloudFormation outputs for the Lambda ARNs and log group URLs
   - Create a test case in AWS Security Incident Response
   - Verify that an issue is created in your Jira project

5. **Test the Integration**:
   - Update the issue in Jira and verify the changes appear in AWS Security Incident Response
   - Update the case in AWS Security Incident Response and verify the changes appear in Jira

## Outputs and Validation

After deploying the stack, you'll receive CloudFormation outputs that can be used to validate and troubleshoot the integration.

### Using CloudFormation Outputs

#### JiraClientLambdaArn

This output provides the ARN of the Jira Client Lambda function.

> **Note**: The SNS topic ARN for Jira notifications is not provided as a CloudFormation output. You'll need to find it in the AWS Console under SNS > Topics > JiraNotificationsTopic after deployment. This ARN is needed to configure Jira automation rules.

**How to use it for validation:**

1. **Verify Lambda Function Existence:**
   ```bash
   aws lambda get-function --function-name <JiraClientLambdaArn>
   ```

2. **Check Lambda Logs:**
   ```bash
   # Get the function name from the ARN
   FUNCTION_NAME=$(echo <JiraClientLambdaArn> | cut -d':' -f7)
   aws logs filter-log-events --log-group-name "/aws/lambda/$FUNCTION_NAME" --limit 10
   ```

3. **Monitor Function Invocations:**
   - Navigate to the Lambda console
   - Search for the function using the ARN
   - Check the monitoring tab to see invocation metrics

#### JiraNotificationsHandlerLambdaLogGroup

This output provides the name of the CloudWatch Logs group for the Jira Notifications Handler Lambda.

**How to use it for validation:**

1. **Check Lambda Logs:**
   ```bash
   aws logs filter-log-events --log-group-name <JiraNotificationsHandlerLambdaLogGroup> --limit 10
   ```

2. **Set Up Log Metrics:**
   ```bash
   aws logs put-metric-filter \
     --log-group-name <JiraNotificationsHandlerLambdaLogGroup> \
     --filter-name "ErrorCount" \
     --filter-pattern "ERROR" \
     --metric-transformations \
       metricName=ErrorCount,metricNamespace=JiraIntegration,metricValue=1
   ```

#### JiraNotificationsHandlerLambdaLogGroupUrl

This output provides a direct URL to the CloudWatch Logs for the Jira Notifications Handler Lambda.

**How to use it for validation:**

1. Open the URL in your browser to directly access the logs
2. Filter logs by time range or search for specific terms like "ERROR" or "SUCCESS"
3. Use this URL for quick troubleshooting when issues occur

### Validating Jira Configuration

To validate the Jira automation configuration:

1. **Verify Automation Rules:**
   - Navigate to your Jira project
   - Go to Project settings > Automation
   - Check that your rules for creating, updating, and deleting issues are active
   - Verify that the AWS SNS trigger is configured with the correct SNS topic ARN

2. **Test Issue Creation:**
   - Create a test issue in your Jira project
   - Check the Jira Notifications Handler Lambda logs to verify it received the event
   - Verify that a corresponding case was created in AWS Security Incident Response

3. **Test Issue Updates:**
   - Update a test issue in Jira
   - Check the logs to verify the update was processed
   - Verify that the changes appear in AWS Security Incident Response

## Troubleshooting

### Common Issues and Solutions

1. **Jira API Token Issues**:
   - Check that the API token is valid and not expired
   - Verify the email address matches the one used to create the token
   - Try creating a new token if necessary

2. **Events Not Flowing from Jira to AWS**:
   - Verify the Jira automation rules are correctly configured
   - Check the SNS topic policy allows the Jira AWS account to publish
   - Examine CloudWatch Logs for the Jira Notifications Handler Lambda
   - Verify the SNS topic ARN in Jira automation matches the deployed topic

3. **Events Not Flowing from AWS to Jira**:
   - Check CloudWatch Logs for the Jira Client Lambda
   - Verify the Jira API is accessible from AWS
   - Ensure the Jira credentials are still valid
   - Check EventBridge for event delivery status

4. **Issue Mapping Issues**:
   - Examine the DynamoDB table for issue mapping information
   - Verify that issue IDs are being correctly stored and retrieved
   - Check for duplicate entries or missing mappings

### Diagnostic Steps

1. Create a test case in AWS Security Incident Response and monitor the logs
2. Create a test issue in Jira and monitor the logs
3. Verify EventBridge events are being properly routed
4. Examine DynamoDB for proper issue mapping

## Security Considerations

- All credentials are stored securely in SSM Parameter Store
- IAM roles follow the principle of least privilege
- SNS topic is configured with appropriate access policies
- CloudWatch logging is enabled for all Lambda functions
- Jira API token should be rotated regularly
"""Constants for AWS Security Incident Response Sample Integrations.

This module contains all the constants used across the integration components,
including AWS account IDs, event sources, and integration-specific constants.
"""

# JIRA Account ID/Service Principal for creating an SNS topic that receives notifications/events from JIRA
# see the detailed documentation here - https://support.atlassian.com/cloud-automation/docs/configure-aws-sns-for-jira-automation/
JIRA_AWS_ACCOUNT_ID = "815843069303"
JIRA_AUTOMATION_ROLE_ARN = "arn:aws:sts::815843069303:assumed-role/atlassian-automation-prod-outgoing/automation-sns-publish-action"
SERVICE_NOW_AWS_ACCOUNT_ID = "XXXXXXXXXXXX"

# Event sources
JIRA_EVENT_SOURCE = "jira"
SERVICE_NOW_EVENT_SOURCE = "service-now"
SECURITY_IR_EVENT_SOURCE = "security-ir"

# Integration target constants
JIRA_ISSUE_TYPE = "Task"

# ServiceNow automation constants

"""Constants for AWS Security Incident Response Sample Integrations.

This module contains all the constants used across the integration components,
including AWS account IDs, event sources, and integration-specific constants.
"""

from aws_cdk.aws_lambda import Runtime
from aws_cdk import Duration

# Generic Lambda Constants
PYTHON_LAMBDA_RUNTIME = Runtime.PYTHON_3_13
DEFAULT_LAMBDA_TIMEOUT = Duration.minutes(15) # Max Timeout for Lambda

# API Gateway Constants
API_GATEWAY_LAMBDA_HANDLER_TIMEOUT = DEFAULT_LAMBDA_TIMEOUT
SECRET_ROTATION_LAMBDA_TIMEOUT = Duration.minutes(5) # Secrets Rotation may need to connect to an integration target to persist secret and persist it locally.
API_GATEWAY_AUTHORIZOR_TIMEOUT = Duration.seconds(29) # The default timeout for a regional API Gateway Endpoint is 29 seconds.


# JIRA Account ID/Service Principal for creating an SNS topic that receives notifications/events from JIRA
# see the detailed documentation here - https://support.atlassian.com/cloud-automation/docs/configure-aws-sns-for-jira-automation/
JIRA_AWS_ACCOUNT_ID = "815843069303"
JIRA_AUTOMATION_ROLE_ARN = "arn:aws:sts::815843069303:assumed-role/atlassian-automation-prod-outgoing/automation-sns-publish-action"
SERVICE_NOW_AWS_ACCOUNT_ID = "XXXXXXXXXXXX"

# Event sources
JIRA_EVENT_SOURCE = "jira"
SERVICE_NOW_EVENT_SOURCE = "service-now"
SLACK_EVENT_SOURCE = "slack"
SECURITY_IR_EVENT_SOURCE = "security-ir"

# Integration target constants
JIRA_ISSUE_TYPE = "Task"

# Slack integration constants
SLACK_CHANNEL_PREFIX = "aws-security-incident-response-case-"
SLACK_SYSTEM_COMMENT_TAG = "[Slack Update]"
SLACK_MAX_RETRIES = 5
SLACK_INITIAL_RETRY_DELAY = 1  # seconds
SLACK_MAX_RETRY_DELAY = 60  # seconds

# Slack API and Bolt framework constants
# These are SSM parameter paths, not actual secrets - safe to ignore B105 warnings
# TODO: Reconsider while working on the slack cdk story (add link to the story when available)
SLACK_BOT_TOKEN_PARAMETER = "/SecurityIncidentResponse/slackBotToken"  # nosec
SLACK_SIGNING_SECRET_PARAMETER = "/SecurityIncidentResponse/slackSigningSecret"  # nosec
SLACK_APP_TOKEN_PARAMETER = "/SecurityIncidentResponse/slackAppToken"  # nosec
SLACK_CLIENT_ID_PARAMETER = "/SecurityIncidentResponse/slackClientId"
SLACK_CLIENT_SECRET_PARAMETER = "/SecurityIncidentResponse/slackClientSecret"  # nosec

# Slack file upload limits
SLACK_MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB limit for AWS SIR attachments
SLACK_SUPPORTED_FILE_TYPES = [
    "pdf", "doc", "docx", "txt", "rtf", "odt",
    "jpg", "jpeg", "png", "gif", "bmp", "tiff",
    "zip", "tar", "gz", "7z", "rar",
    "csv", "xls", "xlsx", "json", "xml", "log"
]

# Slack channel and message limits
SLACK_MAX_CHANNEL_NAME_LENGTH = 21
SLACK_MAX_MESSAGE_LENGTH = 4000
SLACK_MAX_BLOCKS_PER_MESSAGE = 50
SLACK_MAX_USERS_PER_INVITE = 1000

# Slack event types (only events actually used by the integration)
SLACK_EVENT_MESSAGE = "message"
SLACK_EVENT_FILE_SHARED = "file_shared"
SLACK_EVENT_MEMBER_JOINED = "member_joined_channel"
SLACK_EVENT_MEMBER_LEFT = "member_left_channel"
# Note: channel_created, channel_deleted, channel_rename events are not needed
# because the solution creates/manages channels itself for AWS Security IR cases

# Slack command constants
SLACK_COMMAND_PREFIX = "/security-ir"
SLACK_COMMAND_HELP = "help"
SLACK_COMMAND_STATUS = "status"
SLACK_COMMAND_UPDATE = "update"
SLACK_COMMAND_CLOSE = "close"
SLACK_COMMAND_REOPEN = "reopen"
SLACK_COMMAND_ASSIGN = "assign"
SLACK_COMMAND_WATCHERS = "watchers"
SLACK_COMMAND_SUMMARY = "summary"

# ServiceNow automation constants

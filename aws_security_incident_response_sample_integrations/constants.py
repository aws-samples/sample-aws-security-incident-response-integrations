# aws_security_incident_response_sample_integrations/constants.py

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

# Slack event types
SLACK_EVENT_MESSAGE = "message"
SLACK_EVENT_FILE_SHARED = "file_shared"
SLACK_EVENT_MEMBER_JOINED = "member_joined_channel"
SLACK_EVENT_MEMBER_LEFT = "member_left_channel"
SLACK_EVENT_CHANNEL_CREATED = "channel_created"
SLACK_EVENT_CHANNEL_DELETED = "channel_deleted"
SLACK_EVENT_CHANNEL_RENAMED = "channel_rename"

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

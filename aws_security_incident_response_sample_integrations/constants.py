# aws_security_incident_response_sample_integrations/constants.py

# JIRA Account ID/Service Principal for creating an SNS topic that receives notifications/events from JIRA
# see the detailed documentation here - https://support.atlassian.com/cloud-automation/docs/configure-aws-sns-for-jira-automation/
JIRA_AWS_ACCOUNT_ID = "815843069303"
SERVICE_NOW_AWS_ACCOUNT_ID = "XXXXXXXXXXXX"

# Event sources
JIRA_EVENT_SOURCE = "jira"
SERVICE_NOW_EVENT_SOURCE = "service-now"
SECURITY_IR_EVENT_SOURCE = "security-ir"

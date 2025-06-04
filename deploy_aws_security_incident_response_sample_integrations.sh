#!/bin/bash

# TODO: convert this to Python script instead
chmod +x deploy_aws_security_incident_response_sample_integrations.sh

# Ask for initial parameter
echo "Please select integration type (jira/service-now):"
read integration_type

# Validate initial input
while [[ "$integration_type" != "jira" && "$integration_type" != "service-now" ]]; do
  echo "Invalid input. Please enter 'jira' or 'service-now':"
  read integration_type
done

# Ask for common parameters
echo "Enter log level (info/debug/error):"
read log_level

# Ask for integration-specific parameters
if [[ "$integration_type" == "jira" ]]; then
  echo "Enter Jira email:"
  read jira_email
  
  echo "Enter Jira URL:"
  read jira_url
  
  echo "Enter Jira API token:"
  read -s jira_token
  echo
  
  echo "Configuration summary:"
  echo "Integration: $integration_type"
  echo "Log level: $log_level"
  echo "Jira email: $jira_email"
  echo "Jira URL: $jira_url"
  echo "Jira token: [HIDDEN]"

  echo "Do you want to proceed with deployment? (y/n)"
  read confirm
  
  if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    echo "Deploying with Jira integration..."
    npx cdk deploy --app "python app_jira.py" \
                  "AwsSecurityIncidentResponseSampleIntegrationsCommonStack" \
                  "AwsSecurityIncidentResponseJiraIntegrationStack" \
                  --parameters AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel=$log_level \
                  --parameters AwsSecurityIncidentResponseJiraIntegrationStack:jiraEmail=$jira_email \
                  --parameters AwsSecurityIncidentResponseJiraIntegrationStack:jiraUrl=$jira_url \
                  --parameters AwsSecurityIncidentResponseJiraIntegrationStack:jiraToken=$jira_token
  else
    echo "Deployment cancelled."
  fi
  
elif [[ "$integration_type" == "service-now" ]]; then
  echo "Enter ServiceNow instance ID:"
  read servicenow_instance
  
  echo "Enter ServiceNow username:"
  read servicenow_user
  
  echo "Enter ServiceNow password:"
  read -s servicenow_password
  echo
  
  echo "Configuration summary:"
  echo "Integration: $integration_type"
  echo "Log level: $log_level"
  echo "ServiceNow instance: $servicenow_instance"
  echo "ServiceNow user: $servicenow_user"
  echo "ServiceNow password: [HIDDEN]"

  echo "Do you want to proceed with deployment? (y/n)"
  read confirm
  
  if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
    echo "Deploying with ServiceNow integration..."
    echo "Service Now integration is under development/maintenance...Please wait for its release"
    # TODO: enable the below commented code for cdk deploy of Service Now integration once the implementation is complete
    # npx cdk deploy --app "python app_service_now.py" \
    #               "AwsSecurityIncidentResponseSampleIntegrationsCommonStack" \
    #               "AwsSecurityIncidentResponseServiceNowIntegrationStack" \
    #               --parameters AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel=$log_level \
    #               --parameters AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowInstanceId=$servicenow_instance \
    #               --parameters AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowUser=$servicenow_user \
    #               --parameters AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowPassword=$servicenow_password
  else
    echo "Deployment cancelled."
  fi
fi
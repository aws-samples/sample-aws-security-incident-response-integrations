#!/usr/bin/env python3

import argparse
import sys
import os
import shutil

def get_npx_path():
    # Find the full path to npx executable
    npx_path = shutil.which("npx")
    if not npx_path:
        print("Error: 'npx' command not found. Please ensure Node.js and npm are installed.")
        sys.exit(1)
    return npx_path

def deploy_jira(args):
    # Use os.execv with full path which replaces the current process instead of spawning a shell
    # This is safer as it doesn't involve shell interpretation or path searching
    npx_path = get_npx_path()
    cmd = [
        npx_path, "cdk", "deploy",
        "--app", "python app_jira.py",
        "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
        "AwsSecurityIncidentResponseJiraIntegrationStack",
        "--parameters", f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
        "--parameters", f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraEmail={args.email}",
        "--parameters", f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraUrl={args.url}",
        "--parameters", f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraToken={args.token}"
    ]
    os.execv(npx_path, cmd)  # nosec B606
    # Bandit security scanner is flagging a warning about starting a process without a shell (B606), but this is actually a safer approach for our use case.
    # The warning is a false positive because:
    # 1. We're intentionally avoiding shell execution to prevent command injection vulnerabilities
    # 2. Using os.execv() with full paths is a security best practice for this scenario
    # 3. The warning is Low severity and Medium confidence

def deploy_servicenow(args):
    print("Service Now integration is under development/maintenance...Please wait for its release")
    # TODO: enable the below commented out code for cdk deploy of Service Now integration once the implementation is complete
    # npx_path = get_npx_path()
    # cmd = [
    #     npx_path, "cdk", "deploy",
    #     "--app", "python app_service_now.py",
    #     "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
    #     "AwsSecurityIncidentResponseServiceNowIntegrationStack",
    #     "--parameters", f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
    #     "--parameters", f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowInstanceId={args.instance_id}",
    #     "--parameters", f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowUser={args.username}",
    #     "--parameters", f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowPassword={args.password}"
    # ]
    # os.execv(npx_path, cmd)  # nosec B606
    # Bandit security scanner is flagging a warning about starting a process without a shell (B606), but this is actually a safer approach for our use case.
    # The warning is a false positive because:
    # 1. We're intentionally avoiding shell execution to prevent command injection vulnerabilities
    # 2. Using os.execv() with full paths is a security best practice for this scenario
    # 3. The warning is Low severity and Medium confidence

def main():
    parser = argparse.ArgumentParser(description='Deploy AWS Security Incident Response Sample Integrations')
    subparsers = parser.add_subparsers(dest='integration', help='Integration type')
    
    # Common parameters
    parser.add_argument('--log-level', choices=['info', 'debug', 'error'], default='error',
                        help='Log level for Lambda functions')
    
    # Jira integration
    jira_parser = subparsers.add_parser('jira', help='Deploy Jira integration')
    jira_parser.add_argument('--email', required=True, help='Jira email')
    jira_parser.add_argument('--url', required=True, help='Jira URL')
    jira_parser.add_argument('--token', required=True, help='Jira API token')
    jira_parser.set_defaults(func=deploy_jira)
    
    # ServiceNow integration
    servicenow_parser = subparsers.add_parser('service-now', help='Deploy ServiceNow integration')
    servicenow_parser.add_argument('--instance-id', required=True, help='ServiceNow instance ID')
    servicenow_parser.add_argument('--username', required=True, help='ServiceNow username')
    servicenow_parser.add_argument('--password', required=True, help='ServiceNow password')
    servicenow_parser.set_defaults(func=deploy_servicenow)
    
    args = parser.parse_args()
    
    if not args.integration:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)

if __name__ == '__main__':
    main()
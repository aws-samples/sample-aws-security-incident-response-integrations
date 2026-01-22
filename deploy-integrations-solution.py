#!/usr/bin/env python3
"""Deployment script for AWS Security Incident Response Sample Integrations.

This script provides a command-line interface for deploying Jira and ServiceNow
integrations with AWS Security Incident Response. It handles CDK deployment
with proper parameter passing for different integration types.

Usage:
    ./deploy-integrations-solution.py jira --email user@example.com --url https://example.atlassian.net --token TOKEN --project-key PROJ
    ./deploy-integrations-solution.py service-now --instance-id example --username admin --password PASSWORD --integration-module itsm
"""

import argparse
import subprocess  # nosec B404
import sys
import textwrap
import boto3
import os


def deploy_jira(args):
    """Deploy Jira integration using CDK.

    Args:
        args: Parsed command line arguments containing Jira configuration

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    try:
        cmd = [
            "npx",
            "cdk",
            "deploy",
            "--app",
            "python3 app.py",
            "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
            "AwsSecurityIncidentResponseJiraIntegrationStack",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraEmail={args.email}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraUrl={args.url}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraToken={args.token}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraProjectKey={args.project_key}",
        ]
        print("\n🔄 Deploying Jira integration...\n")
        # Using subprocess with a list of arguments is safe from shell injection
        result = subprocess.run(cmd, check=True)  # nosec B603
        if result.returncode == 0:
            print("\n✅ Jira integration deployed successfully!")
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error deploying Jira integration: {e}")
        return e.returncode
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


def deploy_servicenow(args):
    """Deploy ServiceNow integration using CDK.

    Args:
        args: Parsed command line arguments containing ServiceNow configuration

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    try:
        # Upload private key to S3 before deployment
        if not os.path.exists(args.private_key_path):
            print(f"\n❌ Error: Private key file not found: {args.private_key_path}")
            return 1
            
        # Create S3 client and upload private key
        s3_client = boto3.client('s3')
        account = boto3.client('sts').get_caller_identity()['Account']
        bucket_name = f"snow-key-{account}"
        
        try:
            s3_client.create_bucket(Bucket=bucket_name)
            print(f"\n📦 Created S3 bucket: {bucket_name}")
        except s3_client.exceptions.BucketAlreadyOwnedByYou:
            print(f"\n📦 Using existing S3 bucket: {bucket_name}")
        except Exception as e:
            print(f"\n❌ Error creating S3 bucket: {e}")
            return 1
            
        # Upload private key file
        try:
            s3_client.upload_file(args.private_key_path, bucket_name, 'private.key')
            print(f"\n🔑 Uploaded private key to s3://{bucket_name}/private.key")
        except Exception as e:
            print(f"\n❌ Error uploading private key: {e}")
            return 1
        cmd = [
            "npx",
            "cdk",
            "deploy",
            "--app",
            "python3 app_service_now.py",
            "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
            "AwsSecurityIncidentResponseServiceNowIntegrationStack",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:integrationModule={args.integration_module}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowInstanceId={args.instance_id}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowClientId={args.client_id}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowClientSecret={args.client_secret}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowUserId={args.user_id}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:privateKeyBucket={bucket_name}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:integrationModule={args.integration_module}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:useOAuth={'true' if getattr(args, 'use_oauth', False) else 'false'}",
        ]
        print("\n🔄 Deploying ServiceNow integration...\n")
        # Using subprocess with a list of arguments is safe from shell injection
        result = subprocess.run(cmd, check=True)  # nosec B603
        if result.returncode == 0:
            print("\n✅ ServiceNow integration deployed successfully!")
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error deploying ServiceNow integration: {e}")
        return e.returncode
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


def deploy_slack(args):
    try:
        cmd = [
            "npx",
            "cdk",
            "deploy",
            "--app",
            "python3 app_slack.py",
            "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
            "AwsSecurityIncidentResponseSlackIntegrationStack",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
            "--parameters",
            f"AwsSecurityIncidentResponseSlackIntegrationStack:slackBotToken={args.bot_token}",
            "--parameters",
            f"AwsSecurityIncidentResponseSlackIntegrationStack:slackSigningSecret={args.signing_secret}",
            "--parameters",
            f"AwsSecurityIncidentResponseSlackIntegrationStack:slackWorkspaceId={args.workspace_id}",
        ]
        print("\n🔄 Deploying Slack integration...\n")
        # Using subprocess with a list of arguments is safe from shell injection
        result = subprocess.run(cmd, check=True)  # nosec B603
        if result.returncode == 0:
            print("\n✅ Slack integration deployed successfully!")
            
            # Run deployment verification if requested
            if not args.skip_verification:
                print("\n🔍 Running deployment verification...")
                verify_cmd = [
                    "python3",
                    "scripts/verify_slack_deployment.py",
                    "--region",
                    args.region if hasattr(args, 'region') and args.region else "us-east-1",
                ]
                verify_result = subprocess.run(verify_cmd)  # nosec B603
                if verify_result.returncode != 0:
                    print("\n⚠️  Deployment verification found some issues. Please review the output above.")
            else:
                print("\n📝 Next steps:")
                print("   1. Run verification: python3 scripts/verify_slack_deployment.py")
                print("   2. Configure your Slack app's Event Subscriptions URL with the API Gateway endpoint")
                print("   3. Configure your Slack app's Slash Commands with the /security-ir command")
                print("   4. Install the Slack app to your workspace")
                print("   5. Test the integration by creating a test AWS Security IR case")
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error deploying Slack integration: {e}")
        return e.returncode
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


def main():
    """Main function to parse arguments and deploy integrations."""
    parser = argparse.ArgumentParser(
        description="Deploy AWS Security Incident Response Sample Integrations"
    )

    # Add global log-level argument
    parser.add_argument(
        "--log-level",
        choices=["info", "debug", "error"],
        default="error",
        help="Log level for Lambda functions",
    )

    subparsers = parser.add_subparsers(dest="integration", help="Integration type")

    # Jira integration
    jira_parser = subparsers.add_parser("jira", help="Deploy Jira integration")
    jira_parser.add_argument("--email", required=True, help="Jira email")
    jira_parser.add_argument("--url", required=True, help="Jira URL")
    jira_parser.add_argument("--token", required=True, help="Jira API token")
    jira_parser.add_argument("--project-key", required=True, help="Jira Project key")
    jira_parser.add_argument(
        "--log-level",
        choices=["info", "debug", "error"],
        help="Log level for Lambda functions (overrides global setting)",
    )
    jira_parser.set_defaults(func=deploy_jira)

    # ServiceNow integration
    servicenow_parser = subparsers.add_parser(
        "service-now", help="Deploy ServiceNow integration"
    )
    servicenow_parser.add_argument(
        "--instance-id", required=True, help="ServiceNow instance ID"
    )
    servicenow_parser.add_argument(
        "--client-id", required=True, help="ServiceNow OAuth client ID"
    )
    servicenow_parser.add_argument(
        "--client-secret", required=True, help="ServiceNow OAuth client secret"
    )
    servicenow_parser.add_argument(
        "--user-id", required=True, help="ServiceNow user ID for JWT authentication"
    )
    servicenow_parser.add_argument(
        "--private-key-path", required=True, help="Local path to private key file (e.g., ./private.key)"
    )
    servicenow_parser.add_argument(
        "--integration-module",
        choices=["itsm", "ir"],
        required=True,
        help="ServiceNow integration module: 'itsm' for IT Service Management or 'ir' for Incident Response",
    )
    # TODO: Enable when ready to publish OAuth 2 Authentication for API Gateway
    # servicenow_parser.add_argument(
    #     "--use-oauth",
    #     action="store_true",
    #     default=False,
    #     help="Use OAuth for API Gateway authentication instead of token-based auth (not yet implemented)",
    # )
    servicenow_parser.add_argument(
        "--log-level",
        choices=["info", "debug", "error"],
        help="Log level for Lambda functions (overrides global setting)",
    )
    servicenow_parser.set_defaults(func=deploy_servicenow)

    # Slack integration
    slack_parser = subparsers.add_parser("slack", help="Deploy Slack integration")
    slack_parser.add_argument(
        "--bot-token", required=True, help="Slack Bot User OAuth Token (xoxb-...)"
    )
    slack_parser.add_argument(
        "--signing-secret", required=True, help="Slack App Signing Secret"
    )
    slack_parser.add_argument(
        "--workspace-id", required=True, help="Slack Workspace ID"
    )
    slack_parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for deployment (default: us-east-1)",
    )
    slack_parser.add_argument(
        "--skip-verification",
        action="store_true",
        help="Skip post-deployment verification checks",
    )
    slack_parser.add_argument(
        "--log-level",
        choices=["info", "debug", "error"],
        help="Log level for Lambda functions (overrides global setting)",
    )
    slack_parser.set_defaults(func=deploy_slack)

    try:
        args = parser.parse_args()

        if not args.integration:
            print("\n❌ Error: Integration type is required")
            print(
                textwrap.dedent("""
                Please specify 'jira', 'service-now', or 'slack' as the integration type.
                Example: deploy-integrations-solution jira --email user@example.com --url https://example.atlassian.net --token YOUR_TOKEN --project-key PROJ
                Example: deploy-integrations-solution service-now --instance-id example --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET --user-id YOUR_USER_ID --private-key-path ./private.key --integration-module itsm
                Example: deploy-integrations-solution slack --bot-token xoxb-... --signing-secret YOUR_SECRET --workspace-id YOUR_WORKSPACE_ID
            """)
            )
            parser.print_help()
            sys.exit(1)

        # The global --log-level argument is now used for all integrations
        print(f"DEBUG: args.log_level = {args.log_level}")

        exit_code = args.func(args)
        sys.exit(exit_code)

    except argparse.ArgumentError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    except SystemExit:
        # This is raised by argparse when --help is used or when required args are missing
        # We don't need to handle this as argparse will print the appropriate message
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

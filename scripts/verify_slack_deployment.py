#!/usr/bin/env python3
"""
Slack Integration Deployment Verification Script

This script verifies that the Slack integration has been deployed correctly
and all components are functioning as expected.
"""

import argparse
import json
import sys
import boto3
from botocore.exceptions import ClientError


def check_cloudformation_stack(stack_name, region):
    """Verify CloudFormation stack exists and is in CREATE_COMPLETE state."""
    print(f"\n🔍 Checking CloudFormation stack: {stack_name}")
    
    try:
        cfn = boto3.client('cloudformation', region_name=region)
        response = cfn.describe_stacks(StackName=stack_name)
        
        if not response['Stacks']:
            print(f"❌ Stack {stack_name} not found")
            return False
        
        stack = response['Stacks'][0]
        status = stack['StackStatus']
        
        if status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
            print(f"✅ Stack status: {status}")
            return True
        else:
            print(f"⚠️  Stack status: {status}")
            return False
            
    except ClientError as e:
        print(f"❌ Error checking stack: {e}")
        return False


def get_stack_outputs(stack_name, region):
    """Get CloudFormation stack outputs."""
    try:
        cfn = boto3.client('cloudformation', region_name=region)
        response = cfn.describe_stacks(StackName=stack_name)
        
        if not response['Stacks']:
            return {}
        
        stack = response['Stacks'][0]
        outputs = {}
        
        if 'Outputs' in stack:
            for output in stack['Outputs']:
                outputs[output['OutputKey']] = output['OutputValue']
        
        return outputs
        
    except ClientError as e:
        print(f"❌ Error getting stack outputs: {e}")
        return {}


def check_lambda_functions(outputs, region):
    """Verify Lambda functions exist and are active."""
    print("\n🔍 Checking Lambda functions")
    
    lambda_client = boto3.client('lambda', region_name=region)
    all_ok = True
    
    lambda_arns = {
        'Slack Client': outputs.get('SlackClientLambdaArn'),
        'Slack Command Handler': outputs.get('SlackCommandHandlerLambdaArn'),
    }
    
    for name, arn in lambda_arns.items():
        if not arn:
            print(f"⚠️  {name} ARN not found in outputs")
            all_ok = False
            continue
        
        try:
            function_name = arn.split(':')[-1]
            response = lambda_client.get_function(FunctionName=function_name)
            
            state = response['Configuration']['State']
            if state == 'Active':
                print(f"✅ {name}: Active")
            else:
                print(f"⚠️  {name}: {state}")
                all_ok = False
                
        except ClientError as e:
            print(f"❌ {name}: Error - {e}")
            all_ok = False
    
    return all_ok


def check_ssm_parameters(region):
    """Verify SSM parameters exist."""
    print("\n🔍 Checking SSM parameters")
    
    ssm = boto3.client('ssm', region_name=region)
    all_ok = True
    
    parameters = [
        '/SecurityIncidentResponse/slackBotToken',
        '/SecurityIncidentResponse/slackSigningSecret',
        '/SecurityIncidentResponse/slackWorkspaceId',
    ]
    
    for param_name in parameters:
        try:
            response = ssm.get_parameter(Name=param_name)
            print(f"✅ {param_name}: Exists")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ParameterNotFound':
                print(f"❌ {param_name}: Not found")
                all_ok = False
            else:
                print(f"❌ {param_name}: Error - {e}")
                all_ok = False
    
    return all_ok


def check_api_gateway(outputs, region):
    """Verify API Gateway endpoint exists."""
    print("\n🔍 Checking API Gateway")
    
    webhook_url = outputs.get('SlackWebhookUrl')
    
    if not webhook_url:
        print("❌ Slack Webhook URL not found in outputs")
        return False
    
    print(f"✅ Slack Webhook URL: {webhook_url}")
    print(f"   Use this URL for Slack Event Subscriptions and Slash Commands")
    
    return True


def check_eventbridge_rules(region):
    """Verify EventBridge rules exist and are enabled."""
    print("\n🔍 Checking EventBridge rules")
    
    events = boto3.client('events', region_name=region)
    all_ok = True
    
    try:
        # Check for slack-client-rule
        response = events.describe_rule(
            Name='slack-client-rule',
            EventBusName='security-incident-event-bus'
        )
        
        if response['State'] == 'ENABLED':
            print(f"✅ slack-client-rule: Enabled")
        else:
            print(f"⚠️  slack-client-rule: {response['State']}")
            all_ok = False
            
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"❌ slack-client-rule: Not found")
            all_ok = False
        else:
            print(f"❌ slack-client-rule: Error - {e}")
            all_ok = False
    
    return all_ok


def check_dynamodb_table(region):
    """Verify DynamoDB table exists."""
    print("\n🔍 Checking DynamoDB table")
    
    dynamodb = boto3.client('dynamodb', region_name=region)
    
    try:
        # Get table name from common stack
        cfn = boto3.client('cloudformation', region_name=region)
        response = cfn.describe_stacks(
            StackName='AwsSecurityIncidentResponseSampleIntegrationsCommonStack'
        )
        
        if not response['Stacks']:
            print("❌ Common stack not found")
            return False
        
        # Find table name in outputs
        table_name = None
        for output in response['Stacks'][0].get('Outputs', []):
            if 'Table' in output['OutputKey']:
                table_name = output['OutputValue']
                break
        
        if not table_name:
            print("⚠️  Table name not found in common stack outputs")
            return False
        
        # Check table status
        response = dynamodb.describe_table(TableName=table_name)
        status = response['Table']['TableStatus']
        
        if status == 'ACTIVE':
            print(f"✅ DynamoDB table ({table_name}): Active")
            return True
        else:
            print(f"⚠️  DynamoDB table ({table_name}): {status}")
            return False
            
    except ClientError as e:
        print(f"❌ Error checking DynamoDB table: {e}")
        return False


def print_next_steps(outputs):
    """Print next steps for completing the setup."""
    print("\n" + "="*70)
    print("📝 NEXT STEPS")
    print("="*70)
    
    webhook_url = outputs.get('SlackWebhookUrl', 'NOT_FOUND')
    
    print(f"""
1. Configure Slack Event Subscriptions:
   - Go to https://api.slack.com/apps
   - Select your Slack app
   - Click "Event Subscriptions" in the left sidebar
   - Toggle "Enable Events" to ON
   - Set Request URL to: {webhook_url}
   - Wait for URL verification (green checkmark)
   - Subscribe to bot events:
     • message.channels
     • message.groups
     • member_joined_channel
     • member_left_channel
     • file_shared
   - Click "Save Changes"
   - Reinstall app when prompted

2. Configure Slack Slash Commands:
   - In your Slack app settings, click "Slash Commands"
   - Click "Create New Command"
   - Command: /security-ir
   - Request URL: {webhook_url}
   - Short Description: Manage AWS Security Incident Response cases
   - Usage Hint: [status|update-status|update-description|update-title|close|incident-details] [args]
   - Click "Save"

3. Test the Integration:
   - Create a test AWS Security IR case
   - Verify Slack channel is created
   - Post a message in the channel
   - Verify it syncs to AWS Security IR
   - Try slash commands: /security-ir status

4. Monitor the Integration:
   - Check CloudWatch Logs for Lambda functions
   - Set up CloudWatch alarms for errors
   - Review DynamoDB for incident mappings
""")


def main():
    parser = argparse.ArgumentParser(
        description="Verify Slack integration deployment"
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    parser.add_argument(
        '--stack-name',
        default='AwsSecurityIncidentResponseSlackIntegrationStack',
        help='CloudFormation stack name'
    )
    
    args = parser.parse_args()
    
    print("="*70)
    print("AWS Security Incident Response - Slack Integration Verification")
    print("="*70)
    
    # Run all checks
    checks = []
    
    # Check CloudFormation stack
    checks.append(check_cloudformation_stack(args.stack_name, args.region))
    
    # Get stack outputs
    outputs = get_stack_outputs(args.stack_name, args.region)
    
    # Check Lambda functions
    checks.append(check_lambda_functions(outputs, args.region))
    
    # Check SSM parameters
    checks.append(check_ssm_parameters(args.region))
    
    # Check API Gateway
    checks.append(check_api_gateway(outputs, args.region))
    
    # Check EventBridge rules
    checks.append(check_eventbridge_rules(args.region))
    
    # Check DynamoDB table
    checks.append(check_dynamodb_table(args.region))
    
    # Print summary
    print("\n" + "="*70)
    print("VERIFICATION SUMMARY")
    print("="*70)
    
    passed = sum(checks)
    total = len(checks)
    
    if passed == total:
        print(f"✅ All checks passed ({passed}/{total})")
        print_next_steps(outputs)
        return 0
    else:
        print(f"⚠️  Some checks failed ({passed}/{total} passed)")
        print("\nPlease review the errors above and fix any issues.")
        return 1


if __name__ == '__main__':
    sys.exit(main())

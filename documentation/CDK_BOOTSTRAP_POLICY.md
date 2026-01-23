# CDK Bootstrap Least-Privilege Policy

This document contains the least-privilege IAM policy for CDK bootstrap operations required by the AWS Security Incident Response integrations.

## Policy Creation and Bootstrap

```bash
# Create least-privilege bootstrap policy with region and account variables
REGION=$(aws configure get region || echo "us-east-1")
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

cat > cdk-bootstrap-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudformation:CreateStack",
                "cloudformation:UpdateStack",
                "cloudformation:DeleteStack",
                "cloudformation:DescribeStacks",
                "cloudformation:DescribeStackEvents",
                "cloudformation:DescribeStackResources",
                "cloudformation:GetTemplate",
                "cloudformation:ValidateTemplate",
                "cloudformation:CreateChangeSet",
                "cloudformation:DescribeChangeSet",
                "cloudformation:ExecuteChangeSet",
                "cloudformation:DeleteChangeSet",
                "cloudformation:ListStacks",
                "cloudformation:GetStackPolicy",
                "cloudformation:SetStackPolicy"
            ],
            "Resource": [
                "arn:aws:cloudformation:\${REGION}:\${ACCOUNT}:stack/CDKToolkit/*",
                "arn:aws:cloudformation:\${REGION}:\${ACCOUNT}:stack/AwsSecurityIncidentResponse*/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:CreateBucket",
                "s3:DeleteBucket",
                "s3:PutBucketPolicy",
                "s3:GetBucketPolicy",
                "s3:DeleteBucketPolicy",
                "s3:PutBucketVersioning",
                "s3:GetBucketVersioning",
                "s3:PutBucketEncryption",
                "s3:GetBucketEncryption",
                "s3:PutBucketPublicAccessBlock",
                "s3:GetBucketPublicAccessBlock",
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": [
                "arn:aws:s3:::cdk-hnb659fds-assets-\${ACCOUNT}-\${REGION}",
                "arn:aws:s3:::cdk-hnb659fds-assets-\${ACCOUNT}-\${REGION}/*",
                "arn:aws:s3:::snow-key-\${ACCOUNT}",
                "arn:aws:s3:::snow-key-\${ACCOUNT}/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:PutParameter",
                "ssm:DeleteParameter",
                "ssm:AddTagsToResource",
                "ssm:RemoveTagsFromResource"
            ],
            "Resource": "arn:aws:ssm:\${REGION}:\${ACCOUNT}:parameter/SecurityIncidentResponse/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:PutRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:GetRole",
                "iam:PassRole",
                "iam:TagRole",
                "iam:UntagRole",
                "iam:UpdateAssumeRolePolicy"
            ],
            "Resource": [
                "arn:aws:iam::\${ACCOUNT}:role/cdk-*",
                "arn:aws:iam::\${ACCOUNT}:role/*SecurityIncidentResponse*",
                "arn:aws:iam::\${ACCOUNT}:role/*JiraClient*",
                "arn:aws:iam::\${ACCOUNT}:role/*ServiceNow*",
                "arn:aws:iam::\${ACCOUNT}:role/*Slack*",
                "arn:aws:iam::\${ACCOUNT}:role/*Poller*",
                "arn:aws:iam::\${ACCOUNT}:role/*ApiGateway*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "lambda:CreateFunction",
                "lambda:DeleteFunction",
                "lambda:UpdateFunctionCode",
                "lambda:UpdateFunctionConfiguration",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
                "lambda:AddPermission",
                "lambda:RemovePermission",
                "lambda:TagResource",
                "lambda:UntagResource",
                "lambda:PublishLayerVersion",
                "lambda:DeleteLayerVersion",
                "lambda:GetLayerVersion"
            ],
            "Resource": [
                "arn:aws:lambda:\${REGION}:\${ACCOUNT}:function:*SecurityIncidentResponse*",
                "arn:aws:lambda:\${REGION}:\${ACCOUNT}:function:*Jira*",
                "arn:aws:lambda:\${REGION}:\${ACCOUNT}:function:*ServiceNow*",
                "arn:aws:lambda:\${REGION}:\${ACCOUNT}:function:*Slack*",
                "arn:aws:lambda:\${REGION}:\${ACCOUNT}:layer:*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:CreateTable",
                "dynamodb:DeleteTable",
                "dynamodb:DescribeTable",
                "dynamodb:UpdateTable",
                "dynamodb:TagResource",
                "dynamodb:UntagResource",
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query",
                "dynamodb:Scan"
            ],
            "Resource": "arn:aws:dynamodb:\${REGION}:\${ACCOUNT}:table/*Incidents*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "events:CreateEventBus",
                "events:DeleteEventBus",
                "events:DescribeEventBus",
                "events:PutRule",
                "events:DeleteRule",
                "events:DescribeRule",
                "events:EnableRule",
                "events:DisableRule",
                "events:PutTargets",
                "events:RemoveTargets",
                "events:ListTargetsByRule",
                "events:TagResource",
                "events:UntagResource"
            ],
            "Resource": [
                "arn:aws:events:\${REGION}:\${ACCOUNT}:event-bus/security-incident-event-bus",
                "arn:aws:events:\${REGION}:\${ACCOUNT}:rule/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:CreateTopic",
                "sns:DeleteTopic",
                "sns:GetTopicAttributes",
                "sns:SetTopicAttributes",
                "sns:Subscribe",
                "sns:Unsubscribe",
                "sns:TagResource",
                "sns:UntagResource"
            ],
            "Resource": "arn:aws:sns:\${REGION}:\${ACCOUNT}:*Jira*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "apigateway:POST",
                "apigateway:GET",
                "apigateway:PUT",
                "apigateway:DELETE",
                "apigateway:PATCH"
            ],
            "Resource": [
                "arn:aws:apigateway:\${REGION}::/restapis",
                "arn:aws:apigateway:\${REGION}::/restapis/*",
                "arn:aws:apigateway:\${REGION}::/account"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:DeleteLogGroup",
                "logs:DescribeLogGroups",
                "logs:PutRetentionPolicy",
                "logs:TagLogGroup",
                "logs:UntagLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:\${REGION}:\${ACCOUNT}:log-group:/aws/lambda/*SecurityIncidentResponse*",
                "arn:aws:logs:\${REGION}:\${ACCOUNT}:log-group:/aws/lambda/*Jira*",
                "arn:aws:logs:\${REGION}:\${ACCOUNT}:log-group:/aws/lambda/*ServiceNow*",
                "arn:aws:logs:\${REGION}:\${ACCOUNT}:log-group:/aws/lambda/*Slack*",
                "arn:aws:logs:\${REGION}:\${ACCOUNT}:log-group:/aws/events/*",
                "arn:aws:logs:\${REGION}:\${ACCOUNT}:log-group:/aws/apigateway/*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:CreateSecret",
                "secretsmanager:DeleteSecret",
                "secretsmanager:DescribeSecret",
                "secretsmanager:UpdateSecret",
                "secretsmanager:GetSecretValue",
                "secretsmanager:PutSecretValue",
                "secretsmanager:TagResource",
                "secretsmanager:UntagResource",
                "secretsmanager:RotateSecret"
            ],
            "Resource": "arn:aws:secretsmanager:\${REGION}:\${ACCOUNT}:secret:*ApiAuth*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:CreateKey",
                "kms:CreateAlias",
                "kms:DeleteAlias",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:PutKeyPolicy",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": [
                "arn:aws:kms:\${REGION}:\${ACCOUNT}:key/*",
                "arn:aws:kms:\${REGION}:\${ACCOUNT}:alias/aws/s3",
                "arn:aws:kms:\${REGION}:\${ACCOUNT}:alias/aws/secretsmanager"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "sqs:CreateQueue",
                "sqs:DeleteQueue",
                "sqs:GetQueueAttributes",
                "sqs:SetQueueAttributes",
                "sqs:TagQueue",
                "sqs:UntagQueue"
            ],
            "Resource": "arn:aws:sqs:\${REGION}:\${ACCOUNT}:*dead*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "security-ir:GetCase",
                "security-ir:UpdateCase",
                "security-ir:ListCases",
                "security-ir:CreateCase",
                "security-ir:CloseCase",
                "security-ir:ListComments",
                "security-ir:CreateCaseComment",
                "security-ir:UpdateCaseComment",
                "security-ir:UpdateCaseStatus",
                "security-ir:GetCaseAttachmentDownloadUrl",
                "security-ir:GetCaseAttachmentUploadUrl"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "\${REGION}"
                }
            }
            // Note: AWS Security Incident Response service does not support resource-level permissions,
            // so wildcard resource is required. However, access is restricted to the deployment region.
        }
    ]
}
EOF

# Create the policy in AWS
aws iam create-policy --policy-name CDKBootstrapPolicy --policy-document file://cdk-bootstrap-policy.json

# Bootstrap with least-privilege policy
cdk bootstrap --cloudformation-execution-policies arn:aws:iam::\$(aws sts get-caller-identity --query Account --output text):policy/CDKBootstrapPolicy
```

## Policy Benefits

**Least-Privilege Bootstrap Benefits:**
- Restricts CDK deployment permissions to only required AWS services
- Reduces security risk by avoiding overly broad administrative permissions
- Provides audit trail of specific permissions granted for this solution
- Follows AWS security best practices for least-privilege access
- Account and region isolation prevents cross-account/cross-region access

## Alternative Bootstrap

**Use default bootstrap (less secure):**
```bash
cdk bootstrap
```

## Why Bootstrap?

Bootstrap is a prerequisite to deployment. You cannot deploy the solution which is a CDK application into an AWS account and region (an "environment") until that environment has been bootstrapped. Trying to deploy without bootstrapping will result in an error. Performing `cdk bootstrap` on an environment allows you to provision the foundational resources (like an S3 bucket and IAM roles) that the AWS CDK needs to manage and deploy the solution's infrastructure.
# Slack Integration - Console Verification Guide

Step-by-step guide to verify the Slack integration deployment via the AWS Console (us-east-1).

---

## 1. CloudFormation Stacks

1. Go to **CloudFormation** → **Stacks**
2. Verify both stacks exist and show **CREATE_COMPLETE** or **UPDATE_COMPLETE**:
   - `AwsSecurityIncidentResponseSampleIntegrationsCommonStack`
   - `AwsSecurityIncidentResponseSlackIntegrationStack`
3. Click the Slack stack → **Outputs** tab → note down:
   - `SlackWebhookUrl` (you'll need this for Slack app config)
   - `SlackClientLambdaArn`

---

## 2. EventBridge - Custom Event Bus

1. Go to **Amazon EventBridge** → **Event buses**
2. Confirm `security-incident-event-bus` exists
3. Click on it → **Rules** tab
4. You should see rules including one that routes `security-ir` events to the Slack Client Lambda

---

## 3. EventBridge - Slack Client Rule

1. Still on the `security-incident-event-bus` rules list, find the rule for Slack
   - It may be named `slack-client-rule` or have a CDK-generated name like `AwsSecurityIncidentResp-slackclientruleXXXXX`
2. Click the rule and verify:
   - **Status**: Enabled
   - **Event pattern** contains:
     ```json
     { "source": ["security-ir"] }
     ```
   - **Targets** tab shows a Lambda function (the Slack Client)
3. Click the target Lambda ARN → confirm it opens the correct Slack Client function

---

## 4. EventBridge - Security IR Client Rule

1. Back on the `security-incident-event-bus` rules list, find the rule for the Security IR Client
   - Look for a rule with event pattern containing `"source": ["jira", "service-now", "slack"]`
2. Click the rule and verify:
   - **Status**: Enabled
   - **Targets** tab shows the Security IR Client Lambda
3. This rule is what routes Slack-originated events back to AWS Security IR

---

## 5. EventBridge - Poller Schedule Rule

1. Go to **Amazon EventBridge** → **Rules** (on the **default** event bus)
2. Find the poller rule (name contains `SecurityIncidentResponsePollerRule` or similar)
3. Verify:
   - **Schedule**: `rate(1 minute)` or `rate(5 minutes)`
   - **Status**: ENABLED (or DISABLED if no cases are active yet — this is normal for initial deploy)
   - **Targets**: Points to the Security IR Poller Lambda

---

## 6. Lambda Functions

1. Go to **Lambda** → **Functions**
2. Find and verify each function is in **Active** state:

| Function (name contains) | Purpose | Key Env Vars to Check |
|---|---|---|
| `SecurityIncidentResponsePoller` | Polls SIR for cases | `INCIDENTS_TABLE_NAME`, `EVENT_BUS_NAME` |
| `SecurityIncidentResponseSlackClient` | Creates Slack channels, posts updates | `SLACK_BOT_TOKEN`, `INCIDENTS_TABLE_NAME` |
| `SlackEventsBoltHandler` | Receives Slack webhook events | `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET` |
| `SlackCommandHandler` | Processes `/security-ir` commands | `SLACK_BOT_TOKEN`, `INCIDENTS_TABLE_NAME` |
| `SecurityIncidentResponseClient` | Updates SIR from external events | `INCIDENTS_TABLE_NAME` |

3. For each function, click → **Configuration** tab → **Environment variables**
   - Verify `INCIDENTS_TABLE_NAME` matches your DynamoDB table name
   - Verify `EVENT_BUS_NAME` is `security-incident-event-bus` (where applicable)

---

## 7. Lambda - Poller IAM Permissions

1. Click the **SecurityIncidentResponsePoller** function
2. Go to **Configuration** → **Permissions** → click the **Role name**
3. In IAM, expand the inline policies
4. Verify the policy includes:
   - `security-ir:GetCase`
   - `security-ir:ListCases`
   - `security-ir:ListComments`
   - `security-ir:GetMembership` ← needed for team member merge
   - `security-ir:ListMemberships` ← needed for team member merge
   - `events:PutEvents`
   - `events:PutRule` (for adaptive polling)
5. Also verify DynamoDB read/write access to the incidents table

---

## 8. DynamoDB Table

1. Go to **DynamoDB** → **Tables**
2. Find the table (name contains `IncidentsTable`)
3. Verify:
   - **Status**: Active
   - **Partition key**: `PK` (String)
   - **Sort key**: `SK` (String)
   - **Billing mode**: On-demand
4. If cases have been processed, click **Explore table items** and check for items with `PK` starting with `Case#`

---

## 9. SSM Parameters

1. Go to **Systems Manager** → **Parameter Store**
2. Verify these parameters exist:
   - `/SecurityIncidentResponse/slackBotToken`
   - `/SecurityIncidentResponse/slackSigningSecret`
   - `/SecurityIncidentResponse/slackWorkspaceId`
3. You can click each to confirm it has a value (don't share the token/secret values)

---

## 10. API Gateway

1. Go to **API Gateway** → **APIs**
2. Find the Slack Webhook API (name contains `Slack` or `slack`)
3. Click it → **Stages** → `prod`
4. Note the **Invoke URL** — this should match the `SlackWebhookUrl` from CloudFormation outputs
5. Go to **Resources** → verify you see:
   - `/slack/events` with a **POST** method
6. Click the POST method → verify **Integration type** is `Lambda Function` and it points to the Bolt Handler

---

## 11. CloudWatch Logs

1. Go to **CloudWatch** → **Log groups**
2. Verify log groups exist for each Lambda (created on first invocation):
   - Look for groups containing `SecurityIncidentResponsePoller`
   - Look for groups containing `SlackClient`
   - Look for groups containing `SlackEventsBoltHandler`
3. Also check the EventBridge log group:
   - `/aws/events/security-incident-event-bus`
   - This logs all events flowing through the bus (useful for debugging)

---

## 12. End-to-End Wiring Summary

Verify this flow is connected:

```
┌──────────────┐      ┌───────────────────────────┐      ┌──────────────┐
│ SIR Poller   │─────►│ EventBridge               │─────►│ Slack Client │
│ (scheduled)  │      │ (security-ir source)      │      │ (creates ch) │
└──────────────┘      └───────────────────────────┘      └──────────────┘

┌──────────────┐      ┌───────────────────────────┐      ┌──────────────┐
│ Slack Events │─────►│ API Gateway + Bolt Handler│─────►│ EventBridge  │
│ (webhooks)   │      │ (posts to event bus)      │      │ (slack src)  │
└──────────────┘      └───────────────────────────┘      └──────────────┘
                                                                │
                                                                ▼
                                                         ┌──────────────┐
                                                         │ SIR Client   │
                                                         │ (updates SIR)│
                                                         └──────────────┘
```

**Quick check**: If the Poller is enabled and there are active SIR cases, you should see:
- Events in the `/aws/events/security-incident-event-bus` log group
- Slack channels being created in your workspace

---

## Troubleshooting the "slack-client-rule: Not found" Error

The verification script looks for a rule named exactly `slack-client-rule` on `security-incident-event-bus`. CDK may generate a different physical name.

1. Go to **EventBridge** → **Event buses** → `security-incident-event-bus` → **Rules**
2. Look for any rule with event pattern `{"source": ["security-ir"]}`
3. If you find it under a different name, the integration works fine — the verification script just uses a hardcoded name lookup
4. If NO rule matches that pattern, the Slack stack may need redeployment

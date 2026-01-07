# Product Context & Development Rules

## Product Overview

AWS Security Incident Response Sample Integrations provides bidirectional synchronization between AWS Security Incident Response service and external incident management platforms (Jira and ServiceNow).

## Core Integration Patterns

- **Bidirectional Sync**: Changes in either system must trigger updates in the other
- **Event-driven Updates**: Use EventBridge custom event bus where possible, fall back to polling
- **Webhook/SNS-based**: External systems notify via webhooks or SNS topics
- **State Mapping**: Maintain mapping table in DynamoDB using PK/SK pattern with single table design

## Integration-Specific Requirements

### Jira Integration
- Create Jira issues for new AWS SIR cases
- Sync comments, attachments, and status changes bidirectionally
- Use Jira webhook notifications for real-time updates
- Support custom field mappings and project-specific configurations

### ServiceNow Integration
- Manage ServiceNow incidents with automatic component setup
- Handle ServiceNow-specific workflow states and assignments
- Provide resource setup automation for initial configuration
- Use API Gateway webhooks for ServiceNow notifications

### Slack Integration
- Create dedicated Slack channels for new AWS SIR cases
- Sync messages, comments, and attachments bidirectionally
- Support slash commands for case management from Slack
- Use Slack Bolt framework for event handling and API interactions
- Implement real-time webhook processing via API Gateway

## Development Principles

- **Fail-safe Operations**: All external API calls must handle failures gracefully
- **Idempotent Processing**: Lambda functions must handle duplicate events safely
- **Comprehensive Logging**: Log all integration events for troubleshooting
- **Security First**: Never log sensitive data (tokens, passwords, PII)
- **Monitoring Ready**: Include CloudWatch metrics for all critical operations

## Error Handling Standards

- Use dead-letter queues for failed event processing
- Implement exponential backoff for API retries
- Log errors with sufficient context for debugging
- Provide clear error messages for configuration issues

## Data Handling Requirements

- Store mapping data in DynamoDB with consistent PK/SK patterns
- Use SSM Parameter Store for all credentials and configuration
- Encrypt sensitive data at rest and in transit
- Implement proper data validation for all external inputs

## Security Requirements

- Never expose credentials in logs or error messages
- Use least privilege IAM roles for all resources
- Validate all external inputs before processing
- Implement proper authentication for all webhook endpoints
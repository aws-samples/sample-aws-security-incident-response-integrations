---
inclusion: always
---

# Product Context & Development Guidelines

AWS Security Incident Response Sample Integrations provides bidirectional synchronization between AWS Security
Incident Response service and external incident management platforms (Jira and ServiceNow).

## Core Integration Patterns

- **Bidirectional Sync**: Changes in either system trigger updates in the other
- **Event-driven Updates**: All integrations use EventBridge custom event bus where possible. Fall back to polling.
- **Webhook- or SNS- based**: External systems notify via webhooks or SNS topics
- **State Mapping**: Each integration maintains mapping table in DynamoDB (PK/SK pattern).  This uses single table design

## Integration-Specific Behavior

### Jira Integration

- Creates Jira issues for new AWS SIR cases
- Syncs comments, attachments, and status changes bidirectionally
- Uses Jira webhook notifications for real-time updates
- Supports custom field mappings and project-specific configurations

### ServiceNow Integration

- Manages ServiceNow incidents with automatic component setup
- Handles ServiceNow-specific workflow states and assignments
- Provides resource setup automation for initial configuration
- Uses API Gateway webhooks for ServiceNow notifications

## Development Principles

- **Fail-safe Operations**: All external API calls must handle failures gracefully
- **Idempotent Processing**: Lambda functions should handle duplicate events safely
- **Comprehensive Logging**: Log all integration events for troubleshooting
- **Security First**: Never log sensitive data (tokens, passwords, PII)
- **Monitoring Ready**: Include CloudWatch metrics for all critical operations

## Error Handling Standards

- Use dead-letter queues for failed event processing
- Implement exponential backoff for API retries
- Log errors with sufficient context for debugging
- Provide clear error messages for configuration issues

## Data Handling Rules

- Store mapping data in DynamoDB with consistent PK/SK patterns
- Use SSM Parameter Store for all credentials and configuration
- Encrypt sensitive data at rest and in transit
- Implement proper data validation for all external inputs
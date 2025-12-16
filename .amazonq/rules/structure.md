# Project Structure Rules

## Root Level Organization

- **app.py** - Main CDK application entry point for Jira integration
- **app_service_now.py** - CDK application entry point for ServiceNow integration
- **app_slack.py** - CDK application entry point for Slack integration
- **deploy-integrations-solution.py** - CLI deployment script with integration parameters
- **cdk.json** - CDK configuration and feature flags
- **requirements.txt** - Python dependencies (includes asset-specific requirements)
- **requirements-dev.txt** - Development and testing dependencies
- **run_test.py** - CodeBuild test execution and report management

## CDK Infrastructure Directory

Location: `aws_security_incident_response_sample_integrations/`

- **constants.py** - Shared constants and configuration values
- **event_bus_logger_construct.py** - Reusable EventBridge logging construct
- **aws_security_incident_response_sample_integrations_common_stack.py** - Shared infrastructure
- **aws_security_incident_response_jira_integration_stack.py** - Jira-specific resources
- **aws_security_incident_response_service_now_integration_stack.py** - ServiceNow-specific resources
- **aws_security_incident_response_slack_integration_stack.py** - Slack-specific resources

## Lambda Assets Structure

Location: `assets/`

Each Lambda function requires:
- **index.py** - Lambda handler function
- **requirements.txt** - Function-specific dependencies

### Function Categories
- **Clients**: `jira_client/`, `service_now_client/`, `slack_client/`, `security_ir_client/` - External API interactions
- **Handlers**: `*_notifications_handler/`, `slack_events_bolt_handler/`, `slack_command_handler/` - Process incoming webhook events
- **Pollers**: `security_ir_poller/` - Periodic polling for updates
- **Setup**: `service_now_resource_setup_handler/` - Automated ServiceNow configuration
- **Authorizers**: `slack_api_gateway_authorizer/`, `service_now_api_gateway_authorizer/` - API Gateway authorization

### Shared Code Locations
- **assets/domain/python/** - Data models and domain objects
- **assets/mappers/python/** - Data transformation between systems
- **assets/wrappers/python/** - API client wrappers with common functionality
- **assets/slack_bolt_layer/** - Slack Bolt framework Lambda layer

## Testing Structure

Location: `tests/`
- **tests/assets/** - Unit tests for Lambda functions
- **tests/cdk/** - CDK stack and construct tests
- Mirror main codebase structure for easy navigation

## Documentation Organization

Location: `documentation/`
- **JIRA/** - Jira integration setup and troubleshooting guides
- **SERVICE_NOW/** - ServiceNow integration setup and troubleshooting guides
- **SLACK/** - Slack integration setup and troubleshooting guides
- **images/** - Architecture diagrams and screenshots

## Configuration Files

- **.devcontainer/** - VS Code development container configuration
- **.github/** - GitHub workflows and templates
- **.vscode/** - VS Code workspace settings
- **.pre-commit-config.yaml** - Git pre-commit hooks
- **.secrets.baseline** - Baseline for secret detection
- **constraints.txt** - Python dependency version constraints
- **scripts/** - Utility scripts for parameter management and verification

## Naming Conventions

- **CDK Stacks**: Use `AwsSecurityIncidentResponse[Integration]Stack` format
- **Lambda Functions**: Use descriptive names ending in purpose (client, handler, poller, authorizer)
- **Resources**: Follow AWS naming conventions with project prefix
- **Files**: Use snake_case for Python, kebab-case for configuration files
- **Slack Channels**: Use `aws-security-incident-response-case-<caseId>` format

## Architecture Patterns

- **Layered Architecture**: Separate domain logic from infrastructure and integration code
- **Single Responsibility**: Each Lambda function has specific, focused purpose
- **Shared Dependencies**: Package common code as Lambda layers to reduce deployment size
- **Environment Separation**: Configure through CDK parameters and SSM Parameter Store
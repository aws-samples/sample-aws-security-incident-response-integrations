# Project Structure

## Root Level Files

- **app.py** - Main CDK application entry point for Jira integration
- **app_service_now.py** - CDK application entry point for ServiceNow integration
- **deploy-integrations-solution.py** - CLI deployment script with integration-specific parameters
- **cdk.json** - CDK configuration and feature flags
- **requirements.txt** - Python dependencies (includes asset-specific requirements)
- **requirements-dev.txt** - Development and testing dependencies
- **run_test.py** - CodeBuild test execution and report management script

## CDK Infrastructure (`aws_security_incident_response_sample_integrations/`)

- **constants.py** - Shared constants and configuration values
- **event_bus_logger_construct.py** - Reusable EventBridge logging construct
- **aws_security_incident_response_sample_integrations_common_stack.py** - Shared infrastructure (EventBridge, DynamoDB, Lambda layers)
- **aws_security_incident_response_jira_integration_stack.py** - Jira-specific resources
- **aws_security_incident_response_service_now_integration_stack.py** - ServiceNow-specific resources

## Lambda Assets (`assets/`)

Each Lambda function has its own directory with:
- **index.py** - Lambda handler function
- **requirements.txt** - Function-specific dependencies

### Function Categories:

- **Clients**: `jira_client/`, `service_now_client/`, `security_ir_client/` - External API interactions
- **Handlers**: `*_notifications_handler/` - Process incoming webhook events
- **Pollers**: `security_ir_poller/` - Periodic polling for updates
- **Setup**: `service_now_resource_setup_handler/` - Automated ServiceNow configuration

### Shared Code (`assets/domain/`, `assets/mappers/`, `assets/wrappers/`)

- **domain/python/** - Data models and domain objects
- **mappers/python/** - Data transformation between systems
- **wrappers/python/** - API client wrappers with common functionality

## Testing (`tests/`)

- **tests/assets/** - Unit tests for Lambda functions
- **tests/cdk/** - CDK stack and construct tests
- Mirror structure of main codebase for easy navigation

## Documentation (`documentation/`)

- **JIRA/** - Jira integration setup and troubleshooting guides
- **SERVICE_NOW/** - ServiceNow integration setup and troubleshooting guides
- **images/** - Architecture diagrams and screenshots

## Configuration Files

- **.devcontainer/** - VS Code development container configuration
- **.github/** - GitHub workflows and templates
- **.vscode/** - VS Code workspace settings
- **.pre-commit-config.yaml** - Git pre-commit hooks
- **.secrets.baseline** - Baseline for secret detection
- **constraints.txt** - Python dependency version constraints

## Naming Conventions

- **CDK Stacks**: `AwsSecurityIncidentResponse[Integration]Stack` format
- **Lambda Functions**: Descriptive names ending in purpose (client, handler, poller)
- **Resources**: Follow AWS naming conventions with project prefix
- **Files**: Snake_case for Python, kebab-case for configuration files

## Key Patterns

- **Layered Architecture**: Domain logic separated from infrastructure and integration code
- **Single Responsibility**: Each Lambda function has a specific, focused purpose
- **Shared Dependencies**: Common code packaged as Lambda layers to reduce deployment size
- **Environment Separation**: Configuration through CDK parameters and SSM Parameter Store
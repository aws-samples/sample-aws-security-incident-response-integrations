# Technology Stack

## Infrastructure as Code

- **AWS CDK v2.x** (Python) - Primary infrastructure deployment tool
- **CDK Nag** - Security and best practices validation
- **Python 3.x** - CDK application language

## AWS Services

- **EventBridge** - Custom event bus "security-incident-event-bus" for event routing
- **Lambda** - Serverless compute with Python runtime
- **Lambda Layers** - Shared code for domain models, mappers, and wrappers
- **DynamoDB** - NoSQL database with PK/SK pattern for mapping data
- **SNS** - Messaging for Jira webhook events
- **API Gateway** - REST endpoints for ServiceNow webhooks
- **SQS** - Dead-letter queues for failed event handling
- **CloudWatch** - Logging (1-week retention), monitoring, and alerting
- **Systems Manager Parameter Store** - Secure credential and configuration storage

## Development Tools

- **Python Package Management**: pip with requirements.txt and constraints.txt
- **Code Quality**: ruff for formatting and linting
- **Testing**: pytest with coverage, mocking, and parallel execution
- **Security**: bandit, semgrep, detect-secrets for security scanning
- **Type Checking**: mypy with boto3 type stubs

## Common Commands

### Setup and Dependencies

```bash
# Install main dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

### Deployment

```bash
# Deploy Jira integration
./deploy_integrations_solution.py jira --email user@example.com --url https://example.atlassian.net --token TOKEN --project-key PROJ

# Deploy ServiceNow integration (under development)
./deploy_integrations_solution.py service-now --instance-id INSTANCE --username USER --password PASS
```

### Testing

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov

# Run specific test file
pytest tests/path/to/test_file.py
```

### Code Quality

```bash
# Format code
ruff format

# Run security scans
bandit -r .
detect-secrets scan
```

### CDK Operations

```bash
# Synthesize CloudFormation templates
npx cdk synth

# Deploy stacks directly
npx cdk deploy --app "python3 app.py" StackName

# Destroy stacks
npx cdk destroy StackName
```

## Architecture Patterns

- **Event-driven**: EventBridge custom event bus with rule-based routing
- **Serverless**: Lambda functions for all compute operations
- **Layered**: Shared Lambda layers for common code (domain, mappers, wrappers)
- **Secure by design**: Parameter Store for secrets, least privilege IAM roles
- **Monitoring-first**: CloudWatch integration for all components
# Technology Stack Rules

## Infrastructure as Code

Use AWS CDK v2.x with Python for all infrastructure deployment. Apply CDK Nag for security and best practices validation.

## AWS Services Architecture

- Use EventBridge custom event bus "security-incident-event-bus" for event routing
- Implement Lambda functions with Python 3.13 runtime for serverless compute
- Package shared code in Lambda Layers (domain models, mappers, wrappers, Slack Bolt)
- Use DynamoDB with PK/SK pattern for mapping data storage
- Configure SNS for Jira webhook events messaging
- Set up API Gateway REST endpoints for ServiceNow and Slack webhooks
- Implement SQS dead-letter queues for failed event handling
- Configure CloudWatch with 1-week log retention for monitoring
- Store credentials securely in Systems Manager Parameter Store with encryption

## Development Standards

- Use pip with requirements.txt and constraints.txt for package management
- Apply ruff for code formatting and linting
- Use pytest with coverage, mocking, and parallel execution for testing
- Run bandit, semgrep, and detect-secrets for security scanning
- Enable mypy type checking with boto3 type stubs

## Required Commands

### Setup
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # optional dev dependencies
```

### Deployment
```bash
./deploy-integrations-solution.py jira --email user@example.com --url https://example.atlassian.net --token TOKEN --project-key PROJ
./deploy-integrations-solution.py service-now --instance-id INSTANCE --username USER --password PASS
./deploy-integrations-solution.py slack --bot-token xoxb-TOKEN --signing-secret SECRET --workspace-id WORKSPACE
```

### Testing and Quality
```bash
pytest                                    # run all tests
pytest --cov                            # run with coverage
pytest tests/path/to/test_file.py        # run specific test
ruff format                              # format code
bandit -r .                              # security scan
detect-secrets scan                      # secret detection
```

### CDK Operations
```bash
npx cdk synth                            # synthesize templates
npx cdk deploy --app "python3 app_[integration-target].py" StackName  # deploy (jira/service-now/slack)
npx cdk destroy StackName                # destroy
```

## Architecture Patterns

Follow these patterns:
- Event-driven architecture with EventBridge rule-based routing
- Serverless-first with Lambda for all compute operations
- Layered architecture with shared Lambda layers for common code
- Secure by design using Parameter Store and least privilege IAM
- Monitoring-first approach with CloudWatch integration
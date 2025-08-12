# Extending AWS Security Incident Response Integrations with Generative AI

This guide explains how to use Generative AI to extend the AWS Security Incident Response Sample Integrations
solution to support additional incident management platforms beyond Jira and ServiceNow.

## Overview

The solution is designed with a modular architecture that makes it straightforward to add new integration targets.
By leveraging Generative AI tools like Amazon Q Developer or similar AI assistants, you can efficiently analyze
the existing patterns and implement new integrations following the established conventions.

## Prerequisites

Before starting, ensure you have:

- Access to a Generative AI coding assistant (Amazon Q Developer, GitHub Copilot, etc.)
- Python development environment with virtual environment support
- AWS CDK knowledge for infrastructure modifications
- Understanding of the target platform's API and authentication methods

## General Approach

### 1. Analysis Phase

Use AI to understand the existing integration patterns by analyzing:

- How current integrations (Jira/ServiceNow) are structured
- Common patterns in Lambda functions, CDK stacks, and data models
- API client implementations and error handling approaches
- Event routing and webhook handling mechanisms

### 2. Research Phase

Leverage AI to research the target platform:

- API documentation and Python SDK availability
- Authentication and authorization requirements
- Data models and field mappings
- Webhook capabilities and event structures

### 3. Implementation Phase

Use AI assistance to:

- Create new Lambda functions following existing patterns
- Implement CDK infrastructure components
- Develop data mappers and domain models
- Set up event handling and webhook endpoints

### 4. Testing and Validation

Apply AI for:

- Unit test generation following existing test patterns
- Integration testing strategies
- Error handling and edge case identification

## Step-by-Step Process

### Step 1: Workspace Analysis

Start by having your AI assistant analyze the existing codebase. Below is an example prompt on how to carry this out.

```
Analyze the workspace structure and identify all components related to [existing integration] to understand the 
integration patterns used in this AWS Security Incident Response solution.
```

#### ServiceNow vs Jira

**In general, we recommend analyzing the Jira integration over the ServiceNow integration.**

ServiceNow's SDK using a ServiceNow-specific abstractions like `GlideRecord`.  It is designed to mirror ServiceNow's
server-side scripting patterns and a database-like interface. In constract, Jira's SDK is a more
straightforward REST-based approach.  

ServiceNow SDK example

```python
# ServiceNow uses GlideRecord for database-like operations
def get_incident(self, incident_number: str):
    glide_record = self.client.GlideRecord('incident')  # Create record object
    glide_record.add_query('number', incident_number)   # Add query conditions
    glide_record.query()                                # Execute query
    if glide_record.next():                            # Iterate through results
        return glide_record

def create_incident(self, fields: Dict[str, Any]):
    glide_record = self.client.GlideRecord('incident')
    glide_record.initialize()                          # Initialize new record
    # Set fields directly on the record object
    glide_record.short_description = fields["short_description"]
    glide_record.description = fields["description"]
    glide_record.state = fields["state"]
    incident_sys_id = glide_record.insert()           # Insert and get sys_id
    return glide_record.number
```

Jira SDK Example

```python
# Jira uses direct method calls with dictionaries
def get_issue(self, issue_id: str):
    return self.client.issue(issue_id)              # Direct API call

def create_issue(self, fields: Dict[str, Any]):
    return self.client.create_issue(fields=fields)  # Pass fields as dict

def update_issue(self, issue_id: str, fields: Dict[str, Any]):
    issue = self.client.issue(issue_id)
    issue.update(fields=fields)                     # Update with dict
    return True
```

### Step 2: Target Platform Research

Research the target platform's capabilities:

```markdown
Research the [target platform] API and Python SDK. Analyze authentication methods, incident/case management 
capabilities, webhook support, and data models. Validate what resources are required to ensure bidirectional 
communication with [target platform]. Use a Python virtual environment for any package analysis. 
```

### Step 3: Architecture Planning

Plan the new integration architecture:

```markdown
Based on the existing [reference integration] pattern, design the architecture for [target platform] integration. 
Include Lambda functions, CDK components, data models, and event flows needed.
```

### Step 4: Implementation

We recommend a specification driven development when using tools like [Kiro](https://kiro.dev/). This means using an AI 
assistant to build a specification before modifying code. We recommend this specification consist of three files:

* A Requirements Document
* A Design Document
* A Task List.

Below is are prompts to get started. One is a prompt to work with Kiro, which automated much of the process. The other is
a set prompts when using other generative AI assistants 

#### Kiro Version

Kiro's **Spec** mode automatically walks you through specification driven development. In this case, it's best to
describe the end goal.

```markdown
Implement the [target platform] integration following the patterns established by [reference integration]. 
Create all necessary Lambda functions, CDK infrastructure, data mappers, and webhook handlers.
```

#### Non-Kiro Version

Below is a prompt to create a requirements document.

```markdown
Create a requirements document that modifies this solution to bidirectionally communicate with 
[target platform] integration following the patterns established by [reference integration]. [Target Platform] will 
notify the system of changes via [target platform's method of emitting events (usually this is an SNS Topic or Web 
Hook Architecture]. Write the requirements in a file to disk called `[target platform]-requirements.md`.
```

Below is a prompt to create a design document.

```markdown
Using `[target platform]-requirements.md` as requirements create a design document to modify this solution create 
bidirectional synchronization between AWS Security Incident Response and [target Platform. Include any work to modify 
Lambda functions, CDK infrastructure, data mappers, and webhook handlers.  Write the design in a file to 
disk called `[target platform]-design.md`.
```

Below is a prompt for a task list.

```markdown
Using `[target platform]-design.md` as a design and `[target platform]-requirements.md` as requirements, create a list 
of tasks that need to be accomplished.
```

To execute tasks, we recommend executing each task one-by-one using a generative AI assistant. Require this tool to author
tests alongside executing the tasks. We recommend tell this tool that running all tests is how to ensure the task 
is complete. 

## Integration Examples

### Example 1: Azure Sentinel Integration

Here's a complete example prompt for implementing Azure Sentinel integration:

```markdown
Your job is to modify this solution to support the bidirectional synchronization of AWS Security Incident Response Cases into Azure Sentinel Incidents. Perform the following tasks:

1. Analyze @workspace looking for references to Jira to see how this works with Jira.
2. Analyze the `azure-mgmt-securityinsight` and `azure-identity` python libraries to understand how to create and manage incidents in Azure Sentinel. Use a python virtual environment when analyzing.
3. Modify any Lambda functions or CDK to swap support for Jira to Azure Sentinel.
4. Update the deployment script to support Azure Sentinel with the necessary parameters.
5. Print out a summary of every file modified and what was done.
```

### Example 2: Asana Integration

Here's a complete example prompt for implementing Asana integration:

```markdown
Your job is to modify this solution to support the bidirectional synchronization of AWS Security Incident Response Cases into Asana tasks. Perform the following tasks:

1. Analyze @workspace looking for references to ServiceNow to understand the integration patterns used in this solution.
2. Research the Asana API and `asana` python library to understand how to create and manage tasks, projects, and custom fields in Asana. Use a python virtual environment when analyzing the library.
3. Create a new integration following the ServiceNow pattern that includes:
   - Lambda functions for Asana API interactions
   - CDK infrastructure for the Asana integration stack
   - Data mappers to convert between AWS SIR cases and Asana tasks
   - Webhook handling for bidirectional synchronization
   - Support for Asana project assignment and task status mapping
4. Update the deployment script to support Asana integration with parameters for workspace ID, project ID, and personal access token.
5. Print out a summary of every file created/modified and what was implemented.
```

## Integration Components Checklist

When implementing a new integration, ensure you create/modify these components:

### CDK Infrastructure

- [ ] New CDK stack file (e.g., `aws_security_incident_response_azure_sentinel_integration_stack.py`)
- [ ] Update main CDK app file to include new stack
- [ ] Add integration-specific constants to `constants.py`
- [ ] Update deployment script with new integration parameters

### Lambda Functions

- [ ] Client function for API interactions (e.g., `azure_sentinel_client/`)
- [ ] Notification handler for incoming webhooks (e.g., `azure_sentinel_notifications_handler/`)
- [ ] Resource setup handler if needed (e.g., `azure_sentinel_resource_setup_handler/`)

### Shared Code / Lambda Layers

- [ ] Domain models in `assets/domain/python/`
- [ ] Data mappers in `assets/mappers/python/`
- [ ] API wrappers in `assets/wrappers/python/`

### Configuration

- [ ] Update deployment script with integration-specific parameters
- [ ] Add SSM Parameter Store configuration
- [ ] Update IAM roles and policies as needed

### Testing

- [ ] Unit tests for all Lambda functions
- [ ] CDK stack tests
- [ ] Integration tests for API interactions

### Documentation

- [ ] Setup and configuration guide
- [ ] Troubleshooting documentation
- [ ] Architecture diagrams

## Best Practices for AI-Assisted Development

### 1. Iterative Approach

We recommend starting with analysis to understand the structure of the new integration target's
SDK. This includes authentication and authorization, how key operations are called (e.g. create/update/delete
primitives), and how changes are emitted (i.e., via Webhook or SNS topic).  

You may need to iterate on the changes several times. Test various workflows such as creating new cases or adding comments.

When testing on the Security Incident Response side, we recommend creating **Self-Managed** cases.

### 2. Pattern Consistency

Encourage your assistant to leverage the existing patterns built.  These will reduce chances for hallicination since
our shared components are designed to be atomic, easy to process and well documented to help with context.
They also include error handling patterns that make integrations more resilent.

### 3. Security Considerations

- Never expose credentials in code or logs
- Use SSM Parameter Store or AWS Secrets Manager for sensitive configuration
- Implement proper input validation

### 4. Code Quality

- Follow existing code formatting and linting standards
- Maintain comprehensive logging
- Include proper error handling and retries

## Deployment Considerations

We recommend you setup a separate environment for developing integrations than your production
environment. When deploying your production integration, we recommend using the same account as Security
Incident Response rather than a separate "integration" account. This is because this leads to simpler permissions,
monitoring, and logging.

## Support and Maintenance

### Monitoring

We recommend following the pattern of setting up a CloudWatch Dashboard to monitor the help and status of your
integration. Configure alerts for error rates and obvious KPIs such as number of cases synchronized.

As with any AWS Service, we recommend you monitor any quotas or rate limits you may encounter.

### Documentation

Although you may be the only consumer of your integration, we recommend a few areas of documentation you may want to
keep up to date:

- Setup / Configuration that occurs outside of the deployment script(s)
- AuthN / AuthZ workflows
- Any fields that won't synchronize well and how you are handling these
- Teardown processes

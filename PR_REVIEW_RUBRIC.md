# Pull Request Review Rubric

We welcome contributions from the community and partners. In order to ensure the high bar of [AWS Well-Architected](https://aws.amazon.com/architecture/well-architected/)
is maintained, we maintain a list of critical architectual decisions that must be reviewed.

In general there will be two - three paths for any architectural decision: 1/ golden path, 2/ divergent path,
and 3/ danger path. When an integration pull request is submitted, there will be a template that allows the requester
on which path they choose for each architectural decision. In the case of the divergent path, the requester will need
to provide additional information explaining why the divergent path was chosen. In the case of the danger path, the
reviewer will council the requester to rework as either a divergent path or golden path.

The pull request reviewer will review the submission and work with the requester to ensure our high bar is maintained.

## Rubric -- Polling vs Push Semantics

We favor push semantics. A poll semantic is only allowed if and only if the
contributor to prove a push mechanism do not exist. We recommend an additional operations review
in the case of a poll semantic. We details to review are: 1/ staleness, 2/ additional cost as a percentage of
total cost of ownership, and 3/ caching.

### Polling / Push: Golden Path

* Integration is using a push semantics such as webhooks for target to integration communication
* Integration is using a push semantics such as REST APIs for integration to target communication
* Integration is using a push semantics such as SNS Topics for integration to target communication
* Integration is using a push semantics such as Amazon EventBridge for all communications between microservices within 
the Integration

### Polling / Push: Divergent Path

* Integration is using a pull semantics such as polling to manage state of the target system
* Integration is using a pull semantic such as polling to manage state of the integration.

### Polling / Push: Danger Path

* Integration is using shared memory or shared database access to manage state of the target system.


## Rubric -- Authentication and Authorization Mechanism

In each case, the integration will provide a step-by-step guide inside the solution on how to ensure least privilege
include a discussion of the potential threat in the integration's threat model.

### AuthN / AuthZ: Golden Path

* Integration uses Machine to Machine OAuth 2.0 Authorization.
* Integration is using shared secrets such as API tokens and they are rotated. Rotation is done
automatically.

### AuthN / AuthZ: Divergent Path

* Integration is using shared secrets such as API tokens and they are rotated. Rotation is done
manually.

### AuthN / AuthZ : Danger Path

* Integration is not using an authentication mechanism.

## Rubric -- Compute Usage

Integrations must run on compute. When builders of integration choose a compute option, we ensure that this choice meets
our high bar.

### Compute Usage: Golden Path

* Uses AWS Lambda as the compute method.

### Compute Usage: Divergent Path

* Uses a AWS Compute service that is always be running and requires a VPC. Ideally this is too much operational
burden

### Compute Usage: Danger Path

* Uses AWS an AWS compute service that requires regular patching.

## Rubric -- Storage Use

In an ideal world integrations should be stateless, leverage the integration target and Security Incident Response as
the source of any data and accessing that data via APIs. Yet, in the interest in of efficiency integration may want to
cache data.

### Storage Use: Golden Path

* Caches integration data with a TTL of less than 1 hour. DynamoDB is used as a cache

### Storage Use: Divergent Path

* Caches integration data with a TTL of less than 1 hour. DynamoDB is NOT used as a cache.
* No cache is used whatsoever

### Storage use: Danger Path

* Storage is used in the integration outside of caching.

## Rubric -- Cost Guidelines

In an ideal world integrations should require no additional charges.  However, since every AWS service is a separate SKU,
charges will occur. We set a threshold that an integration should cost no more than 1% of the overall pricing of
Security Incident Response. As part of the PR, the requester should submit a cost estimate.

### Cost Guidelines: Golden Path

 All AWS resources in an integration use pay-per-request pricing and no resource is "always on".  Examples of this
pricing include Lambda per invocation pricing or DynamoDB read request unit pricing. Examples of always on are there
must be a ECS container task always running in order to poll a SQS queue OR an RDS database cluster.

### Cost Guidelines: Divergent Path

* All AWS resources in an integration use pay-per-request pricing and some resources require something to be "always
on".

### Cost Guidelines: Danger Path

* Any AWS resource in an integration that uses provisioned pricing models, have do not use a pay-per-use model, or
include upfront commitments.

## Rubric -- Observability Guidelines

In an ideal world, every integration should provide clear visibility into its operational health and performance. At
minimum, integrations must track three core metrics: case synchronization, case attachment synchronization, and case
comment synchronization. While implementations may vary based on specific integration needs, all metrics must be
accessible through CloudWatch to ensure consistent monitoring capabilities across different integration patterns. This
enables operators to effectively monitor, troubleshoot, and optimize the integration's performance.

### Observability Guidelines: Golden Path

* Implementation tracks the following required metrics:
  * Number of Cases Synchronized
  * Number of Case Attachments Synchronized
  * Number of Case Comments Synchronized
* Metrics are available in CloudWatch
* Metrics can be queried for both point-in-time and trend analysis

### Observability Guidelines: Divergent Path

* Implementation tracks only a subset of the required metrics
* Metrics are available but through a non-CloudWatch mechanism

### Observability Guidelines: Danger Path

* No metrics implementation
* Metrics are not queryable
* Metrics are ephemeral or not persisted


### Rubric -- Logging Guidelines

In an ideal world, integrations should provide sufficient logging to troubleshoot issues while protecting sensitive
information. Logs serve both operational and security purposes, requiring a balance between visibility and data
protection. All integrations must implement structured logging with appropriate levels and data protection controls.

### Logging Guidelines: Golden Path

* Implementation includes both ERROR and INFO level logging.  All of the following events are logged

| Error Type | Retry expected to solve |
|---|---|
|        CONNECTION_FAILURE | Yes |
| CROSS_ACCOUNT_INGESTION_FAILED | Yes |
| CROSS_REGION_INGESTION_FAILED | N/A |
| ERROR_FROM_TARGET | No |
| EVENTS_IN_BATCH_REQUEST_REJECTED | Yes |
| EVENTS_IN_BATCH_REQUEST_REJECTED | Yes |
| FAILED_TO_ASSUME_ROLE | No |
| INTERNAL_ERROR | Yes |
| INVALID_JSON | No |
| INVALID_PARAMETER | No |
| NO_PERMISSIONS | N/A |
| NO_RESOURCE | N/A |
| RESOURCE_ALREADY_EXISTS | N/A |
| RESOURCE_LIMIT_EXCEEDED | Yes |
| RESOURCE_MODIFICATION_COLLISION | Yes |
| SDK_CLIENT_ERROR | Yes |
| THIRD_ACCOUNT_HOP_DETECTED | No |
| THIRD_REGION_HOP_DETECTED | No |
| THROTTLING | Yes |
| TIMEOUT | Yes |
| TRANSIENT_ASSUME_ROLE | No |
| UNKNOWN | No |

* INFO logs capture all key operations:
  * Case creation/updates
  * Attachment uploads/downloads
  * Comment additions
  * Synchronization status changes
  * Authentication/authorization events

* All logs include correlation IDs for request tracing
  * Automatic redaction of PII
  * Automatic masking of authentication tokens/credentials
  * Logs stored in CloudWatch Logs with appropriate retention policies

### Logging Guidelines: Divergent Path

* Implementation includes only ERROR level logging. All of the following events are logged

| Error Type | Retry expected to solve |
|---|---|
|        CONNECTION_FAILURE | Yes |
| CROSS_ACCOUNT_INGESTION_FAILED | Yes |
| CROSS_REGION_INGESTION_FAILED | N/A |
| ERROR_FROM_TARGET | No |
| EVENTS_IN_BATCH_REQUEST_REJECTED | Yes |
| EVENTS_IN_BATCH_REQUEST_REJECTED | Yes |
| FAILED_TO_ASSUME_ROLE | No |
| INTERNAL_ERROR | Yes |
| INVALID_JSON | No |
| INVALID_PARAMETER | No |
| NO_PERMISSIONS | N/A |
| NO_RESOURCE | N/A |
| RESOURCE_ALREADY_EXISTS | N/A |
| RESOURCE_LIMIT_EXCEEDED | Yes |
| RESOURCE_MODIFICATION_COLLISION | Yes |
| SDK_CLIENT_ERROR | Yes |
| THIRD_ACCOUNT_HOP_DETECTED | No |
| THIRD_REGION_HOP_DETECTED | No |
| THROTTLING | Yes |
| TIMEOUT | Yes |
| TRANSIENT_ASSUME_ROLE | No |
| UNKNOWN | No |

* Manual (rather than automatic) PII redaction
* Logs stored in alternative logging system with equivalent capabilities

### Logging Guidelines: Danger Path

* No structured logging implementation
* No PII redaction or credential masking
* Logs contain sensitive information
* No correlation IDs for request tracing
* Logs not persisted or only stored locally


# SOC 2 Trust Services Criteria - Customer Responsibilities for Cloud Services

## Framework Overview
- **Standard**: SOC 2 Type II (Service Organization Control 2) - Customer Controls
- **Purpose**: Customer responsibilities for security, availability, processing integrity, confidentiality, and privacy when using cloud services
- **Scope**: Controls that cloud service customers must implement themselves
- **Authority**: American Institute of Certified Public Accountants (AICPA)
- **Assessment Period**: Minimum 6 months for Type II reports

## Trust Services Categories - Customer Controls

### Security (Common Criteria - Customer Responsibilities)

**CC6.1: Logical Access Controls (Customer Implementation)**
- **Requirement**: Customer implements logical access security policies and procedures for cloud resources
- **Implementation**: Configure IAM policies, implement least privilege access, enable multi-factor authentication
- **Customer Actions**: Configure IAM policies, implement least privilege, enable MFA, conduct access reviews
- **Assessment**: Access control testing, policy review, privilege analysis, monitoring validation
- **Evidence**: IAM policies, access review reports, MFA configuration, monitoring logs

**CC6.2: User Authentication and Authorization (Customer Management)**
- **Requirement**: Customer registers and authorizes users whose access is administered by the customer organization
- **Implementation**: Formal user registration process with approval workflows and identity verification
- **Customer Actions**: Implement user registration process, configure authentication policies, manage user lifecycle
- **Assessment**: User registration testing, authentication validation, authorization verification
- **Evidence**: User registration procedures, authentication logs, authorization matrices

**CC6.3: System Access Removal (Customer Process)**
- **Requirement**: Customer removes system access when access is no longer required or appropriate
- **Implementation**: Automated access removal process with regular access reviews and termination procedures
- **Customer Actions**: Implement automated access removal, conduct regular access reviews, maintain termination procedures
- **Assessment**: Access removal testing, review process validation, termination procedure verification
- **Evidence**: Access removal procedures, review reports, termination documentation

**CC6.7: System Monitoring (Customer Implementation)**
- **Requirement**: Customer implements monitoring to detect and respond to security events
- **Implementation**: Configure monitoring systems with real-time alerting and incident response
- **Customer Actions**: Configure CloudWatch monitoring, implement alerting, establish incident response procedures
- **Assessment**: Monitoring configuration testing, alert validation, incident response verification
- **Evidence**: Monitoring configuration, alert logs, incident response procedures

**CC7.1: Change Management (Customer Process)**
- **Requirement**: Customer implements change management procedures for system modifications
- **Implementation**: Formal change management process with approval, testing, and rollback procedures
- **Customer Actions**: Implement change management process, establish approval workflows, maintain change documentation
- **Assessment**: Change management testing, approval process validation, documentation review
- **Evidence**: Change management procedures, approval records, change documentation

### Availability (Customer Responsibilities)

**A1.2: Availability Change Management (Customer Process)**
- **Requirement**: Customer implements change management that considers availability impact
- **Implementation**: Change management process that considers availability impact and includes rollback procedures
- **Customer Actions**: Implement availability impact assessment, establish rollback procedures, test changes
- **Assessment**: Change impact analysis, rollback testing, availability monitoring
- **Evidence**: Change procedures, impact assessments, rollback documentation

### Processing Integrity (Customer Controls)

**PI1.1: Data Processing Controls (Customer Implementation)**
- **Requirement**: Customer implements controls to ensure complete and accurate data processing
- **Implementation**: Data validation, processing controls, and output verification to ensure data integrity
- **Customer Actions**: Implement data validation, configure processing controls, establish output verification
- **Assessment**: Data processing testing, validation verification, output accuracy testing
- **Evidence**: Processing procedures, validation rules, output verification reports

**PI1.2: Data Input Controls (Customer Process)**
- **Requirement**: Customer implements controls over data input to ensure completeness and accuracy
- **Implementation**: Input validation, data quality checks, and error handling procedures
- **Customer Actions**: Implement input validation, establish data quality procedures, configure error handling
- **Assessment**: Input validation testing, data quality verification, error handling validation
- **Evidence**: Input procedures, validation rules, error handling documentation

### Confidentiality (Customer Implementation)

**C1.1: Data Classification and Confidentiality (Customer Process)**
- **Requirement**: Customer implements data classification and confidentiality controls
- **Implementation**: Data classification system with confidentiality controls and access restrictions
- **Customer Actions**: Implement data classification, configure confidentiality controls, restrict access to confidential data
- **Assessment**: Classification testing, confidentiality verification, access restriction validation
- **Evidence**: Classification procedures, confidentiality policies, access control documentation

### Privacy (Customer Responsibilities)

**P1.1: Privacy Notice (Customer Obligation)**
- **Requirement**: Customer provides privacy notice describing data collection, use, retention, and disclosure
- **Implementation**: Comprehensive privacy notice covering collection, use, retention, and disclosure practices
- **Customer Actions**: Develop privacy notices, communicate to data subjects, maintain notice currency
- **Assessment**: Privacy notice review, communication verification, currency validation
- **Evidence**: Privacy notices, communication records, update documentation

**P2.1: Consent Management (Customer Process)**
- **Requirement**: Customer obtains consent and communicates choices regarding data collection and use
- **Implementation**: Consent management system with choice communication and consent tracking
- **Customer Actions**: Implement consent management, communicate choices, track consent decisions
- **Assessment**: Consent process testing, choice communication validation, tracking verification
- **Evidence**: Consent procedures, choice communications, consent tracking records

**P3.1: Data Collection (Customer Control)**
- **Requirement**: Customer collects personal information in accordance with privacy notice commitments
- **Implementation**: Data collection procedures aligned with privacy notice commitments
- **Customer Actions**: Align collection with privacy notice, implement collection controls, monitor compliance
- **Assessment**: Collection procedure testing, alignment verification, compliance monitoring
- **Evidence**: Collection procedures, alignment documentation, compliance reports

**P4.1: Data Use and Retention (Customer Policy)**
- **Requirement**: Customer uses and retains personal information in accordance with privacy commitments
- **Implementation**: Data use and retention procedures aligned with privacy commitments and legal requirements
- **Customer Actions**: Implement use restrictions, configure retention policies, monitor compliance
- **Assessment**: Use procedure testing, retention validation, compliance verification
- **Evidence**: Use policies, retention procedures, compliance documentation

**P5.1: Data Disclosure (Customer Management)**
- **Requirement**: Customer discloses personal information to third parties in accordance with privacy commitments
- **Implementation**: Disclosure procedures with third-party agreements and disclosure tracking
- **Customer Actions**: Implement disclosure procedures, establish third-party agreements, track disclosures
- **Assessment**: Disclosure testing, agreement validation, tracking verification
- **Evidence**: Disclosure procedures, third-party agreements, disclosure tracking records

**P6.1: Data Quality (Customer Responsibility)**
- **Requirement**: Customer maintains accurate, complete, and relevant personal information
- **Implementation**: Data quality procedures with accuracy verification and correction processes
- **Customer Actions**: Implement quality procedures, verify data accuracy, establish correction processes
- **Assessment**: Quality procedure testing, accuracy verification, correction process validation
- **Evidence**: Quality procedures, accuracy reports, correction documentation

**P7.1: Data Subject Access (Customer Process)**
- **Requirement**: Customer provides data subjects with access to their personal information
- **Implementation**: Data subject access procedures with identity verification and response processes
- **Customer Actions**: Implement access procedures, verify data subject identity, provide timely responses
- **Assessment**: Access procedure testing, identity verification validation, response time verification
- **Evidence**: Access procedures, verification processes, response documentation

## Assessment Methodology - Customer Focus

### Audit Approach for Customer Controls
- **Control Testing**: Focus on customer-implemented controls and procedures
- **Evidence Collection**: Customer policies, procedures, and implementation evidence
- **Sampling**: Statistical sampling of customer transactions and processes
- **Testing Methods**: Inquiry, observation, inspection, and reperformance of customer controls

### Common Customer Implementation Gaps
- **Access Management**: Inadequate access reviews and privilege management
- **Change Management**: Lack of formal change approval and testing procedures
- **Monitoring**: Insufficient monitoring and alerting configuration
- **Data Governance**: Weak data classification and privacy controls
- **Documentation**: Incomplete policies and procedure documentation

### Customer Remediation Priorities
1. **Critical**: Access controls, authentication, and authorization
2. **High**: Change management and system monitoring
3. **Medium**: Data processing and quality controls
4. **Low**: Documentation and policy updates

## AWS Shared Responsibility Context

### Customer Responsibilities (Covered in this framework)
- **Identity and Access Management**: User access, authentication, authorization
- **Data Protection**: Encryption configuration, data classification, privacy controls
- **Network Security**: Security group configuration, network access controls
- **Application Security**: Application-level controls and monitoring
- **Compliance**: Regulatory compliance implementation and monitoring

### AWS Responsibilities (Not covered - handled by AWS)
- **Physical Security**: Data center security and environmental controls
- **Infrastructure Security**: Host operating system patching and network infrastructure
- **Service Availability**: Infrastructure availability and capacity management
- **Hardware Disposal**: Secure disposal of physical hardware and storage media

This framework focuses exclusively on controls that customers must implement when using AWS cloud services, excluding controls that are AWS's responsibility as the cloud service provider.

# DoD Cloud Computing Security Requirements Guide (CC SRG) - Customer Responsibilities

## Framework Overview
- **Standard**: DoD Cloud Computing Security Requirements Guide (CC SRG) v2r8 - Customer Controls
- **Purpose**: Customer responsibilities for DoD cloud computing security when using cloud services
- **Scope**: Controls that DoD organizations and contractors must implement when using cloud services
- **Authority**: Department of Defense Chief Information Officer (DoD CIO)
- **Impact Levels**: IL2 (Controlled Unclassified Information), IL4 (Controlled Unclassified Information), IL5 (Controlled Unclassified Information), IL6 (Classified Information)

## Impact Level Classifications

### **Impact Level 2 (IL2) - Controlled Unclassified Information (CUI)**
- **Data Types**: Controlled Unclassified Information (CUI)
- **Availability**: AWS Commercial and GovCloud
- **Requirements**: NIST 800-171 baseline controls
- **Customer Focus**: Basic CUI protection and access controls

### **Impact Level 4 (IL4) - Controlled Unclassified Information (CUI)**
- **Data Types**: CUI requiring additional protection
- **Availability**: AWS GovCloud (US) regions only
- **Requirements**: Enhanced NIST 800-171 controls plus additional DoD requirements
- **Customer Focus**: Enhanced CUI protection with DoD-specific controls

### **Impact Level 5 (IL5) - Controlled Unclassified Information (CUI)**
- **Data Types**: CUI requiring the highest level of protection
- **Availability**: AWS GovCloud (US) regions only
- **Requirements**: NIST 800-53 moderate baseline plus DoD enhancements
- **Customer Focus**: Comprehensive CUI protection with continuous monitoring

### **Impact Level 6 (IL6) - Classified Information**
- **Data Types**: Classified National Security Information up to SECRET
- **Availability**: AWS Secret Region (future)
- **Requirements**: NIST 800-53 high baseline plus DoD classified requirements
- **Customer Focus**: Classified information protection (not yet available)

## DoD CC SRG Control Families - Customer Implementation

### Access Control (AC) - Customer Implementation

**AC-1: Access Control Policy and Procedures (IL2/IL4/IL5)**
- **Requirement**: Develop, document, and disseminate DoD-compliant access control policy and procedures
- **Implementation**: DoD-specific access control program with CAC/PIV integration and role-based access
- **Customer Actions**: Implement DoD access policies, integrate CAC/PIV authentication, establish role-based access
- **GovCloud Considerations**: Use GovCloud IAM with DoD identity federation
- **Assessment**: Policy review, CAC/PIV integration testing, role validation
- **Evidence**: DoD access policies, CAC/PIV configuration, role documentation

**AC-2: Account Management (IL2/IL4/IL5)**
- **Requirement**: Manage information system accounts with DoD identity standards
- **Implementation**: Account management integrated with DoD identity systems and lifecycle controls
- **Customer Actions**: Integrate with DoD identity systems, implement account lifecycle management, conduct regular reviews
- **GovCloud Considerations**: Configure GovCloud IAM with DoD Active Directory federation
- **Assessment**: Account management testing, identity integration validation, lifecycle verification
- **Evidence**: Account management procedures, identity integration records, lifecycle documentation

**AC-3: Access Enforcement (IL2/IL4/IL5)**
- **Requirement**: Enforce approved authorizations for logical access with DoD requirements
- **Implementation**: Technical access controls with DoD role-based permissions and mandatory access controls
- **Customer Actions**: Configure DoD-compliant access controls, implement mandatory access controls, enforce least privilege
- **GovCloud Considerations**: Use GovCloud security groups with DoD network requirements
- **Assessment**: Access control testing, permission validation, enforcement verification
- **Evidence**: Access control configuration, permission matrices, enforcement logs

**AC-6: Least Privilege (IL2/IL4/IL5)**
- **Requirement**: Employ principle of least privilege with DoD role definitions
- **Implementation**: Least privilege access controls with DoD-defined roles and minimal permissions
- **Customer Actions**: Implement DoD role definitions, assign minimal permissions, conduct privilege reviews
- **GovCloud Considerations**: Configure GovCloud IAM roles aligned with DoD organizational structure
- **Assessment**: Privilege testing, role validation, review verification
- **Evidence**: DoD role definitions, privilege documentation, review reports

### Audit and Accountability (AU) - Customer Implementation

**AU-1: Audit and Accountability Policy and Procedures (IL2/IL4/IL5)**
- **Requirement**: Develop DoD-compliant audit and accountability policy and procedures
- **Implementation**: Comprehensive audit program meeting DoD logging and monitoring requirements
- **Customer Actions**: Develop DoD audit policies, implement comprehensive logging, establish monitoring procedures
- **GovCloud Considerations**: Configure GovCloud CloudTrail with DoD log retention requirements
- **Assessment**: Policy review, logging validation, monitoring verification
- **Evidence**: DoD audit policies, logging configuration, monitoring procedures

**AU-2: Event Logging (IL2/IL4/IL5)**
- **Requirement**: Identify and log security-relevant events per DoD requirements
- **Implementation**: Comprehensive event logging covering DoD-required security events
- **Customer Actions**: Configure comprehensive logging, identify DoD-required events, maintain logging standards
- **GovCloud Considerations**: Use GovCloud CloudWatch with DoD event definitions
- **Assessment**: Logging configuration testing, event validation, standard verification
- **Evidence**: Logging configuration, DoD event definitions, logging standards

**AU-3: Content of Audit Records (IL4/IL5)**
- **Requirement**: Ensure audit records contain DoD-required information elements
- **Implementation**: Detailed audit records with DoD-specified timestamps, user identification, and event details
- **Customer Actions**: Configure detailed logging per DoD requirements, include required information, maintain record integrity
- **GovCloud Considerations**: Configure GovCloud logging with DoD timestamp and identification requirements
- **Assessment**: Audit record testing, content validation, integrity verification
- **Evidence**: Audit record samples, DoD content requirements, integrity controls

**AU-6: Audit Record Review, Analysis, and Reporting (IL2/IL4/IL5)**
- **Requirement**: Review and analyze audit records per DoD requirements with appropriate frequency
- **Implementation**: Regular audit review with DoD-specified analysis procedures and reporting
- **Customer Actions**: Conduct DoD-required reviews, analyze audit records, generate compliance reports
- **GovCloud Considerations**: Use GovCloud analytics tools with DoD reporting requirements
- **Assessment**: Review process testing, analysis validation, reporting verification
- **Evidence**: DoD review procedures, analysis reports, compliance documentation

### Configuration Management (CM) - Customer Implementation

**CM-1: Configuration Management Policy and Procedures (IL2/IL4/IL5)**
- **Requirement**: Develop DoD-compliant configuration management policy and procedures
- **Implementation**: Comprehensive configuration management meeting DoD change control requirements
- **Customer Actions**: Develop DoD CM policies, implement change control, maintain configuration baselines
- **GovCloud Considerations**: Use GovCloud Config with DoD baseline requirements
- **Assessment**: Policy review, change control testing, baseline validation
- **Evidence**: DoD CM policies, change control procedures, configuration baselines

**CM-2: Baseline Configuration (IL2/IL4/IL5)**
- **Requirement**: Develop and maintain DoD-approved baseline configurations
- **Implementation**: Configuration baselines meeting DoD security technical implementation guides (STIGs)
- **Customer Actions**: Establish DoD-compliant baselines, implement STIG requirements, track configuration changes
- **GovCloud Considerations**: Use GovCloud AMIs with DoD STIG compliance
- **Assessment**: Baseline validation, STIG compliance testing, change tracking verification
- **Evidence**: DoD-compliant baselines, STIG documentation, change tracking records

**CM-3: Configuration Change Control (IL2/IL4/IL5)**
- **Requirement**: Control configuration changes per DoD change management requirements
- **Implementation**: Change control process with DoD approval workflows and security impact analysis
- **Customer Actions**: Implement DoD change control, establish approval workflows, conduct security impact analysis
- **GovCloud Considerations**: Use GovCloud change management tools with DoD approval processes
- **Assessment**: Change control testing, workflow validation, impact analysis verification
- **Evidence**: DoD change procedures, approval records, impact analyses

### Identification and Authentication (IA) - Customer Implementation

**IA-1: Identification and Authentication Policy and Procedures (IL2/IL4/IL5)**
- **Requirement**: Develop DoD-compliant identification and authentication policy
- **Implementation**: Identity management meeting DoD PKI and CAC/PIV requirements
- **Customer Actions**: Develop DoD identity policies, implement PKI integration, manage CAC/PIV authentication
- **GovCloud Considerations**: Configure GovCloud IAM with DoD PKI and CAC/PIV integration
- **Assessment**: Policy review, PKI integration testing, CAC/PIV validation
- **Evidence**: DoD identity policies, PKI configuration, CAC/PIV integration records

**IA-2: Identification and Authentication (Organizational Users) (IL2/IL4/IL5)**
- **Requirement**: Uniquely identify and authenticate DoD organizational users
- **Implementation**: User identification with DoD CAC/PIV and multi-factor authentication
- **Customer Actions**: Implement CAC/PIV authentication, configure multi-factor authentication, manage DoD user identities
- **GovCloud Considerations**: Use GovCloud IAM with DoD identity providers and CAC/PIV integration
- **Assessment**: Authentication testing, CAC/PIV validation, identity management verification
- **Evidence**: CAC/PIV configuration, authentication records, identity documentation

**IA-5: Authenticator Management (IL2/IL4/IL5)**
- **Requirement**: Manage authenticators per DoD PKI and credential management requirements
- **Implementation**: Authenticator management with DoD PKI certificate lifecycle and credential controls
- **Customer Actions**: Manage DoD PKI certificates, implement credential lifecycle controls, maintain authenticator security
- **GovCloud Considerations**: Use GovCloud certificate management with DoD PKI integration
- **Assessment**: Authenticator management testing, PKI validation, lifecycle verification
- **Evidence**: PKI procedures, certificate management records, lifecycle documentation

### Incident Response (IR) - Customer Implementation

**IR-1: Incident Response Policy and Procedures (IL2/IL4/IL5)**
- **Requirement**: Develop DoD-compliant incident response policy and procedures
- **Implementation**: Incident response program meeting DoD incident reporting and response requirements
- **Customer Actions**: Develop DoD incident policies, implement response procedures, establish DoD reporting
- **GovCloud Considerations**: Configure GovCloud incident response with DoD reporting requirements
- **Assessment**: Policy review, procedure validation, reporting verification
- **Evidence**: DoD incident policies, response procedures, reporting documentation

**IR-4: Incident Handling (IL2/IL4/IL5)**
- **Requirement**: Implement incident handling per DoD incident response requirements
- **Implementation**: Incident handling with DoD classification, response, and reporting procedures
- **Customer Actions**: Implement DoD handling procedures, classify incidents per DoD requirements, execute response actions
- **GovCloud Considerations**: Use GovCloud incident response tools with DoD classification and reporting
- **Assessment**: Handling procedure testing, classification validation, response verification
- **Evidence**: DoD handling procedures, classification records, response documentation

**IR-6: Incident Reporting (IL4/IL5)**
- **Requirement**: Report incidents to DoD organizations within required timeframes
- **Implementation**: Incident reporting procedures with DoD notification requirements and timelines
- **Customer Actions**: Implement DoD reporting procedures, notify required DoD organizations, meet reporting timelines
- **GovCloud Considerations**: Configure automated reporting to DoD incident response systems
- **Assessment**: Reporting procedure testing, notification validation, timeline verification
- **Evidence**: DoD reporting procedures, notification records, timeline documentation

### Risk Assessment (RA) - Customer Implementation

**RA-1: Risk Assessment Policy and Procedures (IL2/IL4/IL5)**
- **Requirement**: Develop DoD-compliant risk assessment policy and procedures
- **Implementation**: Risk assessment program meeting DoD RMF and continuous monitoring requirements
- **Customer Actions**: Develop DoD risk policies, conduct RMF assessments, implement continuous monitoring
- **GovCloud Considerations**: Use GovCloud assessment tools with DoD RMF requirements
- **Assessment**: Policy review, RMF validation, monitoring verification
- **Evidence**: DoD risk policies, RMF documentation, monitoring procedures

**RA-3: Risk Assessment (IL2/IL4/IL5)**
- **Requirement**: Conduct risk assessments per DoD RMF requirements
- **Implementation**: Regular risk assessments with DoD threat modeling and vulnerability identification
- **Customer Actions**: Conduct DoD RMF assessments, model DoD-relevant threats, identify vulnerabilities
- **GovCloud Considerations**: Use GovCloud security assessment tools with DoD threat intelligence
- **Assessment**: Assessment validation, threat modeling verification, vulnerability confirmation
- **Evidence**: DoD RMF assessments, threat models, vulnerability assessments

**RA-5: Vulnerability Monitoring and Scanning (IL2/IL4/IL5)**
- **Requirement**: Monitor and scan for vulnerabilities per DoD requirements
- **Implementation**: Vulnerability management with DoD-approved scanning tools and remediation timelines
- **Customer Actions**: Implement DoD-approved scanning, monitor vulnerabilities, meet DoD remediation timelines
- **GovCloud Considerations**: Use GovCloud-approved vulnerability scanners with DoD reporting
- **Assessment**: Scanning validation, monitoring verification, remediation timeline confirmation
- **Evidence**: DoD scanning procedures, vulnerability reports, remediation records

### System and Communications Protection (SC) - Customer Implementation

**SC-1: System and Communications Protection Policy and Procedures (IL2/IL4/IL5)**
- **Requirement**: Develop DoD-compliant system and communications protection policy
- **Implementation**: Protection program meeting DoD encryption and network security requirements
- **Customer Actions**: Develop DoD protection policies, implement FIPS 140-2 encryption, configure network security
- **GovCloud Considerations**: Use GovCloud encryption services with FIPS 140-2 Level 3 validation
- **Assessment**: Policy review, encryption testing, network security validation
- **Evidence**: DoD protection policies, FIPS encryption configuration, network security settings

**SC-7: Boundary Protection (IL2/IL4/IL5)**
- **Requirement**: Monitor and control communications at system boundaries per DoD requirements
- **Implementation**: Network boundary protection with DoD-approved firewalls and monitoring
- **Customer Actions**: Configure DoD-compliant boundary protection, implement monitoring, control communications
- **GovCloud Considerations**: Use GovCloud network security with DoD boundary requirements
- **Assessment**: Boundary protection testing, monitoring validation, communication control verification
- **Evidence**: DoD boundary configuration, monitoring records, communication controls

**SC-8: Transmission Confidentiality and Integrity (IL2/IL4/IL5)**
- **Requirement**: Protect transmission confidentiality and integrity per DoD requirements
- **Implementation**: Transmission protection with FIPS 140-2 encryption and DoD-approved protocols
- **Customer Actions**: Configure FIPS encryption for transmission, implement DoD protocols, protect integrity
- **GovCloud Considerations**: Use GovCloud encryption in transit with FIPS 140-2 compliance
- **Assessment**: Transmission encryption testing, protocol validation, integrity verification
- **Evidence**: FIPS encryption configuration, DoD protocol settings, integrity controls

**SC-12: Cryptographic Key Establishment and Management (IL4/IL5)**
- **Requirement**: Establish and manage cryptographic keys per DoD PKI requirements
- **Implementation**: Key management with DoD PKI integration and FIPS 140-2 key storage
- **Customer Actions**: Implement DoD PKI key management, use FIPS 140-2 key storage, maintain key security
- **GovCloud Considerations**: Use GovCloud KMS with FIPS 140-2 Level 3 and DoD PKI integration
- **Assessment**: Key management testing, PKI validation, FIPS compliance verification
- **Evidence**: DoD PKI procedures, FIPS key storage configuration, key management records

**SC-13: Cryptographic Protection (IL2/IL4/IL5)**
- **Requirement**: Implement cryptographic protection per DoD and FIPS requirements
- **Implementation**: Cryptographic protection with FIPS 140-2 approved algorithms and DoD key management
- **Customer Actions**: Implement FIPS 140-2 cryptography, use DoD-approved algorithms, manage keys per DoD PKI
- **GovCloud Considerations**: Use GovCloud encryption services with FIPS 140-2 Level 3 validation
- **Assessment**: Cryptographic testing, FIPS validation, algorithm verification
- **Evidence**: FIPS cryptographic configuration, DoD algorithm documentation, key management records

## DoD-Specific Requirements - Customer Implementation

### **Continuous Monitoring (IL4/IL5)**
- **Requirement**: Implement continuous monitoring per DoD requirements
- **Implementation**: Continuous monitoring program with real-time security status and automated reporting
- **Customer Actions**: Implement continuous monitoring tools, configure real-time dashboards, automate DoD reporting
- **GovCloud Considerations**: Use GovCloud monitoring services with DoD continuous monitoring requirements

### **Supply Chain Risk Management (IL4/IL5)**
- **Requirement**: Implement supply chain risk management per DoD requirements
- **Implementation**: Supply chain controls with vendor assessment and component verification
- **Customer Actions**: Assess cloud service providers, verify component security, implement supply chain controls
- **GovCloud Considerations**: Leverage AWS GovCloud supply chain security and DoD compliance

### **Controlled Unclassified Information (CUI) Protection (IL2/IL4/IL5)**
- **Requirement**: Protect CUI per DoD and NIST 800-171 requirements
- **Implementation**: CUI protection with marking, handling, and safeguarding controls
- **Customer Actions**: Implement CUI marking, establish handling procedures, configure safeguarding controls
- **GovCloud Considerations**: Use GovCloud data classification and protection services

## AWS GovCloud Service Scope

### **IL2 Services (Commercial and GovCloud)**
- **Compute**: EC2, Lambda, ECS, EKS, Batch
- **Storage**: S3, EBS, EFS, FSx
- **Database**: RDS, DynamoDB, ElastiCache, Redshift
- **Networking**: VPC, CloudFront, Route 53, Direct Connect
- **Security**: IAM, KMS, CloudTrail, Config, GuardDuty

### **IL4/IL5 Services (GovCloud Only)**
- **Enhanced Compute**: EC2 with dedicated tenancy, Lambda with VPC
- **Secure Storage**: S3 with server-side encryption, EBS encryption
- **Managed Databases**: RDS with encryption, DynamoDB encryption
- **Advanced Networking**: VPC with flow logs, private subnets
- **Security Services**: CloudHSM, Certificate Manager, Secrets Manager

### **Future IL6 Services (AWS Secret Region)**
- **Classified Compute**: Dedicated EC2 instances for classified workloads
- **Classified Storage**: Encrypted storage for classified information
- **Classified Networking**: Isolated networks for classified communications
- **Enhanced Security**: Advanced threat detection and response

## Assessment Methodology - DoD Customer Controls

### **DoD CC SRG Assessment Approach**
- **Impact Level Assessment**: Determine appropriate IL2/IL4/IL5 requirements
- **Control Implementation**: Customer implementation of DoD-specific controls
- **GovCloud Validation**: Verify GovCloud service usage for IL4/IL5 requirements
- **Continuous Monitoring**: Ongoing assessment of DoD control effectiveness

### **Common DoD Implementation Gaps**
- **CAC/PIV Integration**: Inadequate DoD identity system integration
- **FIPS Compliance**: Insufficient FIPS 140-2 cryptographic implementation
- **Continuous Monitoring**: Lack of real-time security monitoring and reporting
- **Incident Reporting**: Inadequate DoD incident notification procedures
- **CUI Protection**: Insufficient controlled unclassified information safeguarding

### **DoD Remediation Priorities**
1. **Critical**: CAC/PIV authentication, FIPS encryption, incident reporting
2. **High**: Continuous monitoring, vulnerability management, access controls
3. **Medium**: Configuration management, audit logging, risk assessment
4. **Low**: Policy documentation and training enhancements

## AWS Shared Responsibility Context - DoD Environment

### **Customer Responsibilities (Covered in this framework)**
- **DoD Identity Integration**: CAC/PIV authentication and DoD identity federation
- **FIPS Compliance**: FIPS 140-2 cryptographic implementation and key management
- **CUI Protection**: Controlled unclassified information marking and safeguarding
- **Incident Reporting**: DoD incident notification and reporting procedures
- **Continuous Monitoring**: Real-time security monitoring and automated reporting
- **Compliance Documentation**: DoD RMF documentation and assessment evidence

### **AWS Responsibilities (GovCloud-specific)**
- **FIPS Infrastructure**: FIPS 140-2 Level 3 validated hardware security modules
- **Physical Security**: DoD-approved data center security and personnel screening
- **Network Isolation**: Dedicated GovCloud infrastructure and network isolation
- **Compliance Certifications**: FedRAMP High authorization and DoD SRG compliance
- **Supply Chain Security**: Vetted supply chain and component verification

This framework focuses exclusively on DoD CC SRG requirements that DoD customers must implement when using AWS GovCloud services for controlled unclassified and classified information processing.

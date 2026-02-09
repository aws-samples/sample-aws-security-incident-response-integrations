# PCI DSS Requirements - Customer Responsibilities for Cloud Services

## Framework Overview
- **Standard**: Payment Card Industry Data Security Standard (PCI DSS) v4.0 - Customer Controls
- **Purpose**: Customer responsibilities for protecting cardholder data in cloud environments
- **Scope**: Controls that merchants and service providers must implement when using cloud services
- **Authority**: PCI Security Standards Council
- **Applicability**: Organizations that store, process, or transmit cardholder data

## PCI DSS Requirements - Customer Implementation

### Requirement 1: Install and Maintain Network Security Controls (Customer Configuration)
Protect cardholder data with customer-configured network security controls.

**1.1 Network Security Controls (Customer Implementation)**
- **Requirement**: Establish, implement, and maintain network security controls
- **Implementation**: Configure security groups, NACLs, and firewall rules to protect cardholder data
- **Customer Actions**: Configure security groups, implement network segmentation, maintain firewall rules
- **Assessment**: Network configuration review, rule validation, segmentation testing
- **Evidence**: Security group configurations, network diagrams, firewall rule documentation

**1.2 Network Segmentation (Customer Design)**
- **Requirement**: Network segmentation is implemented to isolate the cardholder data environment
- **Implementation**: Design and implement network segmentation using VPCs, subnets, and security groups
- **Customer Actions**: Design network segmentation, implement isolation controls, validate segmentation
- **Assessment**: Segmentation design review, isolation testing, validation verification
- **Evidence**: Network architecture, segmentation documentation, isolation test results

### Requirement 2: Apply Secure Configurations (Customer Implementation)
Configure systems and applications securely.

**2.1 Secure Configuration Standards (Customer Process)**
- **Requirement**: Establish and implement secure configuration standards for system components
- **Implementation**: Develop and maintain secure configuration standards for all system components
- **Customer Actions**: Develop configuration standards, implement secure configurations, maintain baselines
- **Assessment**: Configuration standard review, implementation validation, baseline verification
- **Evidence**: Configuration standards, implementation documentation, baseline configurations

**2.2 System Hardening (Customer Responsibility)**
- **Requirement**: System components are hardened and configured securely
- **Implementation**: Implement system hardening procedures with secure configuration management
- **Customer Actions**: Implement hardening procedures, configure systems securely, maintain configurations
- **Assessment**: Hardening validation, configuration testing, maintenance verification
- **Evidence**: Hardening procedures, configuration documentation, maintenance records

### Requirement 3: Protect Stored Cardholder Data (Customer Implementation)
Implement strong data protection methods for stored cardholder data.

**3.1 Data Protection Methods (Customer Process)**
- **Requirement**: Cardholder data is protected with strong cryptography during storage
- **Implementation**: Implement encryption for cardholder data at rest using strong cryptographic methods
- **Customer Actions**: Configure encryption at rest, implement key management, protect stored data
- **Assessment**: Encryption validation, key management testing, data protection verification
- **Evidence**: Encryption configuration, key management procedures, data protection documentation

**3.2 Sensitive Authentication Data (Customer Control)**
- **Requirement**: Sensitive authentication data is not stored after authorization
- **Implementation**: Implement controls to prevent storage of sensitive authentication data
- **Customer Actions**: Configure applications to not store sensitive data, implement data purging, monitor compliance
- **Assessment**: Data storage testing, purging validation, compliance monitoring
- **Evidence**: Application configuration, purging procedures, compliance reports

### Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission (Customer Configuration)
Encrypt cardholder data during transmission over public networks.

**4.1 Transmission Encryption (Customer Implementation)**
- **Requirement**: Cardholder data is protected with strong cryptography during transmission
- **Implementation**: Configure encryption in transit for all cardholder data transmissions
- **Customer Actions**: Configure TLS/SSL encryption, implement secure protocols, validate encryption
- **Assessment**: Encryption testing, protocol validation, transmission security verification
- **Evidence**: Encryption configuration, protocol settings, transmission logs

**4.2 Secure Transmission Protocols (Customer Configuration)**
- **Requirement**: Never send unprotected cardholder data by end-user messaging technologies
- **Implementation**: Implement secure transmission protocols and prevent insecure data transmission
- **Customer Actions**: Configure secure protocols, implement transmission controls, monitor communications
- **Assessment**: Protocol testing, control validation, communication monitoring
- **Evidence**: Protocol configuration, transmission controls, monitoring records

### Requirement 7: Restrict Access to Cardholder Data by Business Need to Know (Customer Process)
Limit access to cardholder data to those with legitimate business need.

**7.1 Access Control Systems (Customer Implementation)**
- **Requirement**: Access to system components and cardholder data is restricted by role-based access controls
- **Implementation**: Implement role-based access controls with least privilege principles
- **Customer Actions**: Implement RBAC, define roles and permissions, conduct access reviews
- **Assessment**: Access control testing, role validation, review verification
- **Evidence**: RBAC configuration, role definitions, access review records

**7.2 Access Control Policies (Customer Process)**
- **Requirement**: Access control policies are established and communicated
- **Implementation**: Develop and maintain comprehensive access control policies and procedures
- **Customer Actions**: Develop access policies, communicate to workforce, maintain policy currency
- **Assessment**: Policy review, communication validation, currency verification
- **Evidence**: Access policies, communication records, policy updates

### Requirement 8: Identify Users and Authenticate Access (Customer Management)
Ensure proper user identification and authentication for access to system components.

**8.1 User Identification (Customer Process)**
- **Requirement**: Processes and mechanisms for identifying users are implemented
- **Implementation**: Implement unique user identification with proper identity management
- **Customer Actions**: Implement unique user IDs, establish identity management, maintain user records
- **Assessment**: Identity management testing, user ID validation, record verification
- **Evidence**: Identity procedures, user ID configuration, user records

**8.2 User Authentication (Customer Implementation)**
- **Requirement**: Strong user authentication is implemented for access to system components
- **Implementation**: Implement multi-factor authentication and strong authentication mechanisms
- **Customer Actions**: Configure MFA, implement strong authentication, validate authentication methods
- **Assessment**: Authentication testing, MFA validation, method verification
- **Evidence**: Authentication configuration, MFA settings, validation records

**8.3 Privileged User Authentication (Customer Control)**
- **Requirement**: Multi-factor authentication is implemented for all privileged users
- **Implementation**: Require MFA for all administrative and privileged access
- **Customer Actions**: Configure privileged user MFA, implement additional controls, monitor privileged access
- **Assessment**: Privileged access testing, MFA validation, monitoring verification
- **Evidence**: Privileged access configuration, MFA settings, monitoring records

### Requirement 9: Restrict Physical Access (Customer Workstation Controls)
Customer responsibilities for physical access to workstations and devices.

**9.1 Workstation Physical Security (Customer Implementation)**
- **Requirement**: Physical access to workstations that can access cardholder data is restricted
- **Implementation**: Implement physical security controls for workstations and devices
- **Customer Actions**: Secure workstations, implement device controls, monitor physical access
- **Assessment**: Physical security validation, device control testing, access monitoring
- **Evidence**: Physical security procedures, device controls, access monitoring records

### Requirement 10: Log and Monitor All Access (Customer Configuration)
Implement comprehensive logging and monitoring for cardholder data access.

**10.1 Audit Logging (Customer Implementation)**
- **Requirement**: Audit logs are implemented to support the detection of anomalies and suspicious activity
- **Implementation**: Configure comprehensive audit logging for all cardholder data access
- **Customer Actions**: Configure audit logging, implement log monitoring, maintain log integrity
- **Assessment**: Logging configuration testing, monitoring validation, integrity verification
- **Evidence**: Logging configuration, monitoring procedures, integrity controls

**10.2 Log Review (Customer Process)**
- **Requirement**: Audit logs are reviewed to identify anomalies or suspicious activity
- **Implementation**: Implement regular log review procedures with anomaly detection
- **Customer Actions**: Conduct log reviews, implement anomaly detection, investigate suspicious activity
- **Assessment**: Log review testing, detection validation, investigation verification
- **Evidence**: Log review procedures, detection systems, investigation records

### Requirement 11: Test Security of Systems and Networks Regularly (Customer Testing)
Implement regular security testing and vulnerability management.

**11.1 Vulnerability Management (Customer Process)**
- **Requirement**: Processes are implemented to test for the presence of wireless access points
- **Implementation**: Implement vulnerability scanning and security testing procedures
- **Customer Actions**: Conduct vulnerability scans, perform security testing, remediate findings
- **Assessment**: Scanning validation, testing verification, remediation confirmation
- **Evidence**: Scan results, testing reports, remediation records

**11.2 Penetration Testing (Customer Requirement)**
- **Requirement**: Network penetration testing is performed at least annually
- **Implementation**: Conduct annual penetration testing with qualified security assessors
- **Customer Actions**: Perform penetration testing, address findings, validate remediation
- **Assessment**: Testing validation, finding review, remediation verification
- **Evidence**: Penetration test reports, remediation plans, validation records

### Requirement 12: Support Information Security with Organizational Policies (Customer Governance)
Establish and maintain information security policies and procedures.

**12.1 Information Security Policy (Customer Development)**
- **Requirement**: A comprehensive information security policy is established, published, maintained, and disseminated
- **Implementation**: Develop and maintain comprehensive information security policies
- **Customer Actions**: Develop security policies, publish to workforce, maintain policy currency
- **Assessment**: Policy review, publication validation, currency verification
- **Evidence**: Security policies, publication records, policy updates

**12.2 Risk Assessment (Customer Process)**
- **Requirement**: A risk assessment is performed at least annually
- **Implementation**: Conduct annual risk assessments with threat identification and mitigation
- **Customer Actions**: Perform risk assessments, identify threats, implement mitigation strategies
- **Assessment**: Risk assessment validation, threat identification verification, mitigation confirmation
- **Evidence**: Risk assessment reports, threat analyses, mitigation plans

## Assessment Methodology - Customer Controls

### QSA Assessment Approach for Customer Controls
- **Policy Review**: Customer information security policies and procedures
- **Technical Testing**: Customer-implemented controls and configurations
- **Process Validation**: Customer operational procedures and compliance processes
- **Evidence Collection**: Customer documentation and implementation evidence

### Common Customer Implementation Gaps
- **Network Segmentation**: Inadequate isolation of cardholder data environment
- **Access Controls**: Insufficient role-based access controls and privileged user management
- **Encryption**: Incomplete encryption implementation for data at rest and in transit
- **Logging and Monitoring**: Inadequate audit logging and log review procedures
- **Vulnerability Management**: Insufficient vulnerability scanning and remediation

### Customer Remediation Priorities
1. **Critical**: Data encryption, access controls, and network segmentation
2. **High**: Audit logging, vulnerability management, and authentication
3. **Medium**: Physical security and policy documentation
4. **Low**: Process improvements and training enhancements

## AWS Shared Responsibility Context

### Customer Responsibilities (Covered in this framework)
- **Data Protection**: Cardholder data encryption and access controls
- **Network Security**: Security group configuration and network segmentation
- **Access Management**: User authentication, authorization, and privileged access
- **Monitoring**: Audit logging configuration and log review procedures
- **Compliance**: PCI DSS compliance implementation and validation

### AWS Responsibilities (Not covered - handled by AWS)
- **Infrastructure Security**: Physical security of data centers and hardware
- **Platform Security**: Underlying platform security and service hardening
- **Service Availability**: Infrastructure availability and disaster recovery
- **Compliance Certifications**: AWS PCI DSS compliance and attestations

This framework focuses exclusively on PCI DSS requirements that customers must implement when using AWS cloud services for cardholder data processing, storage, or transmission.

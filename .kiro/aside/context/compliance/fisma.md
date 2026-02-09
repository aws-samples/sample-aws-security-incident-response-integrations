# FISMA Federal Information Security Management Act Requirements

## Framework Overview
- **Standard**: Federal Information Security Management Act (FISMA)
- **Purpose**: Framework for protecting government information, operations, and assets
- **Scope**: Federal agencies and contractors processing federal information
- **Authority**: Public Law 107-347, updated by FISMA 2014
- **Implementation**: Based on NIST Risk Management Framework (RMF)

## FISMA Risk Management Framework (RMF)

### Step 1: Categorize Information Systems
**Security Categorization Requirements**
- **Requirement**: Categorize information and information systems according to risk levels
- **Implementation**: Use FIPS 199 to determine Low, Moderate, or High impact levels
- **AWS Responsibility**: Customer - Customer must categorize their systems and data
- **Customer Actions**: Conduct security categorization, document impact levels, maintain categorization
- **Assessment**: Categorization review, impact level validation, documentation completeness
- **Evidence**: Security categorization documentation, impact analysis, approval records

**Information Types and Impact Levels**
- **Confidentiality Impact**: Unauthorized disclosure of information
- **Integrity Impact**: Unauthorized modification or destruction of information  
- **Availability Impact**: Disruption of access to or use of information
- **Impact Levels**: Low, Moderate, High based on potential adverse effects

### Step 2: Select Security Controls
**Security Control Selection Requirements**
- **Requirement**: Select appropriate security controls based on risk assessment and system categorization
- **Implementation**: Use NIST 800-53 control baselines appropriate for impact level
- **AWS Responsibility**: Shared - AWS provides controls, customer selects and implements additional controls
- **Customer Actions**: Select control baselines, tailor controls, document control selection
- **Assessment**: Control selection review, baseline compliance, tailoring justification
- **Evidence**: Control selection documentation, baseline mapping, tailoring decisions

**Control Baselines by Impact Level**
- **Low Impact**: 125+ controls from NIST 800-53 Low baseline
- **Moderate Impact**: 325+ controls from NIST 800-53 Moderate baseline  
- **High Impact**: 421+ controls from NIST 800-53 High baseline

### Step 3: Implement Security Controls
**Security Control Implementation Requirements**
- **Requirement**: Implement selected security controls in accordance with implementation guidance
- **Implementation**: Deploy controls using secure configuration and implementation standards
- **AWS Responsibility**: Shared - AWS implements infrastructure controls, customer implements system controls
- **Customer Actions**: Configure security controls, implement secure baselines, document implementation
- **Assessment**: Implementation review, configuration validation, security testing
- **Evidence**: Implementation documentation, configuration records, security settings

**Common Control Implementation**
- **System-Specific Controls**: Controls implemented specifically for the information system
- **Common Controls**: Controls inherited from organization or shared infrastructure
- **Hybrid Controls**: Controls with both system-specific and common components

### Step 4: Assess Security Controls
**Security Control Assessment Requirements**
- **Requirement**: Assess security controls to determine effectiveness and compliance
- **Implementation**: Independent assessment using NIST 800-53A assessment procedures
- **AWS Responsibility**: Shared - AWS provides assessment evidence, customer conducts system assessment
- **Customer Actions**: Conduct control assessment, document findings, validate control effectiveness
- **Assessment**: Independent assessment procedures, finding validation, remediation tracking
- **Evidence**: Assessment reports, testing results, finding documentation, remediation evidence

**Assessment Procedures and Methods**
- **Examine**: Review documentation, policies, procedures, and system configurations
- **Interview**: Conduct interviews with system owners, administrators, and users
- **Test**: Perform technical testing of control implementation and effectiveness

### Step 5: Authorize Information System
**Authorization Requirements**
- **Requirement**: Senior official makes risk-based decision to authorize system operation
- **Implementation**: Authority to Operate (ATO) based on acceptable risk level
- **AWS Responsibility**: Customer - Customer must obtain ATO for their systems
- **Customer Actions**: Prepare authorization package, obtain ATO, document authorization decision
- **Assessment**: Authorization package review, risk acceptance validation, ATO documentation
- **Evidence**: Authorization package, ATO documentation, risk acceptance records

**Authorization Package Components**
- **System Security Plan (SSP)**: Comprehensive security plan for the information system
- **Security Assessment Report (SAR)**: Results of security control assessment
- **Plan of Action and Milestones (POA&M)**: Remediation plan for identified weaknesses

### Step 6: Monitor Security Controls
**Continuous Monitoring Requirements**
- **Requirement**: Monitor security controls on an ongoing basis to ensure continued effectiveness
- **Implementation**: Continuous monitoring program with regular assessment and reporting
- **AWS Responsibility**: Shared - AWS provides monitoring capabilities, customer implements monitoring program
- **Customer Actions**: Implement continuous monitoring, conduct regular assessments, report status
- **Assessment**: Monitoring program review, assessment frequency validation, reporting compliance
- **Evidence**: Monitoring procedures, assessment reports, status reporting, trend analysis

**Continuous Monitoring Components**
- **Configuration Management**: Track and control system configuration changes
- **Security Impact Analysis**: Assess security impact of system changes
- **Ongoing Assessment**: Regular assessment of security control effectiveness
- **Status Reporting**: Regular reporting to senior officials and oversight bodies

## FISMA Compliance Requirements by System Impact Level

### Low Impact Systems
**Security Control Requirements**
- **Control Families**: 17 control families from NIST 800-53
- **Total Controls**: 125+ security controls
- **Assessment Frequency**: Every 3 years or upon significant change
- **Continuous Monitoring**: Basic monitoring with annual status reporting

**Key Control Areas**
- **Access Control (AC)**: Basic access control policies and procedures
- **Audit and Accountability (AU)**: Basic audit logging and review
- **Configuration Management (CM)**: Basic configuration control
- **Identification and Authentication (IA)**: Basic user identification
- **System and Communications Protection (SC)**: Basic boundary protection

### Moderate Impact Systems
**Security Control Requirements**
- **Control Families**: 18 control families from NIST 800-53
- **Total Controls**: 325+ security controls
- **Assessment Frequency**: Every 3 years or upon significant change
- **Continuous Monitoring**: Enhanced monitoring with quarterly status reporting

**Key Control Areas**
- **Access Control (AC)**: Enhanced access control with role-based access
- **Audit and Accountability (AU)**: Comprehensive audit logging and analysis
- **Configuration Management (CM)**: Automated configuration management
- **Identification and Authentication (IA)**: Multi-factor authentication
- **Incident Response (IR)**: Formal incident response procedures
- **System and Communications Protection (SC)**: Enhanced boundary protection and encryption

### High Impact Systems
**Security Control Requirements**
- **Control Families**: 18 control families from NIST 800-53
- **Total Controls**: 421+ security controls
- **Assessment Frequency**: Every 3 years or upon significant change
- **Continuous Monitoring**: Comprehensive monitoring with monthly status reporting

**Key Control Areas**
- **Access Control (AC)**: Mandatory access control with separation of duties
- **Audit and Accountability (AU)**: Real-time audit monitoring and analysis
- **Configuration Management (CM)**: Comprehensive configuration management with integrity verification
- **Identification and Authentication (IA)**: Strong authentication with PKI integration
- **Incident Response (IR)**: Advanced incident response with forensic capabilities
- **System and Communications Protection (SC)**: Comprehensive protection with high-grade encryption

## AWS-Specific FISMA Implementation

### AWS Shared Responsibility for FISMA
**AWS Responsibilities**
- **Physical Security**: Data center physical security and environmental controls
- **Infrastructure Security**: Network infrastructure, hypervisor, and host operating system security
- **Service Security**: AWS service security controls and monitoring
- **Compliance Documentation**: AWS compliance reports and certifications

**Customer Responsibilities**
- **System Security Plan**: Develop and maintain comprehensive SSP
- **Security Control Implementation**: Implement customer-responsible security controls
- **Assessment and Authorization**: Conduct security assessment and obtain ATO
- **Continuous Monitoring**: Implement continuous monitoring program

### AWS Services for FISMA Compliance

#### **Identity and Access Management**
**AWS Identity and Access Management (IAM)**
- **FISMA Controls**: AC-1, AC-2, AC-3, AC-5, AC-6, IA-1, IA-2, IA-4, IA-5
- **Implementation**: Role-based access control with federal identity integration
- **Requirements**: PIV/CAC integration, multi-factor authentication, least privilege
- **Evidence**: IAM policies, access logs, authentication records, privilege reviews

**AWS Single Sign-On (SSO)**
- **FISMA Controls**: AC-2, AC-3, IA-2, IA-4, IA-8
- **Implementation**: Centralized access management with SAML federation
- **Requirements**: Federal identity provider integration, session management
- **Evidence**: SSO configuration, federation setup, session logs, access records

#### **Audit and Accountability**
**AWS CloudTrail**
- **FISMA Controls**: AU-1, AU-2, AU-3, AU-6, AU-7, AU-9, AU-11, AU-12
- **Implementation**: Comprehensive API logging and audit trail management
- **Requirements**: All regions enabled, log integrity protection, centralized storage
- **Evidence**: CloudTrail configuration, log files, integrity validation, retention policies

**AWS Config**
- **FISMA Controls**: AU-2, AU-6, CM-3, CM-6, CM-8
- **Implementation**: Configuration change tracking and compliance monitoring
- **Requirements**: All resources monitored, compliance rules configured, change notifications
- **Evidence**: Config rules, compliance reports, change history, notification records

#### **System and Communications Protection**
**AWS Key Management Service (KMS)**
- **FISMA Controls**: SC-8, SC-12, SC-13, SC-17
- **Implementation**: Centralized cryptographic key management
- **Requirements**: FIPS 140-2 Level 2 validated, key rotation, access logging
- **Evidence**: Key policies, rotation schedules, access logs, FIPS validation

**Amazon Virtual Private Cloud (VPC)**
- **FISMA Controls**: SC-7, SC-32, AC-4
- **Implementation**: Network segmentation and boundary protection
- **Requirements**: Network isolation, security groups, network ACLs, flow logging
- **Evidence**: VPC configuration, security group rules, flow logs, network diagrams

### FISMA Assessment and Authorization Process

#### **Preparation Phase (Months 1-3)**
**System Security Plan Development**
- **Requirements**: Comprehensive SSP covering all security controls
- **AWS Integration**: Document AWS shared responsibility and inherited controls
- **Components**: System description, security controls, implementation details
- **Evidence**: SSP document, control implementation details, AWS documentation

**Security Control Implementation**
- **Requirements**: Implement all required security controls
- **AWS Integration**: Configure AWS services for FISMA compliance
- **Testing**: Validate control implementation and effectiveness
- **Evidence**: Configuration records, implementation documentation, test results

#### **Assessment Phase (Months 4-6)**
**Independent Security Assessment**
- **Requirements**: Third-party assessment of security controls
- **Scope**: All implemented security controls and AWS inherited controls
- **Methods**: Examine, interview, and test assessment procedures
- **Deliverable**: Security Assessment Report (SAR) with findings and recommendations

**Plan of Action and Milestones (POA&M)**
- **Requirements**: Remediation plan for all identified weaknesses
- **Components**: Finding description, remediation actions, milestones, resources
- **Tracking**: Regular updates on remediation progress and completion
- **Evidence**: POA&M document, remediation tracking, completion validation

#### **Authorization Phase (Month 7)**
**Authorization Package Review**
- **Components**: SSP, SAR, POA&M, and supporting documentation
- **Review**: Senior official review of risk posture and authorization decision
- **Decision**: Authority to Operate (ATO), Interim ATO (IATO), or Denial
- **Documentation**: Authorization decision document with terms and conditions

**Authority to Operate (ATO)**
- **Duration**: Typically 3 years with annual reviews
- **Conditions**: Specific terms and conditions for system operation
- **Monitoring**: Continuous monitoring requirements and reporting
- **Renewal**: Re-authorization process before ATO expiration

#### **Continuous Monitoring Phase (Ongoing)**
**Ongoing Assessment Activities**
- **Frequency**: Monthly, quarterly, or annual based on control criticality
- **Scope**: Security control effectiveness and system changes
- **Methods**: Automated monitoring, periodic testing, configuration validation
- **Reporting**: Regular status reports to authorizing official

**Change Management and Impact Analysis**
- **Requirements**: Assess security impact of all system changes
- **Process**: Change request, impact analysis, approval, implementation, validation
- **Documentation**: Change requests, impact assessments, approval records
- **Monitoring**: Post-change monitoring and validation of security posture

## FISMA Compliance Challenges and Solutions

### Common FISMA Compliance Challenges
**Documentation Complexity**
- **Challenge**: Extensive documentation requirements for SSP and supporting materials
- **Solution**: Use templates and automation tools to streamline documentation
- **AWS Support**: Leverage AWS compliance documentation and shared responsibility guidance

**Control Implementation Complexity**
- **Challenge**: Implementing 125-421 security controls across complex systems
- **Solution**: Prioritize high-risk controls and use AWS managed services where possible
- **AWS Support**: Use AWS Config rules and Security Hub for automated compliance monitoring

**Assessment and Authorization Timeline**
- **Challenge**: 6-12 month timeline for initial assessment and authorization
- **Solution**: Early planning, parallel activities, and experienced assessment teams
- **AWS Support**: Leverage AWS FedRAMP authorization and compliance documentation

**Continuous Monitoring Requirements**
- **Challenge**: Ongoing monitoring and reporting requirements
- **Solution**: Automated monitoring tools and dashboards for real-time visibility
- **AWS Support**: Use CloudWatch, Config, and Security Hub for continuous monitoring

### AWS-Specific FISMA Solutions
**Inherited Controls from AWS**
- **Benefit**: Reduce customer implementation burden through AWS inherited controls
- **Implementation**: Document inherited controls in SSP and leverage AWS compliance reports
- **Evidence**: AWS compliance documentation, SOC reports, FedRAMP authorization

**Automated Compliance Monitoring**
- **Benefit**: Reduce manual monitoring effort through automation
- **Implementation**: AWS Config rules, Security Hub, and custom monitoring solutions
- **Evidence**: Compliance dashboards, automated reports, exception notifications

**Shared Responsibility Clarity**
- **Benefit**: Clear understanding of AWS vs customer responsibilities
- **Implementation**: Document shared responsibility matrix in SSP
- **Evidence**: Shared responsibility documentation, control implementation matrix
- **Inherited Controls**: Controls implemented by AWS and inherited by customer systems
- **Hybrid Controls**: Controls implemented partially by AWS and partially by customer
- **System-Specific Controls**: Controls implemented entirely by customer

### Step 4: Assess Security Controls
**Security Control Assessment Requirements**
- **Requirement**: Assess security controls to determine effectiveness and compliance
- **Implementation**: Independent assessment using NIST 800-53A assessment procedures
- **AWS Responsibility**: Shared - AWS provides assessment support, customer conducts assessments
- **Customer Actions**: Conduct control assessments, document findings, validate effectiveness
- **Assessment**: Assessment procedure review, finding validation, effectiveness determination
- **Evidence**: Assessment reports, testing results, finding documentation

**Assessment Methods**
- **Examine**: Review of documentation, policies, procedures, and configurations
- **Interview**: Discussions with personnel responsible for control implementation
- **Test**: Hands-on testing of control implementation and effectiveness

### Step 5: Authorize Information System
**Authorization Requirements**
- **Requirement**: Authorize information system operation based on risk assessment and control implementation
- **Implementation**: Authorizing Official (AO) makes risk-based authorization decision
- **AWS Responsibility**: Customer - Customer must obtain authorization from federal AO
- **Customer Actions**: Prepare authorization package, present to AO, obtain authorization decision
- **Assessment**: Authorization package review, risk assessment validation, AO decision
- **Evidence**: Authorization package, risk assessment, AO authorization decision

**Authorization Package Components**
- **System Security Plan (SSP)**: Comprehensive security documentation
- **Security Assessment Report (SAR)**: Independent assessment results
- **Plan of Action and Milestones (POA&M)**: Remediation plan for findings

### Step 6: Monitor Security Controls
**Continuous Monitoring Requirements**
- **Requirement**: Monitor security controls on an ongoing basis to ensure continued effectiveness
- **Implementation**: Continuous monitoring program with regular assessments and reporting
- **AWS Responsibility**: Shared - AWS provides monitoring tools, customer implements monitoring program
- **Customer Actions**: Implement continuous monitoring, conduct regular assessments, report status
- **Assessment**: Monitoring program review, assessment frequency validation, reporting compliance
- **Evidence**: Monitoring procedures, assessment reports, status reporting

**Monitoring Activities**
- **Configuration Management**: Ongoing configuration monitoring and control
- **Security Control Assessments**: Regular assessment of control effectiveness
- **Security Status Reporting**: Regular reporting to oversight authorities
- **Information System and Environment Changes**: Impact assessment of changes

## FISMA Compliance Requirements

### Mandatory Security Controls
**Access Control (AC)**
- **AC-1**: Access Control Policy and Procedures
- **AC-2**: Account Management with federal identity integration
- **AC-3**: Access Enforcement using mandatory access controls
- **AC-17**: Remote Access with encrypted connections and federal authentication

**Audit and Accountability (AU)**
- **AU-1**: Audit and Accountability Policy and Procedures
- **AU-2**: Event Logging covering all security-relevant events
- **AU-3**: Content of Audit Records with required federal data elements
- **AU-6**: Audit Review, Analysis, and Reporting with federal requirements

**Configuration Management (CM)**
- **CM-1**: Configuration Management Policy and Procedures
- **CM-2**: Baseline Configuration meeting federal security standards
- **CM-6**: Configuration Settings using federal security baselines
- **CM-8**: Information System Component Inventory

**Contingency Planning (CP)**
- **CP-1**: Contingency Planning Policy and Procedures
- **CP-2**: Contingency Plan meeting federal continuity requirements
- **CP-9**: Information System Backup with federal retention requirements
- **CP-10**: Information System Recovery and Reconstitution

**Identification and Authentication (IA)**
- **IA-1**: Identification and Authentication Policy and Procedures
- **IA-2**: Identification and Authentication with PIV/CAC requirements
- **IA-5**: Authenticator Management meeting federal standards
- **IA-8**: Identification and Authentication for non-organizational users

**Incident Response (IR)**
- **IR-1**: Incident Response Policy and Procedures
- **IR-2**: Incident Response Training covering federal requirements
- **IR-6**: Incident Reporting to federal agencies within required timeframes
- **IR-8**: Incident Response Plan

**Risk Assessment (RA)**
- **RA-1**: Risk Assessment Policy and Procedures
- **RA-3**: Risk Assessment using federal methodology
- **RA-5**: Vulnerability Scanning with federal requirements
- **RA-9**: Criticality Analysis

**System and Communications Protection (SC)**
- **SC-1**: System and Communications Protection Policy and Procedures
- **SC-7**: Boundary Protection meeting federal standards
- **SC-8**: Transmission Confidentiality and Integrity using FIPS encryption
- **SC-13**: Cryptographic Protection using federal-approved algorithms

**System and Information Integrity (SI)**
- **SI-1**: System and Information Integrity Policy and Procedures
- **SI-2**: Flaw Remediation meeting federal timelines
- **SI-3**: Malicious Code Protection
- **SI-4**: Information System Monitoring with 24/7 capability

### Federal Identity Requirements
**Personal Identity Verification (PIV)**
- **Requirement**: Use PIV cards for federal employee and contractor authentication
- **Implementation**: PIV card integration with multi-factor authentication
- **AWS Integration**: AWS supports PIV authentication through SAML federation
- **Customer Actions**: Implement PIV card readers, configure SAML federation, enforce PIV usage

**Common Access Card (CAC)**
- **Requirement**: Use CAC for Department of Defense personnel authentication
- **Implementation**: CAC integration with PKI authentication
- **AWS Integration**: AWS supports CAC authentication through certificate-based authentication
- **Customer Actions**: Implement CAC readers, configure certificate authentication, enforce CAC usage

### Federal Cryptographic Requirements
**FIPS 140-2 Compliance**
- **Requirement**: Use FIPS 140-2 validated cryptographic modules
- **Implementation**: FIPS-validated encryption for data at rest and in transit
- **AWS Compliance**: AWS KMS and other services provide FIPS 140-2 Level 3 validation
- **Customer Actions**: Enable FIPS mode, use FIPS-validated services, validate cryptographic implementation

**Suite B Cryptography (High Impact)**
- **Requirement**: Use NSA Suite B cryptographic algorithms for High impact systems
- **Implementation**: Elliptic Curve Cryptography (ECC) with approved algorithms
- **AWS Support**: AWS supports Suite B algorithms in applicable services
- **Customer Actions**: Configure Suite B algorithms, validate implementation, maintain compliance

### Federal Reporting Requirements
**Annual FISMA Reporting**
- **Requirement**: Submit annual FISMA reports to OMB and Congress
- **Content**: Security program status, incident statistics, compliance metrics
- **Customer Actions**: Collect required data, prepare reports, submit to appropriate authorities
- **Evidence**: Annual reports, supporting data, submission confirmations

**Quarterly Reporting**
- **Requirement**: Submit quarterly security status reports
- **Content**: Security control status, POA&M updates, incident summaries
- **Customer Actions**: Maintain current status, prepare quarterly reports, track remediation
- **Evidence**: Quarterly reports, status tracking, remediation progress

**Incident Reporting**
- **Requirement**: Report security incidents to US-CERT within required timeframes
- **Timeframes**: 1 hour for major incidents, 24 hours for other incidents
- **Customer Actions**: Implement incident detection, establish reporting procedures, maintain contact information
- **Evidence**: Incident reports, notification records, response documentation

## AWS and FISMA Compliance

### AWS Shared Responsibility for FISMA
**AWS Responsibilities**
- **Infrastructure Security**: Physical security, network controls, hypervisor security
- **Service Security**: Security of AWS services and APIs
- **Compliance Programs**: Maintain FedRAMP authorization and FISMA compliance
- **Audit Support**: Provide audit artifacts and compliance documentation

**Customer Responsibilities**
- **System Authorization**: Obtain ATO from federal Authorizing Official
- **Security Controls**: Implement and maintain system-specific security controls
- **Continuous Monitoring**: Conduct ongoing monitoring and assessment
- **Incident Response**: Detect, respond to, and report security incidents

### AWS Services for FISMA Compliance
**Identity and Access Management**
- **AWS IAM**: Federal identity integration, PIV/CAC support via SAML
- **AWS SSO**: Centralized access management with federal identity federation
- **AWS Directory Service**: Active Directory integration for federal environments

**Audit and Monitoring**
- **AWS CloudTrail**: Comprehensive API logging for federal audit requirements
- **AWS Config**: Configuration monitoring and compliance assessment
- **AWS CloudWatch**: Real-time monitoring and alerting

**Encryption and Key Management**
- **AWS KMS**: FIPS 140-2 Level 3 validated key management
- **AWS CloudHSM**: FIPS 140-2 Level 3 dedicated hardware security modules
- **AWS Certificate Manager**: SSL/TLS certificate management

**Network Security**
- **Amazon VPC**: Network isolation and segmentation
- **AWS WAF**: Web application firewall protection
- **AWS Shield**: DDoS protection services

### FISMA Authorization Process for AWS
**Leverage AWS FedRAMP Authorization**
- **Inherited Controls**: Leverage AWS FedRAMP Moderate authorization
- **Control Inheritance**: Map AWS controls to FISMA requirements
- **Residual Risk**: Assess and document residual risks
- **Supplemental Controls**: Implement additional controls as needed

**System-Specific Authorization**
- **System Security Plan**: Document system-specific implementation
- **Security Assessment**: Conduct independent assessment of system controls
- **Authorization Package**: Prepare complete authorization documentation
- **ATO Decision**: Obtain authorization from federal Authorizing Official

## Implementation Guidance

### Phase 1: Planning and Categorization (Weeks 1-2)
1. **System Categorization**: Determine impact levels using FIPS 199
2. **Control Selection**: Select appropriate control baseline
3. **Control Tailoring**: Tailor controls for specific system requirements
4. **Implementation Planning**: Develop implementation timeline and resources

### Phase 2: Implementation (Weeks 3-8)
1. **AWS Service Configuration**: Configure AWS services for FISMA compliance
2. **Security Control Implementation**: Deploy selected security controls
3. **Federal Identity Integration**: Implement PIV/CAC authentication
4. **Monitoring and Logging**: Enable comprehensive audit logging

### Phase 3: Assessment and Authorization (Weeks 9-16)
1. **Security Assessment**: Conduct independent security assessment
2. **Vulnerability Testing**: Perform vulnerability scanning and penetration testing
3. **Documentation**: Complete authorization package documentation
4. **Authorization**: Present to AO and obtain authorization decision

### Phase 4: Continuous Monitoring (Ongoing)
1. **Ongoing Assessment**: Regular security control assessments
2. **Configuration Monitoring**: Continuous configuration management
3. **Incident Response**: 24/7 incident detection and response
4. **Reporting**: Regular status reporting to oversight authorities

## Compliance Validation

### Assessment Criteria
**Control Implementation**
- **Fully Implemented**: Control is completely implemented and effective
- **Partially Implemented**: Control is implemented but has deficiencies
- **Not Implemented**: Control is not implemented or ineffective

**Risk Assessment**
- **Low Risk**: Minimal impact if control fails
- **Moderate Risk**: Significant impact if control fails  
- **High Risk**: Severe impact if control fails

### Evidence Requirements
**Documentation Evidence**
- **Policies and Procedures**: Documented and approved security procedures
- **Implementation Guides**: Detailed implementation documentation
- **Assessment Reports**: Independent assessment results
- **Authorization Documentation**: ATO and supporting materials

**Technical Evidence**
- **Configuration Screenshots**: System configuration evidence
- **Log Files**: Audit and security log samples
- **Test Results**: Security testing and validation results
- **Monitoring Data**: Continuous monitoring evidence

**Operational Evidence**
- **Training Records**: Personnel security training documentation
- **Incident Reports**: Security incident response documentation
- **Review Records**: Regular review and assessment evidence
- **Compliance Reports**: Ongoing compliance status reporting

### Common FISMA Compliance Challenges
**Identity Management**
- **Challenge**: Integrating PIV/CAC authentication with cloud services
- **Solution**: Use SAML federation and certificate-based authentication
- **AWS Support**: IAM SAML providers and certificate authentication

**Continuous Monitoring**
- **Challenge**: Implementing comprehensive continuous monitoring
- **Solution**: Automated monitoring with AWS Config and CloudWatch
- **AWS Support**: Native monitoring and compliance services

**Incident Response**
- **Challenge**: Meeting federal incident reporting requirements
- **Solution**: Automated incident detection and reporting workflows
- **AWS Support**: CloudWatch Events and SNS for automated notifications

**Audit and Accountability**
- **Challenge**: Comprehensive audit logging and retention
- **Solution**: Centralized logging with appropriate retention policies
- **AWS Support**: CloudTrail and CloudWatch Logs with S3 storage

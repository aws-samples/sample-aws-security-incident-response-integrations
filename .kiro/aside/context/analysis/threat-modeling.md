# Threat Modeling Context for Code Review

## Purpose
This document guides the ASIDE agent in performing threat modeling analysis during code review to **prevent insecure code generation** and **detect security issues early** in the development lifecycle. This is NOT for penetration testing or exploitation - it's for proactive security during code creation.

## Core Methodology: MAESTRO for Code Review

### M - Map the System
Before analyzing code, build a mental model:
```
1. Identify all entry points (HTTP routes, CLI args, file inputs, env vars)
2. Trace data flows from input to output
3. Identify trust boundaries (user ↔ app, app ↔ database, internal ↔ external)
4. Map authentication/authorization checkpoints
5. Identify sensitive data handling paths
```

**Output Required:**
- List of entry points with authentication requirements
- Data flow diagram (conceptual, can be text-based)
- Trust boundary crossings

### A - Analyze Attack Surface
For each entry point identified:
```
Entry Point Analysis Template:
- Path/Function: [location]
- Input Type: [user input, file, env, config]
- Validation Present: [yes/no/partial]
- Authentication Required: [yes/no]
- Authorization Checked: [yes/no]
- Data Sensitivity: [public/internal/confidential/restricted]
```

### E - Enumerate Threats (STRIDE + Reachability)
Apply STRIDE with **reachability verification** - a threat is only valid if there's a path from attacker-controlled input to the vulnerable code.

#### Reachability Classification (CRITICAL)
Every finding MUST include reachability analysis:

| Classification | Definition | Required Evidence |
|----------------|------------|-------------------|
| DIRECT | User input flows directly to vulnerable sink | Show the code path |
| EXPORTED | Vulnerable function is exported/public API | Show export + example usage |
| REFERENCED | Called by code that handles user input | Show call chain |
| INDIRECT | Multiple hops from user input | Document full path |
| UNDETERMINED | Cannot verify reachability | Mark for manual review |

### S - Select Mitigations
For each verified threat, identify:
1. **Preventive controls** - Stop the attack
2. **Detective controls** - Detect the attack
3. **Corrective controls** - Respond to the attack

### T - Test Coverage
Document what security testing should cover:
- Unit tests for validation functions
- Integration tests for auth flows
- Security-specific test cases

### R - Review Completeness
Checklist before completing analysis:
- [ ] All entry points analyzed
- [ ] All STRIDE categories considered for each entry point
- [ ] Reachability verified for each finding
- [ ] Mitigations identified
- [ ] No code sections skipped

### O - Output Documentation
Generate structured findings (format defined below)

---

## STRIDE Analysis Framework

### Spoofing Identity
**Code Review Focus:** Can an attacker impersonate a legitimate user or system?

**What to Look For:**
```
Authentication Bypasses:
- Missing auth middleware on routes
- Auth checks that can be skipped
- Hardcoded credentials
- Default passwords
- JWT without signature verification
- Session tokens without proper entropy

Patterns Indicating Risk:
- Routes without authentication decorators/middleware
- Auth functions that return true on error
- Token validation that catches exceptions and proceeds
```

**Questions for Code Review:**
1. Does this endpoint require authentication?
2. Is the auth check enforced at the right layer?
3. Can the auth check be bypassed through parameter manipulation?

### Tampering
**Code Review Focus:** Can data be modified without detection?

**What to Look For:**
```
Input Modification:
- SQL query string concatenation
- Command string building
- HTML/JS template insertion
- Path string manipulation
- Header injection points

Data Integrity:
- Missing input validation
- Client-side only validation
- Unsigned data in cookies/storage
- Missing checksums for critical data
```

**Sink Functions to Track:**
| Language | Dangerous Sinks |
|----------|-----------------|
| JavaScript | `eval()`, `Function()`, `exec()`, `execSync()`, `innerHTML` |
| Python | `eval()`, `exec()`, `os.system()`, `subprocess.call(shell=True)` |
| Java | `Runtime.exec()`, `ProcessBuilder`, `Statement.execute()` |
| TypeScript | Same as JavaScript + `dangerouslySetInnerHTML` |

### Repudiation
**Code Review Focus:** Can actions be performed without audit trail?

**What to Look For:**
```
Missing Audit:
- Security events without logging
- Sensitive operations without audit trail
- Log files without integrity protection
- Missing timestamps/user context in logs

Log Quality:
- PII in logs (privacy violation)
- Insufficient detail for forensics
- Log injection vulnerabilities
```

### Information Disclosure
**Code Review Focus:** Can sensitive data leak to unauthorized parties?

**What to Look For:**
```
Direct Disclosure:
- Sensitive data in error messages
- Debug info in production
- Comments with secrets
- API responses with extra fields
- Directory listing enabled

Indirect Disclosure:
- Timing attacks (different response times)
- Error message enumeration
- Predictable resource IDs
```

**Sensitive Data Patterns:**
```regex
# Secrets in code (check for these)
(?i)(password|secret|api[_-]?key|token|credential)[\s]*[=:][\s]*['\"][^'\"]+['\"]

# Hardcoded IPs/URLs that might be internal
\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b
```

### Denial of Service
**Code Review Focus:** Can the system be made unavailable?

**What to Look For:**
```
Resource Exhaustion:
- Unbounded loops with user input
- No pagination on list endpoints
- Missing timeouts on external calls
- Large file uploads without limits
- Regex with catastrophic backtracking

Algorithmic Complexity:
- O(n²) or worse with user-controlled n
- Hash collision vulnerable data structures
- XML entity expansion (billion laughs)
```

**ReDoS Pattern Detection:**
```
Dangerous regex patterns:
- Nested quantifiers: (a+)+
- Overlapping alternation: (a|a)+
- Star after group with multiple paths: (a|b)*c
```

### Elevation of Privilege
**Code Review Focus:** Can users gain unauthorized access?

**What to Look For:**
```
Authorization Flaws:
- Missing authorization after authentication
- Object-level authorization missing (IDOR)
- Function-level authorization missing
- Role checks client-side only
- Mass assignment vulnerabilities

Privilege Boundaries:
- Admin functions accessible to users
- Horizontal escalation between users
- Service accounts with excessive privileges
```

---

## Four Question Framework (Adam Shostack)

For each component under review, answer:

### 1. What are we working on?
- Technology stack
- Data handled
- Users and their roles
- External integrations
- Deployment environment

### 2. What can go wrong?
Apply STRIDE to each element:
- For each entry point → What threats apply?
- For each data store → What if compromised?
- For each external service → What if malicious?

### 3. What are we going to do about it?
- Identify existing mitigations
- Recommend new controls
- Prioritize by risk

### 4. Did we do a good job?
- Review completeness check
- Coverage metrics
- Residual risk assessment

---

## Threat Grammar Pattern

Use this structure for documenting threats:

```
[Threat Source] with [Prerequisites] can [Threat Action]
which leads to [Threat Impact]
negatively impacting [Impacted Assets]
```

**Examples:**
```
An unauthenticated attacker with network access can inject SQL through the search parameter
which leads to unauthorized database access
negatively impacting user PII and system integrity

A malicious user with valid credentials can modify other users' data via IDOR
which leads to data tampering
negatively impacting data integrity and user trust
```

---

## Integration with ASIDE Workflow

### Input Requirements
Before threat modeling, the agent needs:
1. **Project Fingerprint** - Technology stack, frameworks
2. **Component Map** - Logical components and boundaries
3. **Data Classification** - What data is handled where

### Output Artifacts

#### Threat Model Document Structure
```markdown
# Threat Model: [Component Name]

## System Overview
[Brief description of component]

## Data Flow Diagram
[Text-based or mermaid diagram]

## Trust Boundaries
| Boundary | Components | Data Crossing |
|----------|------------|---------------|

## Entry Points
| ID | Location | Auth Required | Input Type |
|----|----------|---------------|------------|

## Threat Analysis
### [Entry Point 1]
#### Spoofing
- Threat: [description]
- Reachability: [DIRECT/EXPORTED/REFERENCED/INDIRECT]
- Evidence: [code path]
- Mitigation: [control]
- Status: [Mitigated/At Risk/Accepted]

[Repeat for T-R-I-D-E]

## Risk Summary
| Threat ID | Category | Severity | Status |
|-----------|----------|----------|--------|

## Recommendations
1. [Prioritized list]
```

### Metrics Capture
After threat modeling, record:
```json
{
  "component": "component-name",
  "timestamp": "ISO-8601",
  "metrics": {
    "entry_points_analyzed": 0,
    "threats_identified": 0,
    "by_stride_category": {
      "spoofing": 0,
      "tampering": 0,
      "repudiation": 0,
      "information_disclosure": 0,
      "denial_of_service": 0,
      "elevation_of_privilege": 0
    },
    "reachability_classification": {
      "direct": 0,
      "exported": 0,
      "referenced": 0,
      "indirect": 0,
      "undetermined": 0
    },
    "mitigations_identified": 0,
    "coverage_percentage": 0
  }
}
```

Save to: `.kiro/aside/metrics/threat-model-[component]-[timestamp].json`

---

## Validation Hook Integration

Threat model findings inform validation hooks:

```yaml
# Example: Threat model identified SQL injection risk in UserService
# This generates a validation hook:

validation_rule:
  trigger: "src/services/UserService.ts"
  threats: ["SQL-001"]
  checks:
    - pattern: "query.*\\$\\{.*\\}"
      severity: high
      message: "Parameterize this query - identified as high-risk in threat model"
    - pattern: "execute.*\\+.*"
      severity: high
      message: "String concatenation in SQL detected"
```

---

## Cognitive Bias Mitigation

When performing threat analysis, actively counter:

1. **Confirmation Bias**: Don't just look for expected vulnerabilities
   - Check: "What would I find if I WANTED to exploit this?"

2. **Anchoring**: Don't fixate on first finding
   - Check: "Have I considered ALL STRIDE categories?"

3. **Availability Heuristic**: Don't focus only on recent/famous vulns
   - Check: "Am I checking the boring but dangerous stuff?"

4. **Optimism Bias**: Don't assume defenses work
   - Check: "What if this mitigation fails?"

---

## No-Truncation Policy

**CRITICAL**: Never skip code sections. If analysis would exceed context:
1. Document what was analyzed
2. Document what remains
3. Create checkpoint for continuation
4. Report partial coverage in metrics

Coverage tracking:
```
Files analyzed: 5/12
Functions analyzed: 23/47
Entry points covered: 8/8
Status: INCOMPLETE - checkpoint created
```

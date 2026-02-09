# Step 7: Security Validation & Steering Agent

## Persona

You are a **Security Automation Architect** with expertise in creating intelligent validation systems and contextual security guidance. You specialize in translating threat models into actionable validation rules and steering documents that provide real-time security guidance during development.

## Session Management

Follow the session management protocol in `session/session-management.md` for:
- Context loading and prioritization
- State persistence and checkpointing
- Error handling and recovery

For parallel operations, refer to `session/sub-agent-coordination.md`.

## Context References

Load the following context files as needed:
- `context/analysis/validation-patterns.md` for validation rule patterns
- `context/technology/[language]-security.md` based on detected languages
- Generated artifacts from Steps 1-6 (especially Threat_Model.md)

## Mission
Transform threat analysis into automated security validation and intelligent steering systems. Create project-specific validation hooks and contextual guidance documents that provide developers with real-time security feedback and proactive security recommendations.

## MCP Integration Framework
```javascript
// Enhanced MCP integration for real-time security guidance
const mcpSecurityIntegration = {
  // AppSec MCP integration for validation rules
  appsecValidation: async (fileContent, fileType, projectContext) => {
    const mcpResponse = await callMCPServer('appsec-mcp', {
      action: 'validateCode',
      content: fileContent,
      fileType: fileType,
      projectContext: projectContext,
      threatModel: loadThreatModel()
    });
    
    return {
      issues: mcpResponse.securityIssues,
      recommendations: mcpResponse.recommendations,
      confidence: mcpResponse.confidenceScore
    };
  },
  
  // Builder MCP integration for steering guidance
  builderSteering: async (userQuery, componentContext) => {
    const mcpResponse = await callMCPServer('builder-mcp', {
      action: 'getSecurityGuidance',
      query: userQuery,
      context: componentContext,
      technologies: getProjectTechnologies()
    });
    
    return {
      guidance: mcpResponse.securityGuidance,
      bestPractices: mcpResponse.bestPractices,
      codeExamples: mcpResponse.codeExamples
    };
  }
};
```

## Process

### 1. Global Security Steering Document

**CRITICAL**: Steering documents MUST use YAML frontmatter with `inclusion` mode per Kiro format.

```markdown
Create comprehensive global security guidance:

File: .kiro/steering/global-security.md

**Required YAML Frontmatter**:
---
inclusion: always
---

Content Structure (after frontmatter):
# Global Security Standards

## Universal Security Principles
- Defense in depth - never rely on single control
- Least privilege - minimum access required
- Fail secure - default to deny on errors

## Input Validation
- Validate all user inputs server-side
- Use parameterized queries for database access
- Implement proper output encoding for XSS prevention

## Authentication Best Practices
- Multi-factor authentication for admin access
- Session timeout: 30 minutes maximum
- JWT tokens with proper expiration and rotation

## Authorization Patterns
- Role-based access control (RBAC)
- Attribute-based access control (ABAC) for complex scenarios
- Authorization checks at every layer

## Cryptographic Standards
- Use industry-standard algorithms (AES-256, RSA-2048+)
- Secure key management practices
- Proper secret rotation

## Error Handling Guidelines
- Never expose stack traces to users
- Log errors with correlation IDs
- Generic error messages to users

## Logging and Monitoring Requirements
- Log all security-relevant events
- Include user identity, action, resource, timestamp
- Protect logs from tampering

## Implementation References
Link to actual project files:
#[[file:src/auth/index.ts]]
#[[file:src/middleware/security.ts]]
```

### 2. Component-Specific Steering Documents

**CRITICAL**: Use `fileMatch` inclusion mode with patterns from Component_Map.md

```markdown
For each component identified in Step 3, create specific guidance:

Authentication Component Steering:
File: .kiro/steering/authentication-security.md

**Required YAML Frontmatter**:
---
inclusion: fileMatch
fileMatchPattern: "src/auth/**/*"  # Derived from Component_Map paths
---

# Authentication Security

## Password Policy Enforcement
- Minimum 12 characters
- Require complexity (upper, lower, number, symbol)
- Bcrypt or Argon2 hashing only

## Session Management Security
- Secure session IDs (minimum 128-bit entropy)
- HttpOnly, Secure, SameSite flags
- Session invalidation on logout

## Token Handling Best Practices
- Short-lived access tokens (15 minutes)
- Refresh token rotation
- Secure token storage (never localStorage)

## Implementation References
#[[file:src/auth/authentication.ts]]
#[[file:src/auth/session.ts]]

---

Authorization Component Steering:
File: .kiro/steering/authorization-security.md

**Required YAML Frontmatter**:
---
inclusion: fileMatch
fileMatchPattern: "src/auth/permissions/**/*,src/middleware/authorize*"
---

# Authorization Security

## Role-Based Access Control
- Define roles based on job function
- Assign minimum required permissions
- Regular permission audits

## Privilege Escalation Prevention
- Validate all privilege changes
- Log authorization failures
- Rate limit role changes

---

Data Access Component Steering:
File: .kiro/steering/data-access-security.md

**Required YAML Frontmatter**:
---
inclusion: fileMatch
fileMatchPattern: "src/repositories/**/*,src/data/**/*,src/models/**/*"
---

# Data Access Security

## SQL Injection Prevention
- ALWAYS use parameterized queries
- NEVER concatenate user input into SQL
- Use ORM methods correctly

## Parameterized Query Examples
```sql
-- CORRECT: Parameterized
SELECT * FROM users WHERE id = ?

-- INCORRECT: String concatenation
SELECT * FROM users WHERE id = ' + userId
```

## Implementation References
#[[file:src/repositories/]]
#[[file:src/data/]]

---

API Component Steering:
File: .kiro/steering/api-security.md

**Required YAML Frontmatter**:
---
inclusion: fileMatch
fileMatchPattern: "src/api/**/*,src/routes/**/*,src/controllers/**/*"
---

# API Security

## Input Validation Requirements
- Validate all request parameters
- Use schema validation (Joi, Zod, etc.)
- Reject unexpected fields

## Rate Limiting Implementation
- Configure per-endpoint limits
- Return 429 status on limit exceeded
- Use sliding window algorithm

## CORS Configuration
- Whitelist specific origins
- Never use wildcard in production
- Validate credentials handling
```

### 3. Technology-Specific Steering

**CRITICAL**: Use `fileMatch` inclusion with technology-appropriate patterns.

```markdown
Based on technologies from Step 2, create technology guidance:

React Security Steering:
File: .kiro/steering/react-security.md

**Required YAML Frontmatter**:
---
inclusion: fileMatch
fileMatchPattern: "**/*.tsx,**/*.jsx,src/components/**/*"
---

# React Security Guidelines

## XSS Prevention in React
- React auto-escapes by default - don't disable
- NEVER use dangerouslySetInnerHTML with user input
- Sanitize any HTML before rendering

```jsx
// DANGEROUS - Never do this
<div dangerouslySetInnerHTML={{__html: userInput}} />

// SAFE - Use sanitization library
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />
```

## Client-Side Storage Security
- NEVER store tokens in localStorage (XSS vulnerable)
- Use httpOnly cookies for tokens
- Encrypt sensitive data before sessionStorage

---

Express.js Security Steering:
File: .kiro/steering/express-security.md

**Required YAML Frontmatter**:
---
inclusion: fileMatch
fileMatchPattern: "**/*.ts,**/*.js"
---

# Express.js Security Guidelines

## Middleware Security
- Use helmet for security headers
- Apply rate limiting (express-rate-limit)
- Validate all request bodies

```javascript
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

app.use(helmet());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
}));
```

## Route Protection Patterns
- Authenticate before authorization
- Use middleware for consistent checks
- Validate route parameters

---

Python/Django Security Steering:
File: .kiro/steering/django-security.md

**Required YAML Frontmatter**:
---
inclusion: fileMatch
fileMatchPattern: "**/*.py"
---

# Django Security Guidelines

## Django Security Settings
```python
# settings.py - Required security settings
DEBUG = False  # ALWAYS False in production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

## ORM Security Usage
- NEVER use raw() with user input
- Use parameterized queries only
- Validate all QuerySet filters
```

### 4. Threat-Specific Validation Hook Creation

**CRITICAL**: Validation hooks MUST be derived from threat model, not generic patterns.

## Threat-Derived Hook Generation Protocol

### BLOCKING RULE: No Generic Hooks

Every validation hook MUST:
1. Reference a specific THREAT-ID from Threat_Model.md
2. Target specific files identified in the threat (not wildcards)
3. Include the exact vulnerability location (file:line)
4. Specify concrete evidence requirements
5. Define what "mitigated" means for this specific threat

### DO NOT Generate This (Generic Hook):
```javascript
{
  "name": "SQL Injection Check",
  "when": {
    "patterns": ["**/*.ts", "**/*.js"]  // TOO BROAD
  },
  "then": {
    "prompt": "Check for SQL injection vulnerabilities"  // TOO VAGUE
  }
}
```

### INSTEAD Generate This (Threat-Derived Hook):
```javascript
{
  "name": "ASIDE: THREAT-005 SQL Injection - UserRepository",
  "description": "Validates mitigation of SQL injection in UserRepository.findByEmail()",
  "version": "1",
  "enabled": true,
  "when": {
    "type": "fileEdited",
    "patterns": ["src/repositories/UserRepository.ts"]  // SPECIFIC file from threat
  },
  "then": {
    "type": "askAgent",
    "prompt": `Validate THREAT-005 mitigation status:

**THREAT DETAILS** (from Threat_Model.md):
- ID: THREAT-005
- Type: SQL Injection (CWE-89)
- Location: src/repositories/UserRepository.ts:45
- Function: findByEmail()
- Attack Vector: POST /api/users → UserService.findUser() → UserRepository.findByEmail()
- Severity: HIGH (Sev3)
- CVSS: 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**SPECIFIC VERIFICATION STEPS**:
1. Read src/repositories/UserRepository.ts
2. Check line 45: Is the query now using Prisma.sql`` or parameterized format?
3. Trace the 'email' parameter: Does it still flow from user input to this query?
4. Check for any NEW raw queries added to this file

**EXPECTED SAFE PATTERN**:
\`\`\`typescript
const user = await prisma.$queryRaw(Prisma.sql\`SELECT * FROM users WHERE email = \${email}\`);
// OR
const user = await prisma.user.findUnique({ where: { email } });
\`\`\`

**EVIDENCE REQUIRED**:
- Current code at line 45 (show the actual code)
- Confirmation query is parameterized
- Confidence score with reasoning

**STATUS UPDATE**:
If mitigated: Output "THREAT-005: MITIGATED" with evidence
If still vulnerable: Output "THREAT-005: OPEN" with current code
If unclear: Output "THREAT-005: NEEDS_REVIEW" with questions`
  }
}
```

### Hook Generation Process

```markdown
For EACH HIGH/CRITICAL threat in Threat_Model.md:

1. **Extract Threat Details**:
   - Threat ID (THREAT-XXX)
   - Vulnerability type and CWE
   - Exact file and line number
   - Attack vector (how attacker reaches vulnerable code)
   - CVSS score and severity

2. **Determine Target Files**:
   - Use ONLY the specific file(s) from threat model
   - NO wildcards like **/*.ts
   - Pattern: "src/repositories/UserRepository.ts" not "src/repositories/**/*"

3. **Write Specific Prompt**:
   - Quote the threat details
   - List exact verification steps
   - Show expected safe pattern
   - Define evidence requirements
   - Specify status update format

4. **Generate Hook File**:
   - Name: aside-threat-[THREAT_ID].kiro.hook
   - Save to: .kiro/hooks/
```

### Hook-to-Threat Mapping

Maintain a mapping file for traceability:

```json
// .kiro/aside/generated/hook-threat-mapping.json
{
  "hooks": [
    {
      "hookFile": "aside-threat-005.kiro.hook",
      "threatId": "THREAT-005",
      "threatTitle": "SQL Injection in UserRepository",
      "targetFile": "src/repositories/UserRepository.ts",
      "targetLine": 45,
      "status": "active",
      "lastTriggered": null,
      "mitigationStatus": "open"
    },
    {
      "hookFile": "aside-threat-008.kiro.hook",
      "threatId": "THREAT-008",
      "threatTitle": "XSS in ProfileComponent",
      "targetFile": "src/components/ProfileComponent.tsx",
      "targetLine": 23,
      "status": "active",
      "lastTriggered": null,
      "mitigationStatus": "open"
    }
  ],
  "generated": "ISO-8601",
  "totalThreats": 12,
  "hooksGenerated": 12,
  "coverage": 1.0
}
```

### Hook Quality Verification

Before saving any hook, verify:

```javascript
const validateHook = (hook, threatModel) => {
  const checks = {
    // Must reference a real threat ID
    hasValidThreatId: /THREAT-\d+/.test(hook.then.prompt),

    // Must NOT use generic wildcards
    noGenericPatterns: !hook.when.patterns.some(p =>
      p.includes('**/*.') || p === '**/*'
    ),

    // Must include specific file path
    hasSpecificPath: hook.when.patterns.every(p =>
      p.includes('/') && !p.startsWith('**/')
    ),

    // Prompt must include line number
    hasLineNumber: /:\d+/.test(hook.then.prompt),

    // Prompt must define evidence requirements
    hasEvidenceReqs: hook.then.prompt.includes('EVIDENCE REQUIRED'),

    // Prompt must define status update format
    hasStatusFormat: /THREAT-\d+: (MITIGATED|OPEN|NEEDS_REVIEW)/.test(hook.then.prompt),

    // Must map to a threat in the threat model
    threatExists: threatModel.threats.some(t =>
      hook.then.prompt.includes(t.id)
    )
  };

  const allPassed = Object.values(checks).every(v => v === true);

  if (!allPassed) {
    const failures = Object.entries(checks)
      .filter(([k, v]) => !v)
      .map(([k]) => k);
    console.error(`Hook validation failed: ${failures.join(', ')}`);
    return { valid: false, failures };
  }

  return { valid: true };
};
```

```markdown
Process:
1. Load Threat_Model.md from Step 5
2. Extract identified threats per component type
3. Generate hooks that validate against SPECIFIC threats
4. File patterns must match project's actual structure
```

**Generate Threat-Derived Hooks**:

For each HIGH/CRITICAL threat in Threat_Model.md, create targeted validation:

```javascript
// Example: If threat model identifies "SQL Injection in UserRepository"
const threatBasedHook = {
  "name": "ASIDE: SQL Injection - Data Access Components",
  "description": "Validates against THREAT-005: SQL Injection in data access layer",
  "version": "1",
  "enabled": true,
  "when": {
    "type": "fileEdited",
    // Patterns from actual project structure, NOT generic
    "patterns": ["src/repositories/**/*.ts", "src/data/**/*.ts", "lib/db/**/*.js"]
  },
  "then": {
    "type": "askAgent",
    "prompt": `Validate this file against THREAT-005 (SQL Injection):

#data-security

**Specific Checks from Threat Model**:
1. All database queries use parameterized statements
2. No string concatenation in SQL construction
3. ORM methods used correctly (no raw queries without parameters)
4. User input sanitized before reaching data layer

**Evidence Required**:
- Line numbers of potential issues
- Confidence score based on pattern match strength
- Specific remediation for this codebase's ORM/database library

Focus on implementation correctness, not exploitation.`
  }
};
```

**Hook Generation Per Threat Category**:

| Threat Category | Hook Name Pattern | File Patterns From |
|----------------|-------------------|-------------------|
| Authentication | `auth-[threat-id].kiro.hook` | Component_Map auth components |
| SQL Injection | `sqli-[threat-id].kiro.hook` | Component_Map data-access paths |
| XSS | `xss-[threat-id].kiro.hook` | Component_Map frontend paths |
| SSRF | `ssrf-[threat-id].kiro.hook` | Component_Map integration paths |
| Access Control | `authz-[threat-id].kiro.hook` | Component_Map authorization paths |

**File Pattern Derivation**:
```markdown
DO NOT use generic patterns like "**/*.ts"

INSTEAD, derive from Component_Map.md:
1. Read component locations from Component_Map
2. Extract actual file paths for each component type
3. Use those specific paths in hook patterns

Example:
- Component_Map shows AuthService at "src/services/auth/"
- Hook pattern: "src/services/auth/**/*.ts"
- NOT: "**/*.ts" (too broad, causes false positives)
```

### 5. Steering Hook Creation
```
Create contextual steering hook:

File: .kiro/hooks/security-steering.kiro.hook

Hook Configuration:
{
  "name": "ASIDE Security Steering",
  "version": "1",
  "enabled": true,
  "when": {
    "type": "promptSubmit",
    "patterns": ["security", "auth", "database", "api", "encrypt"]
  },
  "then": {
    "type": "askAgent",
    "prompt": "Load relevant steering documents from .kiro/steering/ based on user query context and provide targeted security guidance."
  }
}

Steering Logic:
- Context-aware guidance selection
- Multi-document synthesis
- User query analysis
- Relevant best practice injection
- Proactive security recommendations
```

### 6. Drift Detection Hook
```
Create drift monitoring hook:

File: .kiro/hooks/security-drift.kiro.hook

Hook Configuration:
{
  "name": "ASIDE Security Drift Detection",
  "version": "1",
  "enabled": true,
  "when": {
    "type": "fileEdited",
    "patterns": [
      "package.json", "requirements.txt", "Cargo.toml",
      "pom.xml", "go.mod", "composer.json"
    ]
  },
  "then": {
    "type": "askAgent",
    "prompt": "Load drift detection prompt from [EXTENSION_PATH]/prompts/maintenance/drift-detection.md and assess security impact of dependency changes."
  }
}

Drift Detection Logic:
- Dependency change analysis
- Security impact assessment
- New vulnerability introduction
- Configuration drift detection
- Incremental threat model updates
```

### 7. Issue Management Hook
```
Create issue management hook:

File: .kiro/hooks/security-issues.kiro.hook

Hook Configuration:
{
  "name": "ASIDE Issue Management",
  "version": "1",
  "enabled": true,
  "when": {
    "type": "userTriggered"
  },
  "then": {
    "type": "askAgent",
    "prompt": "Load issue triage prompt from [EXTENSION_PATH]/prompts/maintenance/issue-triage.md and manage security issues lifecycle."
  }
}

Issue Management Logic:
- Issue classification and prioritization
- False positive identification
- Remediation guidance generation
- Issue lifecycle tracking
- Metrics collection and reporting
```

### 8. Steering Document Content Generation

**CRITICAL**: All steering documents MUST follow Kiro format with YAML frontmatter.

**CRITICAL**: Steering documents MUST be PROJECT-SPECIFIC, not generic templates.

## Project-Specific Steering Generation Protocol

### MANDATORY: No Generic Content

Steering documents are NOT templates. They MUST contain:

1. **Actual File References** from Component_Map.md and profiling
2. **Actual Code Snippets** found during analysis
3. **Actual Line Numbers** where issues exist
4. **Project-Specific Test Cases** based on the codebase

### DO NOT Generate This (Generic Template):
```markdown
## SQL Injection Prevention
- ALWAYS use parameterized queries
- NEVER concatenate user input into SQL
- Use ORM methods correctly
```

### INSTEAD Generate This (Project-Specific):
```markdown
## SQL Injection Prevention for [Project Name]

### This Project's Data Layer
Based on Component_Map analysis:
- **ORM**: Prisma (src/db/prisma.ts)
- **Raw Queries Found**: 2 locations requiring attention
  - `src/repositories/UserRepository.ts:45`
  - `src/repositories/OrderRepository.ts:78`
- **Connection Pool**: src/config/database.ts

### Specific Issues Found in This Codebase

#### Issue 1: UserRepository.ts:45
```typescript
// CURRENT CODE (DANGEROUS)
const user = await prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
```

**Problem**: Template literal in $queryRaw doesn't parameterize by default.

**Required Fix**:
```typescript
// FIXED CODE (SAFE)
const user = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE email = ${email}`
);
```

#### Issue 2: OrderRepository.ts:78
```typescript
// CURRENT CODE (DANGEROUS)
const orders = await db.query(`SELECT * FROM orders WHERE user_id = '${userId}'`);
```

**Required Fix**:
```typescript
// FIXED CODE (SAFE)
const orders = await db.query('SELECT * FROM orders WHERE user_id = $1', [userId]);
```

### Verification Test Cases

For each fixed location, verify with these tests:

| Test ID | Input | Expected Behavior | Pass Criteria |
|---------|-------|-------------------|---------------|
| SQLi-001 | `' OR '1'='1` | Query parameterization | No extra rows returned |
| SQLi-002 | `'; DROP TABLE users; --` | Query parameterization | No SQL execution |
| SQLi-003 | `\x00admin` | Input validation | Null byte rejected |

### Verification Checklist
- [ ] UserRepository.ts:45 - Converted to Prisma.sql
- [ ] OrderRepository.ts:78 - Converted to parameterized query
- [ ] No new raw queries added without review
- [ ] All tests in test/security/sql-injection.test.ts pass
```

### Content Derivation Rules

| Content Type | Source | Example |
|--------------|--------|---------|
| File paths | Component_Map.md | `src/repositories/UserRepository.ts` |
| Line numbers | Component profiles | `:45`, `:78` |
| Code snippets | Actual file content | Read and quote actual code |
| Technology names | Project_Fingerprint.md | Prisma, Express, React |
| Test cases | Based on found patterns | Specific inputs for found vulnerabilities |

### Template Variables to Replace

When generating steering documents, replace these with actual values:

```markdown
[PROJECT_NAME] → From Project_Fingerprint.md
[FILE_PATH] → From Component_Map.md component locations
[LINE_NUMBER] → From component profile vulnerability locations
[CODE_SNIPPET] → Read actual code from file
[ORM_NAME] → From technology detection
[THREAT_ID] → From Threat_Model.md
[FIX_CODE] → Generate based on technology and best practices
```

### Quality Gate for Steering Documents

Before saving a steering document, verify:

```javascript
const validateSteeringDoc = (content, componentMap, profiles) => {
  const checks = {
    hasActualFilePaths: /src\/|lib\/|app\//.test(content),
    hasLineNumbers: /:\d+/.test(content),
    hasCodeSnippets: /```(typescript|javascript|python|go)/.test(content),
    referencesActualComponents: componentMap.components.some(c =>
      content.includes(c.path)
    ),
    noGenericPhrases: ![
      'your application',
      'your codebase',
      '[FILE_PATH]',
      '[PROJECT_NAME]'
    ].some(phrase => content.includes(phrase))
  };

  const allPassed = Object.values(checks).every(v => v === true);

  if (!allPassed) {
    console.error('Steering document quality check failed:', checks);
    return { valid: false, failures: checks };
  }

  return { valid: true };
};
```

```markdown
For each steering document, include:

**Required YAML Frontmatter** (choose appropriate inclusion mode):

For global docs:
---
inclusion: always
---

For component-specific docs:
---
inclusion: fileMatch
fileMatchPattern: "path/from/Component_Map/**/*"
---

For manual reference docs:
---
inclusion: manual
---
(Access via #document-name hashtag)

**Document Structure** (after frontmatter):

# [Component] Security Guidance

## Overview
- Component purpose and security context
- Key security considerations
- Common vulnerability patterns

## Security Requirements
- Mandatory security controls
- Implementation standards
- Validation criteria

## Best Practices
- Recommended implementation patterns
- Security-by-design principles
- Performance considerations

## Common Vulnerabilities
- Vulnerability descriptions
- Prevention techniques (NOT attack scenarios)
- Code pattern recognition

## Code Examples
```language
// SECURE: Example with explanation
const secure = sanitize(input);

// INSECURE: Pattern to avoid
const insecure = input; // Never do this
```

## Implementation References
Link to actual project files for context:
#[[file:src/relevant/path.ts]]
#[[file:src/related/file.ts]]

## Validation Checklist
- [ ] Security control implemented
- [ ] Input validation present
- [ ] Output encoding applied
- [ ] Error handling secure
- [ ] Logging implemented

## References
- Relevant standards and guidelines
- Framework-specific documentation
```

### 9. Hook Integration Testing
```
Test hook functionality:

Validation Hook Testing:
1. Edit a file with known security issue
2. Verify hook triggers automatically
3. Confirm security analysis runs
4. Validate issue detection accuracy
5. Check remediation guidance quality

Steering Hook Testing:
1. Submit security-related query
2. Verify relevant steering documents loaded
3. Confirm contextual guidance provided
4. Validate multi-document synthesis
5. Check guidance relevance and accuracy

Drift Detection Testing:
1. Modify dependency file
2. Verify drift hook triggers
3. Confirm security impact analysis
4. Validate change assessment accuracy
5. Check incremental update recommendations
```

## Output Requirements
Generate validation and steering system:
```markdown
# Validation & Steering Implementation Report

## Global Security Steering
- **File**: .kiro/steering/global-security.md
- **Content**: Universal security principles and guidelines
- **Size**: [FILE_SIZE]
- **Sections**: [SECTION_COUNT]

## Component-Specific Steering
### [Component Name]
- **File**: .kiro/steering/[component]-security.md
- **Content**: Component-specific security guidance
- **Vulnerabilities Covered**: [COUNT]
- **Best Practices**: [COUNT]

## Technology-Specific Steering
### [Technology Name]
- **File**: .kiro/steering/[technology]-security.md
- **Content**: Technology-specific security patterns
- **Framework Version**: [VERSION]
- **Security Features**: [COUNT]

## Validation Hooks
### Security Validation Hook
- **File**: .kiro/hooks/security-validation.kiro.hook
- **Trigger**: File edit events
- **File Patterns**: [PATTERN_COUNT] patterns
- **Validation Rules**: [RULE_COUNT] rules

### Security Steering Hook
- **File**: .kiro/hooks/security-steering.kiro.hook
- **Trigger**: Prompt submission
- **Context Keywords**: [KEYWORD_COUNT] keywords
- **Steering Documents**: [DOCUMENT_COUNT] documents

### Drift Detection Hook
- **File**: .kiro/hooks/security-drift.kiro.hook
- **Trigger**: Dependency file changes
- **Monitored Files**: [FILE_COUNT] files
- **Change Patterns**: [PATTERN_COUNT] patterns

## Hook Testing Results
- **Validation Hook**: [PASS/FAIL] - [DETAILS]
- **Steering Hook**: [PASS/FAIL] - [DETAILS]
- **Drift Detection Hook**: [PASS/FAIL] - [DETAILS]
- **Integration Test**: [PASS/FAIL] - [DETAILS]

## Coverage Metrics
- **Components Covered**: [PERCENTAGE]%
- **Technologies Covered**: [PERCENTAGE]%
- **Vulnerabilities Addressed**: [COUNT]
- **Best Practices Documented**: [COUNT]

## Quality Metrics
- **Steering Document Quality**: [SCORE/10]
- **Hook Responsiveness**: [SCORE/10]
- **Validation Accuracy**: [SCORE/10]
- **False Positive Rate**: [PERCENTAGE]%
```

## Success Criteria
1. ✅ Global security steering document created
2. ✅ Component-specific steering documents generated
3. ✅ Technology-specific steering documents created
4. ✅ Security validation hook implemented
5. ✅ Security steering hook configured
6. ✅ Drift detection hook established
7. ✅ Issue management hook created
8. ✅ All hooks tested and validated
9. ✅ Steering document quality verified
10. ✅ Integration testing completed

---

## STEP COMPLETION GATE

**MANDATORY**: This gate MUST be passed before proceeding to Step 8 (System Finalization).

### Completion Checklist

Before proceeding, verify ALL of the following are complete:

#### Steering Documents (MUST Use Kiro YAML Frontmatter Format)
- [ ] Global security steering created at `.kiro/steering/global-security.md`
- [ ] Global steering has `inclusion: always` YAML frontmatter
- [ ] Component-specific steering docs created for each high-risk component
- [ ] Component steering docs have `inclusion: fileMatch` with `fileMatchPattern`
- [ ] File patterns in steering derived from Component_Map.md paths
- [ ] Technology-specific steering docs created for detected technologies
- [ ] Steering docs reference actual threats from Threat_Model.md
- [ ] All steering docs include `#[[file:path]]` implementation references

#### Validation Hooks (MUST Be Threat-Specific)
- [ ] Each HIGH/CRITICAL threat from Threat_Model.md has corresponding hook
- [ ] Hook names include threat ID (e.g., "ASIDE: THREAT-005 SQL Injection")
- [ ] File patterns derived from Component_Map.md paths (NOT generic **/*)
- [ ] Hook prompts cite specific threat checks from threat model
- [ ] Validation rules reference actual threat mitigations identified
- [ ] No generic "check for security issues" prompts - all threat-specific

#### Drift Detection Hook
- [ ] Drift hook monitors project-specific critical paths
- [ ] Dependency files specific to detected languages monitored
- [ ] Security-relevant config files monitored
- [ ] Hook triggers delta updates not full re-init

#### Issue Management Hook
- [ ] Issue management hook created
- [ ] Issue folder structure established (active/testing/resolved)

#### Hook Quality Verification
- [ ] All hooks have valid JSON schema
- [ ] All hooks have name, description, version, enabled fields
- [ ] Hook file patterns validated against actual project structure
- [ ] No hardcoded generic patterns (patterns derived from analysis)

#### Required Artifacts Generated
- [ ] All hooks saved to `.kiro/hooks/`
- [ ] All steering docs saved to `.kiro/steering/`
- [ ] Hook testing results documented
- [ ] Session state updated

### Gate Verification

```javascript
const gateCheck = {
  globalSteeringExists: await fs_exists('.kiro/steering/global-security.md'),
  globalSteeringHasYamlFrontmatter: await verifyYamlFrontmatter('.kiro/steering/global-security.md', 'always'),
  componentSteeringHasFileMatch: await verifyAllComponentSteeringHasFileMatch('.kiro/steering/'),
  validationHookExists: await fs_exists('.kiro/hooks/security-validation.kiro.hook'),
  driftHookExists: await fs_exists('.kiro/hooks/security-drift.kiro.hook'),
  hooksValidSchema: await validateAllHookSchemas('.kiro/hooks/'),
  hooksDerivedFromThreats: await verifyHooksThreatAlignment(),
  steeringDerivedFromThreats: await verifySteeringThreatAlignment(),
  sessionUpdated: await verifySessionState('step7-complete')
};

// Helper to verify YAML frontmatter format
async function verifyYamlFrontmatter(filePath, expectedInclusion) {
  const content = await fs_read(filePath);
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (!frontmatterMatch) return false;
  return frontmatterMatch[1].includes(`inclusion: ${expectedInclusion}`);
}

const canProceed = Object.values(gateCheck).every(v => v === true);
```

### Session State Update

After passing gate, update session state:

```json
{
  "step7": {
    "status": "complete",
    "completedAt": "ISO-8601",
    "gatesPassed": true,
    "outputs": {
      "hooksDirectory": ".kiro/hooks/",
      "steeringDirectory": ".kiro/steering/"
    },
    "metrics": {
      "steeringDocsCreated": 0,
      "hooksCreated": 0,
      "componentsWithSteering": 0,
      "technologiesWithSteering": 0
    }
  }
}
```

---

**NEXT STEP**: Only after passing this gate, proceed to `step8-steering-docs.md`

Pass validation and steering system to Step 8 (System Finalization) for system finalization and cleanup procedures.

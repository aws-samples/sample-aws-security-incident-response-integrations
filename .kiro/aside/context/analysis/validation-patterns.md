# Security Validation Patterns

## Purpose
Concrete detection patterns for the ASIDE agent to identify security issues during code review. Each pattern includes regex, context requirements, and false positive guidance.

---

## Injection Vulnerabilities

### SQL Injection

**Pattern ID:** `ASIDE-INJ-001`

```javascript
// DANGEROUS - String concatenation in queries
const query = `SELECT * FROM users WHERE id = ${userId}`;
const query = "SELECT * FROM users WHERE id = " + userId;
db.query("SELECT * FROM users WHERE email = '" + email + "'");
```

**Detection Regex (JavaScript/TypeScript):**
```regex
(query|execute|sql)\s*\(\s*[`'"].*\$\{.*\}.*[`'"]
(query|execute|sql)\s*\(\s*[`'"].*\s*\+\s*
```

**Safe Patterns:**
```javascript
// SAFE - Parameterized queries
db.query("SELECT * FROM users WHERE id = $1", [userId]);
db.query("SELECT * FROM users WHERE id = ?", [userId]);
prisma.user.findUnique({ where: { id: userId } });
```

**False Positive Indicators:**
- Concatenation of constants only: `"SELECT * FROM " + TABLE_NAME` (if TABLE_NAME is const)
- Logging statements: `console.log("Query: " + query)`
- Comments or documentation strings

**Reachability Required:** Must trace `userId` back to user input

---

### Command Injection

**Pattern ID:** `ASIDE-INJ-002`

```javascript
// DANGEROUS
exec(`ls ${userPath}`);
execSync(command + userInput);
child_process.spawn(shell, ['-c', userCommand]);
```

**Detection Regex:**
```regex
exec(Sync)?\s*\(\s*[`'"].*\$\{
exec(Sync)?\s*\(\s*.*\+
spawn\s*\(.*shell.*,.*\[.*-c
```

**Safe Patterns:**
```javascript
// SAFE - Array arguments, no shell
execFile('ls', ['-la', validatedPath]);
spawn('node', ['script.js', '--arg', sanitizedValue], { shell: false });
```

---

### Path Traversal

**Pattern ID:** `ASIDE-INJ-003`

```javascript
// DANGEROUS
fs.readFile(req.params.filename);
fs.readFile(path.join(baseDir, userInput));  // Still dangerous!
```

**Detection Regex:**
```regex
(readFile|writeFile|createReadStream|unlink)\s*\(\s*(req\.|params\.|query\.)
path\.join\s*\(.*,\s*(req\.|params\.|query\.|user)
```

**Safe Patterns:**
```javascript
// SAFE - Validate resolved path stays within allowed directory
const resolved = path.resolve(baseDir, userInput);
if (!resolved.startsWith(path.resolve(baseDir))) {
    throw new Error('Path traversal attempt');
}
fs.readFile(resolved);
```

---

## Authentication Flaws

### Missing Auth Middleware

**Pattern ID:** `ASIDE-AUTH-001`

```javascript
// SUSPICIOUS - No auth middleware
router.post('/api/admin/users', createUser);
router.delete('/api/users/:id', deleteUser);

// EXPECTED - With auth
router.post('/api/admin/users', authMiddleware, adminOnly, createUser);
```

**Detection Logic:**
```
For routes matching: /api/*, /admin/*, /private/*
Check: Does middleware chain include auth function?
Auth indicators: authMiddleware, requireAuth, isAuthenticated, passport.authenticate
```

---

### Weak Password Requirements

**Pattern ID:** `ASIDE-AUTH-002`

```javascript
// WEAK
if (password.length >= 6) { ... }
/^.{4,}$/.test(password)

// STRONG
if (password.length >= 12 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password))
```

**Detection Regex:**
```regex
password.*\.length\s*>=?\s*[1-9](?![0-9])   # Length check < 10
/\^\.{[1-9],/                                 # Regex with short min
```

---

### JWT Without Verification

**Pattern ID:** `ASIDE-AUTH-003`

```javascript
// DANGEROUS - No verification
const decoded = jwt.decode(token);  // decode() doesn't verify!

// SAFE
const decoded = jwt.verify(token, secretKey);
```

**Detection Regex:**
```regex
jwt\.decode\s*\(        # decode without verify
algorithms:\s*\[.*none  # Allowing 'none' algorithm
```

---

## Sensitive Data Exposure

### Hardcoded Secrets

**Pattern ID:** `ASIDE-DATA-001`

**Detection Regex:**
```regex
# API Keys
(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]

# Passwords
(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]

# AWS Keys
(?i)AKIA[0-9A-Z]{16}

# Private Keys
-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----

# JWT Secrets
(?i)(jwt[_-]?secret|token[_-]?secret)\s*[:=]\s*['\"][^'\"]+['\"]
```

**False Positive Indicators:**
- Environment variable reference: `process.env.API_KEY`
- Placeholder values: `'your-api-key-here'`, `'CHANGEME'`
- Test files: `*.test.js`, `*.spec.ts`

---

### PII in Logs

**Pattern ID:** `ASIDE-DATA-002`

```javascript
// DANGEROUS
console.log('User data:', user);
logger.info(`Login attempt for ${email}`);

// SAFE
console.log('User data:', { id: user.id, role: user.role });
logger.info(`Login attempt for user ID: ${user.id}`);
```

**Detection Logic:**
```
In logging contexts (console.*, logger.*):
Flag if logging: email, password, ssn, creditCard, phoneNumber, address
Except: When explicitly masked or using only IDs
```

---

## XSS Vulnerabilities

### React dangerouslySetInnerHTML

**Pattern ID:** `ASIDE-XSS-001`

```jsx
// DANGEROUS
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// NEEDS REVIEW - Check if sanitized
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />
```

**Detection Regex:**
```regex
dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*(?!DOMPurify)
```

---

### innerHTML Assignment

**Pattern ID:** `ASIDE-XSS-002`

```javascript
// DANGEROUS
element.innerHTML = userInput;
document.getElementById('content').innerHTML = data.html;

// SAFE
element.textContent = userInput;
```

**Detection Regex:**
```regex
\.innerHTML\s*=\s*(?!['"`]<)  # innerHTML assigned from variable
```

---

## Validation Rule Schema

```json
{
  "id": "ASIDE-INJ-001",
  "category": "injection",
  "subcategory": "sql",
  "severity": "high",
  "owasp": "A03:2021",
  "cwe": "CWE-89",

  "detection": {
    "type": "regex",
    "patterns": ["..."],
    "languages": ["javascript", "typescript"],
    "file_patterns": ["*.js", "*.ts"],
    "exclude_patterns": ["*.test.*", "*.spec.*"]
  },

  "context_requirements": {
    "reachability": "required",
    "data_flow": "user_input_to_sink"
  },

  "false_positive_checks": [
    "constant_concatenation",
    "logging_context",
    "test_file"
  ],

  "remediation": {
    "description": "Use parameterized queries",
    "example_before": "db.query(`SELECT * FROM users WHERE id = ${id}`)",
    "example_after": "db.query('SELECT * FROM users WHERE id = $1', [id])"
  }
}
```

---

## Issue Output Format

```json
{
  "id": "ASIDE-[timestamp]-[hash]",
  "rule_id": "ASIDE-INJ-001",
  "severity": "high",
  "confidence": 0.85,

  "location": {
    "file": "src/services/UserService.ts",
    "line": 42,
    "column": 12,
    "function": "findUserByEmail"
  },

  "finding": {
    "title": "SQL Injection via String Concatenation",
    "description": "User input flows to SQL query without parameterization",
    "code_snippet": "const query = `SELECT * FROM users WHERE email = '${email}'`;",
    "data_flow": [
      "req.body.email (line 38)",
      "email parameter (line 40)",
      "query string (line 42)"
    ]
  },

  "reachability": {
    "classification": "DIRECT",
    "path": "POST /api/users → findUserByEmail → query"
  },

  "remediation": {
    "suggestion": "Use parameterized query",
    "fixed_code": "const query = 'SELECT * FROM users WHERE email = $1';\ndb.query(query, [email]);"
  },

  "status": "active"
}
```

---

## Confidence Scoring

| Factor | Impact |
|--------|--------|
| Pattern match in production code | +0.3 |
| User input traced to sink | +0.3 |
| No sanitization found in path | +0.2 |
| Known dangerous function | +0.2 |
| In test file | -0.5 |
| Contains sanitization call | -0.3 |
| Constant values only | -0.4 |

**Threshold:** Report if confidence >= 0.6

---

## Metrics Capture

After validation run:
```json
{
  "timestamp": "ISO-8601",
  "files_scanned": 0,
  "patterns_checked": 0,
  "findings": {
    "total": 0,
    "by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
    "by_category": { "injection": 0, "auth": 0, "data": 0, "xss": 0 }
  },
  "false_positives_filtered": 0,
  "coverage_percentage": 0
}
```

Save to: `.kiro/aside/metrics/validation-[timestamp].json`

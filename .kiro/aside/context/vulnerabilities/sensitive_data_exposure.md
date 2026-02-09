# Sensitive Data Exposure (CWE-200)

## Vulnerability Overview
- **CWE**: CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP**: A02:2021 - Cryptographic Failures
- **Severity**: High
- **CVSS Base**: 7.5

## Detection Patterns

### Hardcoded Secrets

**Dangerous Patterns:**
```javascript
// API keys in code
const apiKey = 'sk_live_abcd1234xyz';
const apiKey = 'AIzaSyA1B2C3D4E5F6G7H8I9J0K';
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

// Passwords in code
const dbPassword = 'myPassword123!';
const adminPassword = 'admin@123';

// JWT secrets
const secret = 'my-jwt-secret-key';
jwt.sign(payload, 'supersecretkey');

// Private keys (EXAMPLE - DO NOT USE REAL KEYS)
const privateKey = `[PRIVATE_KEY_CONTENT_HERE]`;
```

**Safe Patterns:**
```javascript
// Environment variables
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;
const jwtSecret = process.env.JWT_SECRET;

// AWS Secrets Manager
const secretValue = await secretsManager.getSecretValue({ SecretId: 'my-secret' });

// Azure Key Vault / HashiCorp Vault
const secret = await vault.getSecret('api-key');
```

### PII in Logs

**Dangerous Patterns:**
```javascript
// Logging sensitive data
console.log('User login:', { email, password, ssn });
console.log(`Processing payment for card ${cardNumber}`);
logger.info('User data:', JSON.stringify(user));

// Error messages with PII
throw new Error(`Invalid credentials for ${email}: ${password}`);

// Debug logging in production
console.log('Request body:', req.body);
```

**Safe Patterns:**
```javascript
// Redacted logging
console.log('User login:', { email: maskEmail(email), userId: user.id });
logger.info('Processing payment', { cardLastFour: cardNumber.slice(-4) });

// Structured logging without PII
logger.info({
  action: 'user_login',
  userId: user.id,
  timestamp: new Date().toISOString()
});

// Log only IDs
console.log(`User ${userId} logged in`);
```

### Insecure Data Transmission

**Dangerous Patterns:**
```javascript
// HTTP instead of HTTPS
fetch('http://api.example.com/data');
axios.get('http://insecure-api.com/users');

// Sending sensitive data in URL
fetch(`/api/login?username=${user}&password=${pass}`);
window.location.href = `/reset?email=${email}`;

// Insecure WebSocket
const ws = new WebSocket('ws://example.com/socket');
```

**Safe Patterns:**
```javascript
// HTTPS only
fetch('https://api.example.com/data');

// Sensitive data in body
fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ username, password }),
  headers: { 'Content-Type': 'application/json' }
});

// Secure WebSocket
const ws = new WebSocket('wss://example.com/socket');
```

### Improper Error Handling

**Dangerous Patterns:**
```javascript
// Stack traces in responses
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});

// Detailed error messages
catch (error) {
  res.status(500).json({
    error: error.message,
    query: sqlQuery,
    params: requestParams
  });
}

// Database errors exposed
res.status(500).send(`Database error: ${err.message}`);
```

**Safe Patterns:**
```javascript
// Generic error responses
app.use((err, req, res, next) => {
  console.error(err);  // Log internally

  res.status(500).json({
    error: 'An internal error occurred',
    requestId: req.id  // For support correlation
  });
});

// Environment-aware errors
const isDev = process.env.NODE_ENV === 'development';
res.status(500).json({
  error: isDev ? err.message : 'Internal server error'
});
```

## Detection Regex

```regex
# API keys
(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]

# AWS keys
AKIA[0-9A-Z]{16}

# Private keys
-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----

# Passwords
(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]{4,}['\"]

# JWT secrets
(?i)(jwt[_-]?secret|token[_-]?secret)\s*[:=]\s*['\"][^'\"]+['\"]

# PII in logs
(console\.(log|error|warn)|logger\.(info|warn|error|debug))\s*\([^)]*(?i)(password|ssn|creditcard|card.?number|email)

# HTTP URLs (should be HTTPS)
(?<!localhost)(?<!127\.0\.0\.1)https?://[a-zA-Z0-9.-]+\.[a-z]{2,}
```

## Sensitive Data Categories

| Category | Examples | Detection Keywords |
|----------|----------|-------------------|
| Authentication | Passwords, tokens, API keys | password, token, apiKey, secret |
| PII | SSN, DOB, address | ssn, dateOfBirth, socialSecurity |
| Financial | Credit card, bank account | cardNumber, cvv, accountNumber |
| Health | Medical records, diagnoses | healthRecord, diagnosis, medicalId |
| Location | GPS coordinates, IP addresses | latitude, longitude, ipAddress |

## False Positive Indicators

- **Environment variable reference**: `process.env.API_KEY`
- **Placeholder values**: `'your-api-key-here'`, `'CHANGEME'`, `'xxx'`
- **Test files**: `*.test.js`, `*.spec.ts`, `__tests__/*`
- **Config templates**: `.env.example`, `config.template.js`
- **Documentation**: Markdown files, comments explaining patterns

## Remediation

### Secret Management
```javascript
// Use environment variables
const config = {
  apiKey: process.env.API_KEY,
  dbPassword: process.env.DB_PASSWORD,
  jwtSecret: process.env.JWT_SECRET
};

// Validate required secrets on startup
const requiredEnvVars = ['API_KEY', 'DB_PASSWORD', 'JWT_SECRET'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
}
```

### Data Masking Utilities
```javascript
const maskEmail = (email) => {
  const [local, domain] = email.split('@');
  return `${local.slice(0, 2)}***@${domain}`;
};

const maskCard = (cardNumber) => {
  return `****-****-****-${cardNumber.slice(-4)}`;
};

const maskSensitiveData = (data) => {
  const sensitiveFields = ['password', 'ssn', 'cardNumber', 'cvv'];
  const masked = { ...data };

  for (const field of sensitiveFields) {
    if (masked[field]) {
      masked[field] = '***REDACTED***';
    }
  }

  return masked;
};
```

### Secure Configuration
```javascript
// .gitignore
// .env
// *.pem
// *.key

// Pre-commit hook to check for secrets
// Use tools like git-secrets, truffleHog, detect-secrets
```

## Confidence Scoring

| Factor | Score Impact |
|--------|-------------|
| Matches secret pattern | +0.4 |
| In production code | +0.3 |
| No env var reference | +0.2 |
| In source control | +0.1 |
| .env.example file | -0.5 |
| Test/mock data | -0.4 |
| Placeholder value | -0.4 |

**Report threshold**: >= 0.7

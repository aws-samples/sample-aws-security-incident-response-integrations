# Authentication Component Profiling Patterns

## Overview
- **Component Type**: Authentication Services
- **Criticality**: CRITICAL
- **Security Focus**: Credential handling, session management, token security

## Analysis Framework

### Password Security Analysis

#### Hashing Algorithm Detection
```javascript
const hashingPatterns = {
  secure: {
    bcrypt: /bcrypt\.(hash|compare)/gi,
    scrypt: /scrypt\.(hash|verify)/gi,
    argon2: /argon2\.(hash|verify)/gi
  },
  weak: {
    md5: /md5\s*\(/gi,
    sha1: /sha1\s*\(/gi,
    plaintext: /password\s*===?\s*req\./gi
  }
};
```

#### Salting Strategy Detection
```javascript
const saltPatterns = {
  perPassword: /genSalt|generateSalt/gi,
  global: /SALT\s*=|globalSalt/gi,
  none: /hash\([^,]+\)(?!.*salt)/gi
};
```

### Token Security Analysis

#### JWT Patterns
```javascript
const jwtPatterns = {
  secure: {
    verify: /jwt\.verify\s*\([^)]+,\s*[^)]+,\s*\{[^}]*algorithms/gi,
    rsaSigning: /algorithm[s]?\s*:\s*['"]RS256['"]/gi
  },
  vulnerable: {
    decodeOnly: /jwt\.decode\s*\(/gi,
    noneAlgorithm: /algorithm[s]?\s*:\s*\[?['"]none['"]/gi,
    weakSecret: /jwt\.sign\s*\([^,]+,\s*['"][^'"]{1,20}['"]/gi
  }
};
```

#### Session Patterns
```javascript
const sessionPatterns = {
  secure: {
    httpOnly: /httpOnly\s*:\s*true/gi,
    secure: /secure\s*:\s*true/gi,
    sameSite: /sameSite\s*:\s*['"]strict['"]/gi
  },
  vulnerable: {
    noExpiration: /maxAge\s*:\s*(?:null|undefined|0)/gi,
    insecureCookie: /secure\s*:\s*false/gi,
    predictableId: /sessionId\s*=.*Math\.random/gi
  }
};
```

### MFA Implementation Analysis

#### MFA Detection
```javascript
const mfaPatterns = {
  totp: /totp|authenticator|speakeasy|otplib/gi,
  sms: /twilio|sms.*verify|sendCode/gi,
  email: /email.*verify|verificationCode/gi,
  backup: /backup.*code|recovery.*code/gi
};
```

### Brute Force Protection

#### Rate Limiting Detection
```javascript
const rateLimitPatterns = {
  library: /express-rate-limit|rate-limiter-flexible/gi,
  custom: /attempt.*count|failed.*login.*\d+/gi,
  lockout: /lockout|locked.*account|max.*attempts/gi
};
```

## Output Schema

```json
{
  "componentId": "auth-[uuid]",
  "componentName": "AuthenticationService",
  "componentType": "authentication",
  "securityAnalysis": {
    "passwordSecurity": {
      "hashingAlgorithm": "bcrypt|scrypt|argon2|weak|none",
      "saltingStrategy": "per-password|global|none",
      "passwordPolicy": "strong|weak|none",
      "storageMethod": "hashed|encrypted|plaintext"
    },
    "tokenSecurity": {
      "tokenType": "JWT|session|custom",
      "signingMethod": "RS256|HS256|none",
      "expirationHandling": "proper|missing|too-long",
      "refreshMechanism": "secure|vulnerable|none"
    },
    "sessionSecurity": {
      "sessionGeneration": "cryptographic|weak|predictable",
      "sessionStorage": "server|client|hybrid",
      "sessionInvalidation": "on-logout|on-password-change|never",
      "sessionFixationProtection": true|false
    },
    "mfaImplementation": {
      "mfaSupport": true|false,
      "mfaMethods": ["totp", "sms", "email"],
      "backupCodes": true|false,
      "mfaBypassRisk": "none|low|high"
    },
    "bruteForceProtection": {
      "rateLimiting": "per-ip|per-user|none",
      "accountLockout": "temporary|permanent|none",
      "captchaIntegration": true|false
    }
  },
  "vulnerabilities": [],
  "riskScore": 0.0,
  "recommendations": []
}
```

## Confidence Scoring

| Finding | Indicators | Confidence |
|---------|------------|------------|
| Weak hashing | MD5/SHA1 with password context | 0.95 |
| No salt | Hash without salt parameter | 0.85 |
| JWT none algorithm | Algorithm array contains "none" | 0.95 |
| Weak JWT secret | Short hardcoded string | 0.90 |
| Missing rate limiting | Auth endpoint without limiter | 0.75 |
| Session fixation | No regeneration on login | 0.80 |

## MCP Verification Queries

```javascript
search_aristotle_docs({ query: "password hashing best practices" })
search_aristotle_docs({ query: "JWT security configuration" })
search_aristotle_docs({ query: "session management security" })
search_aristotle_docs({ query: "authentication rate limiting" })
```

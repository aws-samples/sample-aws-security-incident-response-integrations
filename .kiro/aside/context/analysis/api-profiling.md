# API Component Profiling Patterns

## Overview
- **Component Type**: API Services (REST, GraphQL, WebSocket)
- **Criticality**: HIGH
- **Security Focus**: Input validation, output encoding, rate limiting, security headers

## Analysis Framework

### Input Validation Analysis

#### Validation Detection Patterns
```javascript
const inputValidationPatterns = {
  libraries: {
    joi: /joi\.(string|number|object|validate)/gi,
    yup: /yup\.(string|number|object|validate)/gi,
    express_validator: /express-validator|check\(|body\(|param\(/gi,
    zod: /z\.(string|number|object|parse)/gi
  },
  custom: {
    typeCheck: /typeof\s+\w+\s*===?\s*["'](string|number|boolean)/gi,
    lengthCheck: /\.length\s*[<>=]+\s*\d+/gi,
    regexValidation: /\.test\s*\(|\.match\s*\(/gi
  },
  missing: {
    directUse: /req\.(body|query|params)\.\w+(?!\s*\?)/gi,
    noValidation: /app\.(get|post|put|delete)\s*\([^)]+,\s*\(req/gi
  }
};
```

### Output Encoding Analysis

#### Encoding Detection
```javascript
const outputEncodingPatterns = {
  secure: {
    htmlEncoding: /escapeHtml|htmlEscape|sanitize-html/gi,
    jsonSafe: /JSON\.stringify\s*\([^,]+,\s*null/gi,
    urlEncoding: /encodeURIComponent|encodeURI/gi
  },
  vulnerable: {
    directOutput: /res\.(send|json)\s*\(\s*req\./gi,
    templateInjection: /\$\{.*req\.|<%=.*req\./gi,
    noEncoding: /innerHTML\s*=|outerHTML\s*=/gi
  }
};
```

### Rate Limiting Analysis

#### Rate Limit Detection
```javascript
const rateLimitPatterns = {
  libraries: {
    expressRateLimit: /express-rate-limit|rateLimit\(/gi,
    rateLimiterFlexible: /rate-limiter-flexible/gi,
    slowDown: /express-slow-down|slowDown\(/gi
  },
  configuration: {
    windowMs: /windowMs\s*:\s*\d+/gi,
    max: /max\s*:\s*\d+/gi,
    keyGenerator: /keyGenerator\s*:/gi
  },
  customImplementation: {
    tokenBucket: /bucket|tokens?\s*[<>=]/gi,
    slidingWindow: /window\s*\[|sliding/gi
  }
};
```

### Security Headers Analysis

#### Header Detection
```javascript
const securityHeaderPatterns = {
  helmet: /helmet\(|helmet\./gi,
  cors: {
    configuration: /cors\s*\(|cors\s*:/gi,
    origin: /origin\s*:\s*['"*]/gi,
    credentials: /credentials\s*:\s*true/gi
  },
  headers: {
    csp: /Content-Security-Policy|contentSecurityPolicy/gi,
    xframe: /X-Frame-Options|frameguard/gi,
    hsts: /Strict-Transport-Security|hsts/gi,
    xss: /X-XSS-Protection|xssFilter/gi
  }
};
```

### Error Handling Security

#### Error Pattern Detection
```javascript
const errorHandlingPatterns = {
  secure: {
    genericErrors: /res\.status\(\d+\)\.json\s*\(\s*\{\s*error/gi,
    sanitizedMessages: /message:\s*['"](?!.*stack|.*trace)/gi
  },
  vulnerable: {
    stackExposure: /res\.(send|json)\s*\(.*stack/gi,
    errorDetails: /res\.(send|json)\s*\(.*err\)/gi,
    internalInfo: /res\.(send|json)\s*\(.*process\./gi
  }
};
```

## Output Schema

```json
{
  "componentId": "api-[uuid]",
  "componentName": "UserAPI",
  "componentType": "api-endpoint",
  "securityAnalysis": {
    "inputValidation": {
      "validationLibrary": "joi|yup|express-validator|zod|custom|none",
      "validationCoverage": 0.0,
      "typeValidation": true|false,
      "lengthValidation": true|false,
      "formatValidation": true|false,
      "sanitization": true|false
    },
    "outputEncoding": {
      "htmlEncoding": true|false,
      "jsonEncoding": true|false,
      "urlEncoding": true|false,
      "contextualEncoding": true|false
    },
    "rateLimiting": {
      "implementation": "express-rate-limit|custom|none",
      "scope": "per-ip|per-user|per-endpoint|global",
      "windowMs": 0,
      "maxRequests": 0
    },
    "securityHeaders": {
      "helmet": true|false,
      "cors": "restrictive|permissive|misconfigured",
      "csp": true|false,
      "hsts": true|false
    },
    "errorHandling": {
      "sanitizedErrors": true|false,
      "stackTraceExposure": true|false,
      "informationDisclosure": "none|low|high"
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
| Missing input validation | Direct req.body use without check | 0.90 |
| XSS vulnerability | innerHTML with user input | 0.95 |
| No rate limiting | Auth endpoint without limiter | 0.80 |
| CORS misconfiguration | origin: '*' with credentials | 0.95 |
| Stack trace exposure | err.stack in response | 0.95 |
| Missing security headers | No helmet, no CSP | 0.75 |

## MCP Verification Queries

```javascript
search_aristotle_docs({ query: "API input validation best practices" })
search_aristotle_docs({ query: "REST API security headers" })
search_aristotle_docs({ query: "rate limiting implementation" })
search_aristotle_docs({ query: "CORS security configuration" })
```

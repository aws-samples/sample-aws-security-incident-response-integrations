# Frontend Component Profiling Patterns

## Overview
- **Component Type**: Frontend Applications (React, Vue, Angular)
- **Criticality**: MEDIUM-HIGH
- **Security Focus**: XSS prevention, client-side storage, state management, CSP

## Analysis Framework

### XSS Prevention Analysis

#### React-Specific Patterns
```javascript
const reactXSSPatterns = {
  vulnerable: {
    dangerouslySetInnerHTML: /dangerouslySetInnerHTML\s*=\s*\{/gi,
    unsafeEval: /eval\s*\(|Function\s*\(/gi,
    innerHTMLDirect: /\.innerHTML\s*=/gi,
    refManipulation: /ref\.current\.innerHTML/gi
  },
  safe: {
    textContent: /textContent\s*=|\.innerText\s*=/gi,
    sanitization: /DOMPurify\.sanitize|sanitize-html/gi,
    escapedOutput: /\{.*\}(?!.*dangerously)/gi
  }
};
```

#### Vue-Specific Patterns
```javascript
const vueXSSPatterns = {
  vulnerable: {
    vHtml: /v-html\s*=\s*["']/gi,
    templateLiteral: /\$\{.*\}.*innerHTML/gi
  },
  safe: {
    vText: /v-text\s*=|v-bind:textContent/gi,
    mustacheEscaping: /\{\{[^}]+\}\}(?!.*\|.*raw)/gi
  }
};
```

#### Angular-Specific Patterns
```javascript
const angularXSSPatterns = {
  vulnerable: {
    bypassSecurity: /bypassSecurityTrust\w+/gi,
    innerHTML: /\[innerHTML\]\s*=/gi
  },
  safe: {
    sanitizer: /DomSanitizer/gi,
    textInterpolation: /\{\{[^}]+\}\}/gi
  }
};
```

### Client-Side Storage Analysis

#### Storage Pattern Detection
```javascript
const storagePatterns = {
  localStorage: {
    usage: /localStorage\.(setItem|getItem)/gi,
    sensitiveData: /localStorage.*token|localStorage.*password|localStorage.*key/gi
  },
  sessionStorage: {
    usage: /sessionStorage\.(setItem|getItem)/gi,
    sensitiveData: /sessionStorage.*token|sessionStorage.*auth/gi
  },
  cookies: {
    usage: /document\.cookie|js-cookie|Cookies\.(set|get)/gi,
    secureFlags: /secure\s*:\s*true|httpOnly|SameSite/gi
  },
  indexedDB: {
    usage: /indexedDB\.open|IDBDatabase/gi
  }
};
```

### State Management Security

#### State Pattern Detection
```javascript
const stateManagementPatterns = {
  redux: {
    sensitiveState: /createSlice.*token|createSlice.*password/gi,
    devToolsExposure: /redux.*devtools|__REDUX_DEVTOOLS/gi
  },
  context: {
    sensitiveContext: /createContext.*auth|createContext.*user/gi
  },
  vuex: {
    sensitiveState: /state\s*:\s*\{[^}]*token|mutations.*password/gi
  },
  mobx: {
    observableSensitive: /@observable.*token|makeObservable.*password/gi
  }
};
```

### Third-Party Script Security

#### Script Loading Patterns
```javascript
const scriptSecurityPatterns = {
  dangerous: {
    dynamicScript: /createElement\s*\(\s*['"]script['"]/gi,
    evalScript: /eval\s*\(|new\s+Function\s*\(/gi,
    document_write: /document\.write/gi
  },
  cdnUsage: {
    withIntegrity: /integrity\s*=\s*["']sha/gi,
    withoutIntegrity: /<script.*src=.*cdn(?!.*integrity)/gi
  },
  tracking: {
    analytics: /gtag|analytics|mixpanel|segment/gi,
    social: /facebook.*sdk|twitter.*widgets/gi
  }
};
```

### Form Security

#### Form Pattern Detection
```javascript
const formSecurityPatterns = {
  autoComplete: {
    disabled: /autocomplete\s*=\s*["']off["']/gi,
    sensitive: /autocomplete\s*=\s*["']current-password["']/gi
  },
  csrf: {
    token: /csrf.*token|_token|authenticity_token/gi,
    header: /X-CSRF-Token|X-XSRF-TOKEN/gi
  },
  validation: {
    clientSide: /required|pattern\s*=|type\s*=\s*["']email["']/gi,
    customValidation: /validate|validator|checkValidity/gi
  }
};
```

## Output Schema

```json
{
  "componentId": "frontend-[uuid]",
  "componentName": "UserDashboard",
  "componentType": "frontend",
  "securityAnalysis": {
    "xssPrevention": {
      "framework": "react|vue|angular|vanilla",
      "dangerousPatterns": [],
      "sanitizationUsed": true|false,
      "domPurifyIntegration": true|false
    },
    "clientStorage": {
      "localStorage": {
        "used": true|false,
        "sensitiveData": true|false
      },
      "sessionStorage": {
        "used": true|false,
        "sensitiveData": true|false
      },
      "cookies": {
        "secureFlag": true|false,
        "httpOnly": true|false,
        "sameSite": "strict|lax|none"
      }
    },
    "stateManagement": {
      "library": "redux|context|vuex|mobx|none",
      "sensitiveDataInState": true|false,
      "devToolsExposed": true|false
    },
    "thirdPartyScripts": {
      "count": 0,
      "integrityUsed": true|false,
      "trustedSources": true|false
    },
    "formSecurity": {
      "csrfProtection": true|false,
      "autoCompleteHandled": true|false,
      "clientValidation": true|false
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
| XSS via dangerouslySetInnerHTML | User input in dangerous prop | 0.95 |
| Sensitive data in localStorage | Token/password stored | 0.90 |
| Missing CSP | No Content-Security-Policy | 0.75 |
| Dev tools exposed in production | REDUX_DEVTOOLS in prod | 0.85 |
| No SRI on CDN scripts | External script without integrity | 0.80 |
| DOM-based XSS | innerHTML with URL param | 0.90 |

## MCP Verification Queries

```javascript
search_aristotle_docs({ query: "React XSS prevention dangerouslySetInnerHTML" })
search_aristotle_docs({ query: "client-side storage security" })
search_aristotle_docs({ query: "Content Security Policy frontend" })
search_aristotle_docs({ query: "state management sensitive data" })
```

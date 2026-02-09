# MCP Query Patterns Reference

## Overview
- **Purpose**: Reference patterns for MCP security intelligence queries
- **MCP Servers**: appsec-mcp, builder-mcp
- **Query Types**: Technology-specific, vulnerability-specific, compliance

## Technology-Specific Query Templates

### React/Frontend Frameworks
```javascript
// XSS Prevention
search_aristotle_docs({ query: "React XSS prevention" })
search_aristotle_docs({ query: "Content Security Policy frontend" })
search_aristotle_docs({ query: "dangerouslySetInnerHTML security" })

// State Management Security
search_aristotle_docs({ query: "client-side state security" })
search_aristotle_docs({ query: "Redux security best practices" })

// Build Security
search_aristotle_docs({ query: "React build security" })
SearchSoftwareRecommendations({ keyword: "frontend security scanning" })
```

### Express/Node.js
```javascript
// Middleware Security
search_aristotle_docs({ query: "Express middleware security" })
search_aristotle_docs({ query: "helmet security headers" })

// Input Validation
search_aristotle_docs({ query: "Node.js input validation" })
search_aristotle_docs({ query: "express-validator security" })

// Session Security
search_aristotle_docs({ query: "Express session management" })
search_aristotle_docs({ query: "cookie security Node.js" })
```

### Python/Django/Flask
```javascript
// Framework Security
search_aristotle_docs({ query: "Django security settings" })
search_aristotle_docs({ query: "Flask security configuration" })

// SQL Injection
search_aristotle_docs({ query: "Python SQL injection prevention" })
search_aristotle_docs({ query: "Django ORM security" })

// Authentication
search_aristotle_docs({ query: "Python authentication best practices" })
search_aristotle_docs({ query: "Django authentication security" })
```

### Java/Spring
```javascript
// Spring Security
search_aristotle_docs({ query: "Spring Security configuration" })
search_aristotle_docs({ query: "Spring Boot security" })

// Cryptography
search_aristotle_docs({ query: "Java cryptography best practices" })
search_aristotle_docs({ query: "JCA security patterns" })
```

## AWS Service Query Templates

### S3 Security
```javascript
SearchSoftwareRecommendations({ keyword: "S3 bucket security" })
SearchSoftwareRecommendations({ keyword: "S3 encryption" })
SearchSoftwareRecommendations({ keyword: "S3 access control" })
```

### Lambda Security
```javascript
SearchSoftwareRecommendations({ keyword: "Lambda security" })
SearchSoftwareRecommendations({ keyword: "Lambda IAM roles" })
SearchSoftwareRecommendations({ keyword: "Lambda environment variables" })
```

### RDS Security
```javascript
SearchSoftwareRecommendations({ keyword: "RDS security configuration" })
SearchSoftwareRecommendations({ keyword: "RDS encryption" })
SearchSoftwareRecommendations({ keyword: "RDS network security" })
```

### API Gateway
```javascript
SearchSoftwareRecommendations({ keyword: "API Gateway security" })
SearchSoftwareRecommendations({ keyword: "API Gateway authentication" })
SearchSoftwareRecommendations({ keyword: "API Gateway rate limiting" })
```

## Vulnerability-Specific Query Templates

### SQL Injection
```javascript
search_aristotle_docs({ query: "SQL injection prevention ORM" })
search_aristotle_docs({ query: "parameterized queries best practices" })
search_aristotle_docs({ query: "database input sanitization" })
```

### XSS
```javascript
search_aristotle_docs({ query: "XSS prevention [FRAMEWORK]" })
search_aristotle_docs({ query: "Content Security Policy implementation" })
search_aristotle_docs({ query: "output encoding best practices" })
```

### Authentication
```javascript
search_aristotle_docs({ query: "secure password storage" })
search_aristotle_docs({ query: "JWT security best practices" })
search_aristotle_docs({ query: "session management security" })
search_aristotle_docs({ query: "MFA implementation" })
```

### Authorization
```javascript
search_aristotle_docs({ query: "RBAC implementation" })
search_aristotle_docs({ query: "privilege escalation prevention" })
search_aristotle_docs({ query: "API authorization patterns" })
```

### Cryptography
```javascript
search_aristotle_docs({ query: "encryption key management" })
search_aristotle_docs({ query: "cryptographic algorithm selection" })
search_aristotle_docs({ query: "secure random generation" })
```

## Compliance Query Templates

### PCI DSS
```javascript
search_aristotle_docs({ query: "PCI DSS requirements" })
search_aristotle_docs({ query: "payment data encryption" })
search_aristotle_docs({ query: "cardholder data protection" })
```

### GDPR
```javascript
search_aristotle_docs({ query: "GDPR technical requirements" })
search_aristotle_docs({ query: "data protection by design" })
search_aristotle_docs({ query: "user consent management" })
```

### HIPAA
```javascript
search_aristotle_docs({ query: "HIPAA security requirements" })
search_aristotle_docs({ query: "PHI encryption standards" })
search_aristotle_docs({ query: "healthcare audit logging" })
```

### SOC2
```javascript
search_aristotle_docs({ query: "SOC2 security controls" })
search_aristotle_docs({ query: "SOC2 trust principles" })
search_aristotle_docs({ query: "security monitoring SOC2" })
```

## Query Execution Pattern

```javascript
async function gatherSecurityGuidance(technology, vulnerabilities) {
  const results = {
    technologyGuidance: [],
    vulnerabilityGuidance: [],
    errors: []
  };

  // Technology queries
  try {
    const techResults = await search_aristotle_docs({
      query: `${technology} security best practices`
    });
    results.technologyGuidance.push(...techResults);

    // Fetch full documents for top results
    for (const result of techResults.slice(0, 3)) {
      if (result.url) {
        const fullDoc = await read_aristotle_doc({ url: result.url });
        results.technologyGuidance.push(fullDoc);
      }
    }
  } catch (error) {
    results.errors.push({ source: 'technology', error: error.message });
  }

  // Vulnerability queries
  for (const vuln of vulnerabilities) {
    try {
      const vulnResults = await search_aristotle_docs({
        query: `${vuln.type} prevention ${technology}`
      });
      results.vulnerabilityGuidance.push({
        vulnerability: vuln.id,
        guidance: vulnResults
      });
    } catch (error) {
      results.errors.push({ source: vuln.id, error: error.message });
    }
  }

  return results;
}
```

## Minimum Required Queries by Detection

| Detected | Required MCP Queries |
|----------|---------------------|
| React/Vue/Angular | XSS prevention, CSP, client storage |
| Express/Fastify | Middleware security, input validation |
| Python/Django/Flask | Framework security, SQL injection |
| Java/Spring | Spring Security, cryptography |
| Any Database | SQL injection, connection security |
| AWS Services | Service-specific security |
| Authentication | Password, token, session security |
| API Endpoints | Input validation, rate limiting |

## Response Processing

### Relevance Scoring
```javascript
const relevanceFactors = {
  technologyMatch: 0.3,    // Query technology matches project
  versionMatch: 0.2,       // Guidance covers project version
  vulnerabilityMatch: 0.3, // Addresses identified vulnerabilities
  actionability: 0.2       // Provides implementable steps
};
```

### Quality Filtering
- Accept responses with relevance score > 0.6
- Prioritize responses with code examples
- Prefer recent guidance (last 2 years)
- Validate against project technology stack

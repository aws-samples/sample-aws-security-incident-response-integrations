# Data Access Component Profiling Patterns

## Overview
- **Component Type**: Data Access Layer (SQL, NoSQL, ORM)
- **Criticality**: CRITICAL
- **Security Focus**: Injection prevention, connection security, encryption, access control

## Analysis Framework

### SQL Injection Prevention Analysis

#### Query Pattern Detection
```javascript
const queryPatterns = {
  secure: {
    parameterized: /\?\s*,|\$\d+|:\w+/gi,
    preparedStatements: /prepare|prepareStatement/gi,
    ormMethods: /\.find\(|\.findOne\(|\.where\(/gi
  },
  vulnerable: {
    concatenation: /query.*\+.*req\.|execute.*\+.*input/gi,
    templateLiterals: /\$\{.*req\.|`.*\$\{.*user/gi,
    rawQueries: /raw\s*\(|rawQuery|execute\s*\(['"]/gi
  }
};
```

#### ORM Security Patterns
```javascript
const ormPatterns = {
  sequelize: {
    safe: /\.findByPk\(|\.findAll\(\{.*where/gi,
    risky: /sequelize\.query\s*\(|literal\s*\(/gi
  },
  mongoose: {
    safe: /\.findById\(|\.find\(\{/gi,
    risky: /\$where|\.exec\s*\(/gi
  },
  typeorm: {
    safe: /getRepository\(|\.find\(\{/gi,
    risky: /\.query\s*\(|createQueryBuilder.*raw/gi
  },
  prisma: {
    safe: /prisma\.\w+\.find/gi,
    risky: /\$queryRaw|\$executeRaw/gi
  }
};
```

### Connection Security Analysis

#### Connection Pattern Detection
```javascript
const connectionPatterns = {
  secure: {
    ssl: /ssl\s*:\s*true|sslmode\s*=\s*require/gi,
    tls: /tls\s*:\s*\{|rejectUnauthorized/gi,
    connectionPool: /pool\s*:\s*\{|connectionLimit/gi
  },
  vulnerable: {
    plaintext: /ssl\s*:\s*false|sslmode\s*=\s*disable/gi,
    hardcodedCredentials: /password\s*[:=]\s*["'][^"']+["']/gi,
    noTimeout: /connectTimeout\s*:\s*0|timeout\s*:\s*null/gi
  }
};
```

### Data Encryption Analysis

#### Encryption Detection
```javascript
const encryptionPatterns = {
  atRest: {
    columnEncryption: /encrypt\(|pgp_sym_encrypt/gi,
    fieldEncryption: /@Encrypted|@Encrypt/gi,
    transparentEncryption: /TDE|transparent.*encrypt/gi
  },
  inTransit: {
    ssl: /ssl\s*:\s*true|useSSL\s*=\s*true/gi,
    tls: /tls\s*:\s*\{|tlsCAFile/gi
  },
  keyManagement: {
    kms: /AWS\.KMS|kms\.encrypt|kms\.decrypt/gi,
    vault: /hashicorp.*vault|vault\.read/gi,
    hardcoded: /key\s*[:=]\s*["'][a-zA-Z0-9+/=]{16,}["']/gi
  }
};
```

### Access Control Analysis

#### Permission Patterns
```javascript
const accessControlPatterns = {
  database: {
    roleBasedAccess: /GRANT|REVOKE|CREATE ROLE/gi,
    leastPrivilege: /SELECT.*ON|INSERT.*ON/gi
  },
  application: {
    rowLevelSecurity: /RLS|row_level_security|tenant_id/gi,
    columnMasking: /mask\(|MASKED WITH/gi
  },
  audit: {
    logging: /audit_log|query_log|slow_query/gi,
    tracking: /created_by|modified_by|audit_trail/gi
  }
};
```

### Transaction Security

#### Transaction Patterns
```javascript
const transactionPatterns = {
  isolation: {
    serializable: /SERIALIZABLE|isolation.*serializable/gi,
    repeatableRead: /REPEATABLE READ|isolation.*repeatable/gi,
    readCommitted: /READ COMMITTED|isolation.*committed/gi
  },
  handling: {
    properRollback: /rollback\s*\(|ROLLBACK/gi,
    errorHandling: /catch.*rollback|finally.*commit/gi
  },
  risky: {
    noTransaction: /autocommit\s*:\s*true/gi,
    longRunning: /timeout\s*:\s*0|no.*timeout/gi
  }
};
```

## Output Schema

```json
{
  "componentId": "data-[uuid]",
  "componentName": "DatabaseLayer",
  "componentType": "data-access",
  "securityAnalysis": {
    "injectionPrevention": {
      "parameterizedQueries": true|false,
      "ormUsage": "sequelize|mongoose|typeorm|prisma|none",
      "rawQueryUsage": true|false,
      "inputSanitization": true|false
    },
    "connectionSecurity": {
      "encryption": "ssl|tls|none",
      "credentialManagement": "env|vault|hardcoded",
      "connectionPooling": true|false,
      "timeoutConfiguration": "proper|missing|disabled"
    },
    "dataEncryption": {
      "atRest": "column|field|transparent|none",
      "inTransit": "ssl|tls|none",
      "keyManagement": "kms|vault|local|hardcoded"
    },
    "accessControl": {
      "databasePermissions": "least-privilege|over-privileged",
      "rowLevelSecurity": true|false,
      "auditLogging": true|false
    },
    "transactionSecurity": {
      "isolationLevel": "serializable|repeatable-read|read-committed|read-uncommitted",
      "errorHandling": "proper-rollback|missing-rollback",
      "deadlockHandling": true|false
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
| SQL injection | String concat with user input | 0.95 |
| Raw query usage | ORM.query() with variables | 0.85 |
| Hardcoded credentials | Password in connection string | 0.95 |
| No SSL/TLS | ssl: false in config | 0.90 |
| Missing encryption at rest | No encrypt calls, no TDE | 0.70 |
| Over-privileged access | GRANT ALL on production | 0.85 |

## MCP Verification Queries

```javascript
search_aristotle_docs({ query: "SQL injection prevention ORM" })
search_aristotle_docs({ query: "database connection security TLS" })
search_aristotle_docs({ query: "data encryption at rest best practices" })
search_aristotle_docs({ query: "database access control least privilege" })
```

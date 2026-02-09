# Component Security Profiling Context

## Purpose
Guide the ASIDE agent in **discovering and profiling components** for security analysis. This enables targeted validation hooks and accurate threat modeling.

## Component Discovery Process

### Step 1: Project Structure Analysis
Identify components by scanning for these patterns:

```
# Directory patterns indicating components
src/
├── controllers/     → API/Request handlers (HIGH criticality)
├── services/        → Business logic (MEDIUM-HIGH)
├── middleware/      → Request processing (HIGH - auth, validation)
├── routes/          → Entry points (HIGH)
├── models/          → Data structures (MEDIUM)
├── utils/           → Shared utilities (LOW-MEDIUM)
├── auth/            → Authentication (CRITICAL)
├── api/             → External interfaces (HIGH)
└── db/              → Database access (HIGH)
```

### Step 2: Entry Point Identification
Scan for these patterns to find entry points:

| Framework | Pattern to Find | Example |
|-----------|-----------------|---------|
| Express | `app.get/post/put/delete`, `router.*` | `router.post('/users', handler)` |
| FastAPI | `@app.get`, `@router.post` | `@app.post("/users")` |
| Django | `path()`, `url()` in urls.py | `path('users/', views.UserView)` |
| Spring | `@GetMapping`, `@PostMapping` | `@PostMapping("/users")` |
| Flask | `@app.route` | `@app.route('/users', methods=['POST'])` |

### Step 3: Security Criticality Assessment

```yaml
# Criticality scoring algorithm
criticality_factors:
  handles_auth: +3          # Auth logic present
  handles_pii: +3           # PII data processing
  external_facing: +2       # Public API endpoint
  handles_payments: +3      # Financial data
  database_write: +2        # Modifies data
  file_operations: +2       # File I/O
  external_api_calls: +1    # Third-party integration
  admin_functions: +2       # Privileged operations

scoring:
  critical: 7+   # Requires comprehensive validation
  high: 5-6      # Full automated validation
  medium: 3-4    # Standard validation
  low: 0-2       # Basic validation
```

## Framework-Specific Discovery

### Node.js/Express
```javascript
// Look for these patterns:
const express = require('express');
app.use('/api', authMiddleware, router);  // Middleware chain
router.post('/users', validateInput, createUser);  // Route handlers
module.exports = { createUser, updateUser };  // Exported functions
```

**Security-relevant patterns:**
- `req.body`, `req.params`, `req.query` → User input sources
- `res.json()`, `res.send()` → Output points
- `jwt.verify`, `bcrypt.compare` → Auth functions
- `db.query`, `Model.find` → Database operations

### Python/FastAPI
```python
# Look for these patterns:
@app.post("/users", response_model=User)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    # Body indicates: input validation (Pydantic), DB access
```

### React/Frontend
```javascript
// Security-relevant patterns:
dangerouslySetInnerHTML  // XSS risk - CRITICAL
localStorage.setItem     // Sensitive data storage
fetch('/api/...')        // API calls - check auth headers
window.location          // Redirect handling
```

## Component Profile Schema

```json
{
  "id": "auto-generated-uuid",
  "name": "UserService",
  "path": "src/services/UserService.ts",
  "type": "service",
  "criticality": "high",
  "criticality_score": 6,
  "criticality_factors": ["handles_pii", "database_write", "external_facing"],

  "entry_points": [
    {
      "function": "createUser",
      "line": 45,
      "inputs": ["req.body"],
      "auth_required": true,
      "validation": "partial"
    }
  ],

  "data_handling": {
    "inputs": ["user_email", "user_password", "user_name"],
    "outputs": ["user_id", "user_token"],
    "sensitive_fields": ["user_password"],
    "pii_fields": ["user_email", "user_name"]
  },

  "dependencies": {
    "internal": ["DatabaseService", "AuthService"],
    "external": ["bcrypt", "jsonwebtoken"]
  },

  "security_controls": {
    "input_validation": "zod_schema",
    "output_encoding": "json",
    "auth_mechanism": "jwt",
    "rate_limiting": false
  },

  "identified_risks": [],
  "validation_profile": "strict"
}
```

## Data Flow Tracing

### Tracing User Input
Follow data from entry to storage/output:

```
HTTP Request
    ↓
[Entry Point] req.body.email
    ↓
[Validation?] validateEmail(email) - CHECK: exists?
    ↓
[Processing] userService.create({email})
    ↓
[Storage] db.users.insert({email}) - CHECK: parameterized?
    ↓
[Response] res.json({user}) - CHECK: what's exposed?
```

### Trust Boundary Identification
```
┌─────────────────────────────────────────┐
│ UNTRUSTED: User/Browser                 │
└─────────────┬───────────────────────────┘
              │ HTTP Request (VALIDATE HERE)
┌─────────────▼───────────────────────────┐
│ BOUNDARY: API Gateway/Load Balancer     │
└─────────────┬───────────────────────────┘
              │
┌─────────────▼───────────────────────────┐
│ APPLICATION: Controllers/Services       │
└─────────────┬───────────────────────────┘
              │ (AUTHORIZE HERE)
┌─────────────▼───────────────────────────┐
│ TRUSTED: Database/Internal Services     │
└─────────────────────────────────────────┘
```

## Relationship Mapping

### Import/Export Analysis
```javascript
// File: src/services/UserService.ts
import { DatabaseService } from './DatabaseService';  // DEPENDENCY
import { AuthService } from './AuthService';          // DEPENDENCY
export class UserService { ... }                       // EXPORTED

// Creates relationship:
// UserService → depends_on → [DatabaseService, AuthService]
// UserService → exported_by → services/index.ts
```

### Call Graph (Simplified)
```
createUser()
  → validateInput()      [validation]
  → hashPassword()       [auth - security critical]
  → db.insert()          [storage - injection risk]
  → sendWelcomeEmail()   [external - data leakage risk]
```

## Output Artifacts

### Component Map Document
```markdown
# Component Map: [Project Name]

## Components by Criticality

### Critical
| Component | Path | Entry Points | Data Types |
|-----------|------|--------------|------------|
| AuthService | src/auth/ | login, register | credentials |

### High
| Component | Path | Entry Points | Data Types |
|-----------|------|--------------|------------|

## Component Relationships
[Mermaid diagram or text representation]

## Security Control Coverage
| Control | Components With | Components Without |
|---------|-----------------|-------------------|
| Input Validation | 5 | 2 |
| Auth Middleware | 8 | 1 |
```

## Metrics Capture

After component profiling:
```json
{
  "timestamp": "ISO-8601",
  "metrics": {
    "total_components": 0,
    "by_criticality": {
      "critical": 0, "high": 0, "medium": 0, "low": 0
    },
    "entry_points_found": 0,
    "with_input_validation": 0,
    "with_auth_controls": 0,
    "coverage_gaps": []
  }
}
```

Save to: `.kiro/aside/metrics/component-profile-[timestamp].json`

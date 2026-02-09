# Step 2: Component Discovery

## Persona

You are a **Security Architecture Analyst** specializing in identifying components with security implications by understanding application structure and data flows.

## Session Management

Before starting, read `session/session-management.md` for checkpointing requirements.

Load the `Project_Fingerprint.md` from Step 1 - it tells you what technologies to expect.

## Mission

Identify all security-relevant components in this codebase by understanding the application architecture, not by keyword searching. Your goal is to create a Component Map that shows what components exist and how they relate to security.

## What Makes a Component Security-Relevant?

A component is security-relevant if it:
- Handles user authentication or authorization
- Processes user input (API endpoints, forms)
- Accesses or stores data (database, files, cache)
- Communicates with external services
- Manages sensitive information (credentials, PII, payments)
- Controls application flow (middleware, routers)

## Approach: Structure-Based Discovery

**Key Principle**: Find components by understanding project structure, not by searching for keywords.

The Project_Fingerprint.md tells you:
- Which framework is used (determines component patterns)
- What folder structure exists (determines where to look)
- What security libraries are present (indicates security patterns)

Use this information to look in the right places.

## Phase 1: Framework-Specific Component Locations

### For Express/Node.js Applications

Based on the framework detected in Step 1:

| Component Type | Typical Location | What to Look For |
|----------------|------------------|------------------|
| Routes/Controllers | `routes/`, `controllers/`, `api/` | Files that define HTTP endpoints |
| Middleware | `middleware/`, `src/middleware/` | Functions that process requests |
| Authentication | `auth/`, `middleware/auth*` | Login, token verification |
| Models | `models/`, `entities/` | Database entity definitions |
| Services | `services/` | Business logic modules |

### For Django/Python Applications

| Component Type | Typical Location | What to Look For |
|----------------|------------------|------------------|
| Views | `*/views.py` | Request handlers |
| Models | `*/models.py` | Database models |
| Forms | `*/forms.py` | Input validation |
| Authentication | `*/authentication.py`, settings | Auth backends |
| URLs | `*/urls.py` | Route definitions |

### For Other Frameworks

Apply the same principle: use the Project_Fingerprint to identify the framework, then look in the conventional locations for that framework.

## Phase 2: Entry Point Tracing

Start from the main entry point identified in Step 1 and trace the application flow:

### Step 2.1: Read the Entry Point

The entry point (e.g., `src/index.ts`, `app.py`) typically:
1. Initializes the application
2. Registers middleware
3. Sets up routes
4. Connects to databases

Note each of these as you read.

### Step 2.2: Follow Route Registration

When you find route registration:
```
app.use('/api/users', userRoutes)
app.use('/api/auth', authRoutes)
```

Read each route file to understand:
- What endpoints exist
- What handlers process requests
- What validation is applied

### Step 2.3: Follow Middleware Chain

When you find middleware registration:
```
app.use(authMiddleware)
app.use(rateLimiter)
```

Read each middleware to understand:
- What it protects
- What conditions it checks
- What happens on failure

## Phase 3: Security Component Identification

Based on what you've traced, categorize components:

### Authentication Components

Identify components that:
- Verify user identity (login, token validation)
- Manage sessions (create, destroy, refresh)
- Handle password operations (hash, verify, reset)

Note the **file path and the specific function** that performs each action.

### Authorization Components

Identify components that:
- Check permissions before actions
- Enforce role-based access
- Protect routes or resources

Note **what resources are protected** and **how access is decided**.

### Data Access Components

Identify components that:
- Query or modify database data
- Access external APIs
- Read or write files
- Cache data

Note **what data is accessed** and **whether queries use user input**.

### Input Processing Components

Identify components that:
- Accept user input (API parameters, form data)
- Validate input before use
- Transform or sanitize data

Note **what validation is applied** and **what inputs bypass validation**.

## Phase 4: Trust Boundary Mapping

Based on discovered components, identify boundaries:

### External → Application Boundary
- Where does user input enter? (API endpoints, form handlers)
- What validation exists at the boundary?

### Application → Database Boundary
- Where do database queries originate?
- Do queries use parameterization or string concatenation?

### Application → External Services Boundary
- What external APIs are called?
- How are credentials managed?

### Authenticated → Unauthenticated Boundary
- Which endpoints require authentication?
- Which endpoints are public?

## Output: Component Map

Create `.kiro/aside/generated/Component_Map.md`:

```markdown
# Component Map

**Generated**: [timestamp]
**Based on**: Project_Fingerprint.md

## Component Summary

| Category | Count | Examples |
|----------|-------|----------|
| Authentication | [n] | AuthService, TokenValidator |
| Data Access | [n] | UserRepository, OrderService |
| API Endpoints | [n] | UserController, PaymentAPI |
| Middleware | [n] | AuthMiddleware, RateLimiter |

## Authentication Components

### [Component Name]
- **File**: `src/services/AuthService.ts`
- **Purpose**: Handles user login and session management
- **Key Functions**:
  - `login(credentials)` - Validates credentials, creates session
  - `verifyToken(token)` - Validates JWT tokens
  - `logout(sessionId)` - Destroys session
- **Security Notes**: Uses bcrypt for password hashing, JWT for tokens

### [Next Component...]

## Authorization Components

### [Component Name]
- **File**: `src/middleware/authMiddleware.ts`
- **Purpose**: Protects routes requiring authentication
- **Protected Routes**: All `/api/*` routes except `/api/auth/login`
- **Security Notes**: Checks JWT in Authorization header

## Data Access Components

### [Component Name]
- **File**: `src/repositories/UserRepository.ts`
- **Purpose**: Database access for user data
- **Data Accessed**: users table (email, password_hash, profile)
- **Query Pattern**: ORM-based (Prisma)
- **Security Notes**: No raw queries observed

## API Endpoints

### [Route Group Name]
- **File**: `src/routes/userRoutes.ts`
- **Base Path**: `/api/users`
- **Endpoints**:
  | Method | Path | Auth | Purpose |
  |--------|------|------|---------|
  | GET | `/` | Yes | List users |
  | GET | `/:id` | Yes | Get user by ID |
  | POST | `/` | No | Create user |
  | PUT | `/:id` | Yes | Update user |
  | DELETE | `/:id` | Yes (Admin) | Delete user |
- **Security Notes**: No input validation on POST body

## Middleware Components

### [Component Name]
- **File**: `src/middleware/rateLimiter.ts`
- **Purpose**: Limits request rate per IP
- **Configuration**: 100 requests/minute per IP
- **Applied To**: All routes

## Trust Boundaries

### Boundary: External Input → Application
- **Entry Points**: 12 API endpoints in `/api/*`
- **Validation Present**: Partial (6 of 12 endpoints)
- **Unvalidated Inputs**: POST /api/users, PUT /api/orders/:id

### Boundary: Application → Database
- **Access Pattern**: ORM (Prisma)
- **Raw Queries**: None detected
- **Parameterization**: Yes (via ORM)

### Boundary: Application → External APIs
- **Services Called**: Stripe, SendGrid
- **Credential Storage**: Environment variables

### Boundary: Authenticated → Public
- **Public Endpoints**: /api/auth/login, /api/auth/register, /health
- **Protected Endpoints**: All others require valid JWT

## High-Risk Components

Components requiring detailed profiling in Step 3:

1. **AuthService** - Handles credentials, tokens
2. **PaymentController** - Processes payments
3. **UserRepository** - Accesses PII
4. **FileUploadService** - Handles user files

## Component Interaction Diagram

```
[User] → [API Gateway] → [Auth Middleware] → [Controller]
                                                   ↓
                              [Service] ← [Repository] → [Database]
                                   ↓
                           [External APIs]
```
```

## State Update

After completing, update `init_state.json`:

```json
{
  "currentStep": 3,
  "status": "in_progress",
  "completedSteps": [1, 2],
  "artifacts": {
    "projectFingerprint": ".kiro/aside/generated/Project_Fingerprint.md",
    "componentMap": ".kiro/aside/generated/Component_Map.md"
  }
}
```

## Step Completion Gate

Before proceeding to Step 3, verify:

- [ ] Read entry point and traced application flow
- [ ] Identified all authentication components with file paths
- [ ] Identified all authorization components
- [ ] Identified all data access components
- [ ] Mapped API endpoints with auth requirements
- [ ] Identified trust boundaries
- [ ] Listed high-risk components for Step 3 profiling
- [ ] Created Component_Map.md with all sections
- [ ] Updated init_state.json

**Only proceed to Step 3 when all items are checked.**

## Step 3 Input

The Component Map provides Step 3 with:
- List of components to profile
- Priority order (high-risk first)
- Context for each component's purpose
- Trust boundaries to analyze

---

**Next Step**: `step3-component-profiling.md` - Deep security analysis of each component

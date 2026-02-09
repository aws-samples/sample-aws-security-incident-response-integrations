# Step 1: Project Fingerprinting

## Persona

You are a **Technology Stack Analyst** specializing in understanding codebases through their configuration and structure rather than exhaustive searching.

## Session Management

Before starting, read `session/session-management.md` for:
- State persistence protocol
- Checkpoint requirements
- Error handling procedures

## Mission

Understand this project's technology stack, architecture, and security posture by analyzing configuration files and project structure. Your goal is to create a comprehensive fingerprint that guides all subsequent security analysis.

## Approach: Configuration-First Analysis

**Key Principle**: Configuration files tell you more than searching code.

Instead of:
- Searching every file for framework patterns
- Running multiple grep commands for each technology
- Counting files by extension

Do this:
- Read the primary configuration file (package.json, requirements.txt, etc.)
- Understand dependencies and their purposes
- Examine the folder structure to understand architecture
- Read entry point files to understand application flow

## Phase 1: Project Structure Understanding

### Step 1.1: Find the Project Root Configuration

Look for the primary configuration file:

| File | Indicates |
|------|-----------|
| `package.json` | Node.js/JavaScript/TypeScript project |
| `requirements.txt` or `pyproject.toml` | Python project |
| `Cargo.toml` | Rust project |
| `go.mod` | Go project |
| `pom.xml` or `build.gradle` | Java project |
| `Gemfile` | Ruby project |
| `composer.json` | PHP project |

Read this file to understand:
- Project name and description
- All dependencies (production and development)
- Scripts and build commands
- Entry points (main, bin, etc.)

### Step 1.2: Understand the Folder Structure

List the top-level directories to understand architecture:

| Folder | Common Purpose |
|--------|----------------|
| `src/` | Source code |
| `lib/` | Library code |
| `api/` | API definitions |
| `routes/` or `controllers/` | Request handlers |
| `models/` | Data models |
| `services/` | Business logic |
| `middleware/` | Request processing |
| `utils/` or `helpers/` | Utility functions |
| `tests/` or `__tests__/` | Test files |
| `config/` | Configuration |

### Step 1.3: Check for Existing Security Documentation

Before analyzing fresh, check if security analysis already exists:

- `.kiro/aside/generated/` - Previous ASIDE analysis
- `SECURITY.md` - Security policy
- `docs/security/` - Security documentation
- `threat-model.md` - Existing threat model

If previous ASIDE artifacts exist, read them to understand what was already analyzed.

## Phase 2: Technology Stack Analysis

### Step 2.1: Framework Detection

Read the dependency configuration to identify frameworks:

**For Node.js projects (package.json)**:
- Frontend: Look for react, vue, angular, svelte in dependencies
- Backend: Look for express, fastify, koa, nest, hapi
- ORM: Look for sequelize, typeorm, prisma, mongoose

**For Python projects (requirements.txt/pyproject.toml)**:
- Web: Look for django, flask, fastapi, starlette
- ORM: Look for sqlalchemy, django.db, tortoise-orm

**For other languages**: Apply similar pattern - find the web framework and ORM from dependencies.

### Step 2.2: Security Library Detection

From the same dependency file, identify security-related packages:

| Category | Examples |
|----------|----------|
| Authentication | passport, jsonwebtoken, bcrypt, argon2 |
| Authorization | casbin, casl, accesscontrol |
| Validation | joi, yup, zod, class-validator |
| Security headers | helmet, secure-headers |
| Rate limiting | express-rate-limit, bottleneck |
| Encryption | crypto, bcryptjs, node-forge |

### Step 2.3: Database Detection

Look for database indicators:

1. **Connection strings** in environment files (`.env`, `.env.example`)
2. **Database packages** in dependencies (pg, mysql2, mongodb, redis)
3. **Migration files** in folders like `migrations/`, `db/migrate/`
4. **ORM configuration** files (ormconfig.json, database.yml, alembic.ini)

## Phase 3: Architecture Pattern Recognition

### Step 3.1: Entry Point Analysis

Read the main entry point file (typically `index.js`, `app.js`, `main.py`, `main.rs`):

Understand:
- How the application starts
- What middleware is registered
- How routes are configured
- What services are initialized

### Step 3.2: Determine Architecture Type

Based on structure:

| Pattern | Indicators |
|---------|------------|
| Monolith | Single entry point, shared database, all code in one repo |
| Microservices | Multiple services with separate entry points, docker-compose |
| Serverless | Lambda handlers, serverless.yml, SAM templates |
| API-only | No frontend files, just API routes |
| Full-stack | Both frontend (React/Vue) and backend in same repo |

### Step 3.3: Deployment Pattern

Check for:
- `Dockerfile` → Containerized
- `docker-compose.yml` → Multi-container
- `serverless.yml` → Serverless Framework
- `template.yaml` → AWS SAM
- `terraform/` or `*.tf` → Infrastructure as Code
- `.github/workflows/` → CI/CD presence

## Phase 4: Security Feature Assessment

### Step 4.1: Authentication Review

Based on detected auth libraries:
1. Read the authentication middleware/handler file
2. Understand the authentication flow (JWT, session, OAuth)
3. Note token storage and validation approach

### Step 4.2: Authorization Review

If authorization libraries detected:
1. Read the authorization configuration
2. Understand permission model (RBAC, ABAC, ACL)
3. Note where authorization checks are applied

### Step 4.3: Input Validation Review

If validation libraries detected:
1. Check if validation is centralized
2. Note what validation patterns are used
3. Assess API endpoint coverage

## Output: Project Fingerprint

Create `.kiro/aside/generated/Project_Fingerprint.md`:

```markdown
# Project Fingerprint

**Generated**: [timestamp]
**Project**: [name from config]

## Technology Stack

### Primary Language
- **Language**: [TypeScript/JavaScript/Python/etc.]
- **Runtime**: [Node.js 18.x / Python 3.11 / etc.]

### Frameworks
| Type | Framework | Version |
|------|-----------|---------|
| Backend | Express | 4.18.x |
| Frontend | React | 18.x |
| ORM | Prisma | 5.x |

### Databases
| Type | Technology | Purpose |
|------|------------|---------|
| Primary | PostgreSQL | Main data store |
| Cache | Redis | Session cache |

## Architecture

### Pattern
[Monolith / Microservices / Serverless / Full-stack]

### Structure
```
[folder tree of key directories]
```

### Entry Points
- Main: `src/index.ts` - Application entry
- API: `src/routes/` - API route definitions

## Security Features

### Authentication
- **Method**: [JWT / Session / OAuth]
- **Library**: [passport / jsonwebtoken / etc.]
- **Implementation**: [file path]

### Authorization
- **Pattern**: [RBAC / ABAC / Custom]
- **Implementation**: [file path]

### Input Validation
- **Library**: [joi / zod / none]
- **Coverage**: [API endpoints / Forms / etc.]

### Security Middleware
- [ ] Security headers (helmet)
- [ ] Rate limiting
- [ ] CORS configuration
- [ ] CSRF protection

## Dependencies

### Security-Relevant Dependencies
| Package | Version | Purpose |
|---------|---------|---------|
| helmet | 7.x | Security headers |
| bcrypt | 5.x | Password hashing |

### Potential Concerns
- [List any obviously outdated security packages]
- [List any missing expected security packages]

## Risk Profile

### Attack Surface
- **External APIs**: [count] endpoints
- **Authentication**: [Required/Optional/None]
- **Database Access**: [Direct/ORM/Both]

### Initial Risk Assessment
- **Complexity**: [Low/Medium/High]
- **Security Maturity**: [Low/Medium/High]
- **Data Sensitivity**: [Low/Medium/High] (inferred from purpose)

## Next Steps

This fingerprint will be used by:
1. Step 2: Component Discovery - to identify security-relevant components
2. Step 4: MCP Integration - to fetch technology-specific guidance
3. Step 5: Threat Modeling - to identify relevant threats
```

## State Update

After completing, update `init_state.json`:

```json
{
  "currentStep": 2,
  "status": "in_progress",
  "completedSteps": [1],
  "artifacts": {
    "projectFingerprint": ".kiro/aside/generated/Project_Fingerprint.md"
  }
}
```

## Step Completion Gate

Before proceeding to Step 2, verify:

- [ ] Read primary configuration file (package.json, etc.)
- [ ] Understood folder structure
- [ ] Identified primary language and runtime
- [ ] Identified frameworks (frontend, backend, ORM)
- [ ] Identified security libraries in use
- [ ] Assessed authentication approach
- [ ] Created Project_Fingerprint.md with all sections
- [ ] Updated init_state.json

**Only proceed to Step 2 when all items are checked.**

---

**Next Step**: `step2-component-discovery.md` - Discover security-relevant components

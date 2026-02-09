# Drift Detection Instructions

## Persona

You are a **Security Infrastructure Analyst** responsible for detecting changes in the codebase that may impact security posture and determining appropriate security updates.

## Session Management

Follow the session management protocol in `session/session-management.md` for:
- Context loading and prioritization
- State persistence and checkpointing
- Error handling and recovery

## Context References

Load the following context files as needed:
- Generated `Project_Fingerprint.md` for baseline comparison
- Generated `Component_Map.md` for component tracking
- Session state from `.kiro/aside/generated/.session-state.json`

## Purpose
Assess existing security infrastructure and determine if incremental updates or full initialization is needed.

## Tools Required
- **glob**: Pattern matching for file discovery
- **grep**: Content searching within files
- **fs_read**: File content analysis

## Process

### 1. Check Existing Security Infrastructure
```
Use glob tool to discover:
- Pattern: "security/**/*" (existing security folder)
- Pattern: ".kiro/hooks/*security*" (existing security hooks)
- Pattern: ".kiro/steering/*security*" (existing steering documents)
- Pattern: ".aside/**/*" (extension artifacts)
```

### 2. Assess Infrastructure Currency
If security files exist:
```
Use glob to find dependency files:
- Pattern: "package.json" (Node.js projects)
- Pattern: "requirements.txt" (Python projects)  
- Pattern: "Cargo.toml" (Rust projects)
- Pattern: "pom.xml" (Java projects)
- Pattern: "go.mod" (Go projects)

Compare modification times:
- Are dependency files newer than security documents?
- Have significant changes occurred since last analysis?
```

### 3. Technology Stack Changes
```
Use grep to search for new technologies:
- Search pattern: "import.*react" (React adoption)
- Search pattern: "from.*django" (Django adoption)
- Search pattern: "use.*actix" (Actix-web adoption)
- Search pattern: "spring.*boot" (Spring Boot adoption)

Check for new security-relevant dependencies:
- Authentication libraries
- Encryption libraries
- Database connectors
- API frameworks
```

### 4. Configuration Drift
```
Use grep to check for configuration changes:
- Search pattern: "auth.*config" (authentication changes)
- Search pattern: "database.*url" (database changes)
- Search pattern: "api.*key" (API configuration changes)
- Search pattern: "cors.*origin" (CORS policy changes)
```

### 5. Decision Logic
```
FULL INITIALIZATION needed if:
- No existing security/ folder
- No existing .kiro/hooks/*security* files
- Dependency files >7 days newer than security docs
- Major technology stack changes detected
- >50% of components have changed

INCREMENTAL UPDATE sufficient if:
- Security infrastructure exists
- Dependency changes <7 days old
- Minor configuration changes only
- <25% of components changed
```

### 6. Output Requirements
Create drift assessment report:
```markdown
# Drift Detection Report

## Infrastructure Status
- Security folder exists: [YES/NO]
- Security hooks exist: [YES/NO]
- Steering documents exist: [YES/NO]

## Change Assessment
- Dependency file age: [X days]
- Security document age: [X days]
- Technology changes: [LIST]
- Configuration changes: [LIST]

## Recommendation
- Action needed: [FULL_INIT/INCREMENTAL/NONE]
- Reason: [EXPLANATION]
- Priority: [HIGH/MEDIUM/LOW]
```

## Delta Update Logic

**CRITICAL**: When incremental update is recommended, execute these specific delta operations instead of full re-initialization.

### Delta Update Process

```javascript
const deltaUpdateProcess = {
  // Step 1: Identify what changed
  identifyChanges: async (baselineState, currentState) => {
    return {
      addedFiles: findAddedFiles(baselineState, currentState),
      modifiedFiles: findModifiedFiles(baselineState, currentState),
      deletedFiles: findDeletedFiles(baselineState, currentState),
      addedDependencies: findAddedDependencies(baselineState, currentState),
      removedDependencies: findRemovedDependencies(baselineState, currentState),
      configChanges: findConfigChanges(baselineState, currentState)
    };
  },

  // Step 2: Determine impact scope
  determineImpactScope: (changes) => {
    const impactedComponents = [];

    for (const file of [...changes.addedFiles, ...changes.modifiedFiles]) {
      const component = mapFileToComponent(file);
      if (component && !impactedComponents.includes(component)) {
        impactedComponents.push(component);
      }
    }

    return {
      impactedComponents,
      requiresNewThreatAnalysis: changes.addedDependencies.length > 0,
      requiresComplianceUpdate: hasSecurityRelevantChanges(changes)
    };
  },

  // Step 3: Execute targeted updates
  executeTargetedUpdates: async (impactScope, changes) => {
    const updates = [];

    // Only re-profile impacted components
    for (const component of impactScope.impactedComponents) {
      const profile = await reprofileComponent(component);
      updates.push({ type: 'component-profile', component, profile });
    }

    // Update threat model for new dependencies only
    if (impactScope.requiresNewThreatAnalysis) {
      const newThreats = await analyzeNewDependencies(changes.addedDependencies);
      updates.push({ type: 'threat-model-delta', threats: newThreats });
    }

    // Update compliance mapping if needed
    if (impactScope.requiresComplianceUpdate) {
      const complianceDelta = await updateComplianceMapping(changes);
      updates.push({ type: 'compliance-delta', delta: complianceDelta });
    }

    return updates;
  }
};
```

### Incremental Update Operations

| Change Type | Delta Operation | Full Re-init Required? |
|-------------|-----------------|----------------------|
| New file in existing component | Re-profile that component only | No |
| New component directory | Profile new component, update Component_Map | No |
| Modified config file | Update relevant steering docs | No |
| New dependency added | Analyze dependency security, update Threat_Model | No |
| Dependency removed | Remove from analysis, no new threats | No |
| New technology detected | Full re-fingerprint, targeted profiling | Maybe |
| Major architecture change | Full re-initialization | Yes |
| >50% files changed | Full re-initialization | Yes |

### Delta Update Output Format

```json
// .kiro/aside/generated/.delta-update.json
{
  "deltaUpdateId": "delta-2026-01-12-001",
  "timestamp": "2026-01-12T10:30:00Z",
  "triggeredBy": "package.json modification",
  "changes": {
    "filesAdded": 2,
    "filesModified": 5,
    "filesDeleted": 0,
    "dependenciesAdded": ["axios@1.5.0"],
    "dependenciesRemoved": []
  },
  "impactScope": {
    "componentsReanalyzed": ["UserAPI", "AuthService"],
    "newThreatsIdentified": 1,
    "complianceUpdated": false
  },
  "artifactsUpdated": [
    ".kiro/aside/generated/Components/UserAPI_Profile.md",
    ".kiro/aside/generated/Components/AuthService_Profile.md",
    ".kiro/aside/generated/Threat_Model.md"
  ],
  "skippedArtifacts": [
    ".kiro/aside/generated/Project_Fingerprint.md",
    ".kiro/aside/generated/Compliance.md"
  ],
  "duration_ms": 5200
}
```

### Artifact Update Rules

**Project_Fingerprint.md**
- Update only if new technology/language detected
- Otherwise, append change log entry

**Component_Map.md**
- Add new components when directories created
- Remove components when directories deleted
- Update existing component metadata for file changes

**Component Profiles**
- Re-profile only impacted components
- Preserve existing profiles for unchanged components

**Threat_Model.md**
- Append new threats for new dependencies/components
- Do NOT remove existing threats (mark as "needs verification")
- Update threat status based on changes

**Compliance.md**
- Update only if security-relevant changes detected
- Append new compliance gaps without removing existing

### Merge Strategy for Delta Updates

```javascript
const mergeStrategy = {
  // Merge new threats into existing threat model
  mergeThreatModel: (existingModel, deltaThreats) => {
    return {
      ...existingModel,
      threats: [
        ...existingModel.threats,
        ...deltaThreats.map(t => ({
          ...t,
          addedBy: 'delta-update',
          addedAt: new Date().toISOString()
        }))
      ],
      lastUpdated: new Date().toISOString(),
      updateType: 'delta'
    };
  },

  // Merge component profiles
  mergeComponentProfiles: (existingProfiles, updatedProfiles) => {
    const merged = { ...existingProfiles };
    for (const [name, profile] of Object.entries(updatedProfiles)) {
      merged[name] = {
        ...profile,
        previousVersion: existingProfiles[name]?.version,
        version: (existingProfiles[name]?.version || 0) + 1
      };
    }
    return merged;
  }
};
```

## Success Criteria
1. ✅ All existing security infrastructure catalogued
2. ✅ Dependency and configuration changes assessed
3. ✅ Technology stack changes identified
4. ✅ Clear recommendation provided (FULL_INIT/INCREMENTAL/NONE)
5. ✅ Drift assessment report generated
6. ✅ Delta updates preserve unchanged analysis
7. ✅ Only impacted components re-analyzed

## Next Steps
- If FULL_INIT: Proceed to Step 1 (Project Fingerprinting)
- If INCREMENTAL: Execute delta update process above
- If NONE: Create maintenance hook only

# Sub-Agent Coordination for Kiro

## Purpose

Coordinate ASIDE analysis tasks using Kiro's parallel subagent capabilities. This document defines how to:
- Leverage parallel subagents for efficient analysis
- Delegate tasks to appropriate subagent types
- Manage context windows across agents
- Aggregate results from concurrent operations

## Kiro Subagent Model (December 2025+)

### Available Subagent Types

Kiro provides two built-in subagent types:

| Subagent Type | Purpose | Context | Use For |
|---------------|---------|---------|---------|
| **Context Gatherer** | Fast codebase exploration | Separate from main | Component discovery, file scanning, dependency mapping |
| **General Purpose** | Complex multi-step tasks | Separate from main | Component profiling, threat analysis, detailed reviews |

### Key Benefits
1. **Separate Context Windows**: Each subagent has its own context, keeping main agent clean
2. **Parallel Execution**: Multiple subagents can work concurrently
3. **Targeted Delegation**: Right tool for the right task
4. **Reduced Main Context Load**: Heavy analysis offloaded to subagents

## Task Delegation Strategy

### When to Use Context Gatherer
- Initial codebase exploration
- Finding files matching patterns
- Mapping component structure
- Dependency discovery
- Quick searches across many files

### When to Use General Purpose Subagent
- Deep component analysis requiring multi-step reasoning
- Security vulnerability assessment
- Threat modeling per component
- Code review with detailed findings
- Complex pattern detection

### When to Keep in Main Agent
- Coordination decisions
- User interaction
- State management
- Final result aggregation
- Session continuity operations

## Initialization Task Flow

### Phase 1: Foundation (Main Agent + Context Gatherer)
```
Main Agent: Start initialization
    ↓
Context Gatherer Subagent: Scan codebase structure
    ↓ Returns: file listing, tech stack indicators
Main Agent: Create Project_Fingerprint.md
    ↓
Context Gatherer Subagent: Find all entry points, configs, security files
    ↓ Returns: Component candidates
Main Agent: Create Component_Map.md
```

### Phase 2: Analysis (Parallel General Purpose Subagents)
```
Main Agent: Batch components by type

Subagent Batch 1: Auth components profiling
Subagent Batch 2: API components profiling     [PARALLEL]
Subagent Batch 3: Data components profiling

Each batch returns: Components/[name]_Profile.md content
    ↓
Main Agent: Aggregate and save all profiles
```

### Phase 3: Threat Modeling (Main Agent + General Purpose)
```
Main Agent: Load aggregated profiles
    ↓
General Purpose Subagent: Apply STRIDE + MAESTRO analysis
    ↓ Returns: Threat findings
Main Agent: Create Threat_Model.md
```

### Phase 4: Artifacts (Main Agent)
```
Main Agent: Generate validation hooks
Main Agent: Generate steering documents
Main Agent: Create drift detection hook
Main Agent: Save initialization-complete.md
```

## Delegation Syntax

### For Context Gatherer Tasks
```markdown
Use context gatherer subagent to: [specific exploration task]
- Target: [files/patterns/directories]
- Return: [expected information format]
```

### For General Purpose Tasks
```markdown
Use general purpose subagent to: [analysis task]
- Input: [context required]
- Analyze: [what to examine]
- Return: [structured output format]
```

### Batch Delegation Pattern
```markdown
For component batch [1 of N]:
  Components: [list]
  Use general purpose subagent to:
  - Profile each component's security characteristics
  - Identify vulnerabilities using context files
  - Return structured profile for each component
```

## Context Management

### Main Agent Context Budget
Reserve main agent context for:
- Session state management (10%)
- Coordination logic (10%)
- Result aggregation (20%)
- User interaction buffer (10%)
- Current task execution (50%)

### Offload to Subagents
- Detailed code analysis (use general purpose)
- Codebase exploration (use context gatherer)
- Multi-file pattern matching (use context gatherer)
- Deep security review (use general purpose)

### Context Handoff Protocol
When delegating:
1. Provide only essential context to subagent
2. Specify exact return format
3. Let subagent load files it needs
4. Aggregate returned results in main

## Dependency Management

### Dependency Matrix
| Task | Depends On | Required Output |
|------|------------|-----------------|
| Component Discovery | Fingerprint | Project_Fingerprint.md |
| Component Profiling | Discovery | Component_Map.md |
| Threat Modeling | All Profiles | Components/*.md |
| Validation Hooks | Threat Model | Threat_Model.md |
| Steering Docs | Validation Hooks | Threat findings |

### Dependency Check Before Delegation
```javascript
// Before delegating profiling batch
function canDelegateBatch(batch) {
    if (!fileExists('generated/Component_Map.md')) {
        return { ready: false, reason: 'Component map required' };
    }
    return { ready: true };
}
```

## Result Aggregation

### Subagent Results Format
Each subagent should return structured output:
```json
{
  "task": "component_profiling",
  "batch": 1,
  "components_analyzed": ["Auth", "Session", "Permissions"],
  "results": [
    {
      "component": "Auth",
      "profile_content": "...",
      "vulnerabilities_found": 3,
      "criticality": "high"
    }
  ],
  "status": "complete"
}
```

### Main Agent Aggregation
```markdown
After all subagent batches return:
1. Collect all profile content
2. Save each to generated/Components/[name]_Profile.md
3. Update .session-state.json with actual counts
4. Verify file count matches expected count
5. Proceed to threat modeling only if verified
```

## Error Handling

### Subagent Failure Recovery
```
Subagent fails
    ↓
Main agent receives error
    ↓
[Retryable] → Re-delegate same batch
[Not retryable] → Mark components as skipped
    ↓
Continue with other batches
    ↓
Final report notes incomplete coverage
```

### Partial Batch Completion
If subagent partially completes:
- Accept completed component profiles
- Re-delegate only failed components
- Log which components need manual review

## Verification Gates

### After Subagent Delegation
**MANDATORY**: Verify subagent results before proceeding

```markdown
After all profiling subagents return:
1. Count actual profile files: ls generated/Components/*.md | wc -l
2. Compare to expected: Component_Map component count
3. If actual < expected:
   - Log missing components
   - Either re-delegate or report gap to user
4. Only proceed to threat modeling when:
   - Profile count >= 90% of component count, OR
   - User explicitly approves partial analysis
```

---

## Subagent Result Verification Loop

**BLOCKING RULE**: Never trust claimed counts. Always verify artifacts on disk.

### Verification Protocol

When a subagent returns results, the main agent MUST execute this verification loop:

```javascript
// MANDATORY: Subagent Result Verification
const verifySubagentResults = async (subagentResult, expectedComponents) => {
  const verificationLog = {
    subagent: subagentResult.task,
    batch: subagentResult.batch,
    claimed: {
      componentsAnalyzed: subagentResult.components_analyzed.length,
      profilesGenerated: subagentResult.results.length
    },
    actual: {},
    discrepancies: [],
    retryNeeded: []
  };

  // Step 1: Verify each claimed profile was actually saved
  for (const result of subagentResult.results) {
    const expectedPath = `.kiro/aside/generated/Components/${result.component}_Profile.md`;
    const fileExists = await checkFileExists(expectedPath);

    if (!fileExists) {
      verificationLog.discrepancies.push({
        component: result.component,
        issue: 'Profile file not found on disk',
        claimedPath: expectedPath
      });
      verificationLog.retryNeeded.push(result.component);
    } else {
      // Step 2: Verify file content is not empty/placeholder
      const content = await readFile(expectedPath);
      if (content.length < 500 || !content.includes('## Vulnerabilities Found')) {
        verificationLog.discrepancies.push({
          component: result.component,
          issue: 'Profile file is incomplete or placeholder',
          contentLength: content.length
        });
        verificationLog.retryNeeded.push(result.component);
      }
    }
  }

  // Step 3: Count actual files on disk
  const actualFiles = await glob('.kiro/aside/generated/Components/*_Profile.md');
  verificationLog.actual.fileCount = actualFiles.length;
  verificationLog.actual.files = actualFiles.map(f => path.basename(f));

  // Step 4: Determine if verification passed
  const claimedCount = verificationLog.claimed.profilesGenerated;
  const actualCount = verificationLog.actual.fileCount;

  verificationLog.passed = (actualCount >= claimedCount) &&
                           (verificationLog.retryNeeded.length === 0);

  verificationLog.accuracy = actualCount / Math.max(claimedCount, 1);

  return verificationLog;
};
```

### Retry Protocol for Failed Verifications

```javascript
// When verification fails, retry with explicit instructions
const retryFailedComponents = async (failedComponents, originalBatch) => {
  const maxRetries = 2;
  let attempt = 0;

  while (failedComponents.length > 0 && attempt < maxRetries) {
    attempt++;
    console.log(`Retry attempt ${attempt} for ${failedComponents.length} components`);

    // Re-delegate with explicit save verification request
    const retryResult = await delegateToSubagent({
      task: 'component_profiling_retry',
      components: failedComponents,
      instructions: `
        RETRY: These components failed verification. For EACH component:
        1. Analyze the component thoroughly
        2. Generate the profile content
        3. EXPLICITLY save to .kiro/aside/generated/Components/[Name]_Profile.md
        4. VERIFY the file was written by reading it back
        5. Report any save failures immediately

        Components requiring retry: ${failedComponents.join(', ')}
      `
    });

    // Verify retry results
    const retryVerification = await verifySubagentResults(retryResult, failedComponents);

    if (retryVerification.passed) {
      return { success: true, retriesUsed: attempt };
    }

    // Update failed list for next attempt
    failedComponents = retryVerification.retryNeeded;
  }

  // Max retries exceeded
  return {
    success: false,
    retriesUsed: maxRetries,
    stillFailing: failedComponents,
    action: 'ESCALATE_TO_USER'
  };
};
```

### Verification Checkpoints

After EVERY subagent batch completes:

| Checkpoint | Action | Pass Criteria | Failure Action |
|------------|--------|---------------|----------------|
| File Count | `ls generated/Components/*.md \| wc -l` | Count >= claimed | Retry failed components |
| Content Check | Verify each file > 500 chars | All files substantial | Re-analyze empty files |
| Format Check | Verify required sections exist | All sections present | Regenerate malformed profiles |
| Cross-Reference | Match files to Component_Map | All expected files exist | Log missing, retry |

### Main Agent Verification Code

```markdown
After each subagent batch returns:

1. **DO NOT** immediately update session state metrics
2. **EXECUTE** verification protocol:
   ```bash
   # Count actual files
   ACTUAL=$(ls -1 .kiro/aside/generated/Components/*_Profile.md 2>/dev/null | wc -l)

   # Compare to claimed
   CLAIMED=[subagent claimed count]

   if [ "$ACTUAL" -lt "$CLAIMED" ]; then
     echo "VERIFICATION FAILED: Actual ($ACTUAL) < Claimed ($CLAIMED)"
     # Trigger retry protocol
   fi
   ```

3. **ONLY AFTER** verification passes:
   - Update session state with ACTUAL count
   - Log verification result
   - Proceed to next batch

4. **IF** verification fails after retries:
   - Report to user with specific failures
   - Ask: "X components failed profiling. Options: A) Skip and continue, B) Manual review"
   - Do NOT silently proceed with incomplete analysis
```

### Verification Log Format

Save to `.kiro/aside/generated/.verification-log.json`:

```json
{
  "verifications": [
    {
      "timestamp": "ISO-8601",
      "batch": "authentication_batch_1",
      "subagent": "general_purpose",
      "claimed": {
        "components": ["AuthService", "TokenManager", "SessionStore"],
        "count": 3
      },
      "verified": {
        "filesFound": 3,
        "contentValid": 3,
        "files": [
          "AuthService_Profile.md",
          "TokenManager_Profile.md",
          "SessionStore_Profile.md"
        ]
      },
      "passed": true,
      "retriesUsed": 0
    },
    {
      "timestamp": "ISO-8601",
      "batch": "api_batch_1",
      "subagent": "general_purpose",
      "claimed": {
        "components": ["UserAPI", "OrderAPI", "PaymentAPI"],
        "count": 3
      },
      "verified": {
        "filesFound": 2,
        "contentValid": 2,
        "files": ["UserAPI_Profile.md", "OrderAPI_Profile.md"]
      },
      "passed": false,
      "failures": ["PaymentAPI - file not found"],
      "retryAttempted": true,
      "finalResult": "PASSED after 1 retry"
    }
  ],
  "summary": {
    "totalBatches": 6,
    "passedFirstAttempt": 5,
    "passedAfterRetry": 1,
    "failed": 0,
    "overallAccuracy": 1.0
  }
}
```

### Critical Rules

1. **NEVER** update `componentsProfiled` in session state without verification
2. **ALWAYS** run file count verification after subagent returns
3. **ALWAYS** log verification results for audit trail
4. **RETRY** failed components before reporting to user
5. **ESCALATE** to user only after retry exhaustion
6. **INCLUDE** verification log path in session state outputs

## Metrics Tracking

### Per-Subagent Metrics
```json
{
  "subagent_type": "general_purpose",
  "task": "component_profiling_batch_1",
  "components": ["Auth", "Session"],
  "duration_ms": 15000,
  "result": "success",
  "profiles_generated": 2
}
```

### Aggregated Session Metrics
```json
{
  "initialization_summary": {
    "subagent_invocations": 5,
    "context_gatherer_calls": 2,
    "general_purpose_calls": 3,
    "total_duration_ms": 45000,
    "coverage": {
      "components_expected": 47,
      "components_profiled": 47,
      "completion_rate": 1.0
    }
  }
}
```

## Constraints

- Always verify subagent results before proceeding
- Never skip dependency checks
- Keep main agent focused on coordination
- Batch components efficiently (8-12 per batch)
- Aggregate metrics from all subagents
- Report partial completion honestly

## Success Criteria

- All components profiled (or explicit approval for partial)
- Results properly aggregated
- Metrics captured for every subagent call
- Errors logged and recovery attempted
- Verification gates passed before phase transitions

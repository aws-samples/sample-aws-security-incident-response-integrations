# Session Management for Kiro IDE

## Purpose

This document defines how ASIDE manages security analysis sessions within Kiro IDE. Read this document at the start of every session to understand:
- How to load and persist state
- How to checkpoint for continuation
- How to use Kiro's tools efficiently
- How to coordinate with other agents

## Kiro Tool Usage

### Available Kiro Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| Read file | Read file contents | Understanding code, loading state |
| Write file | Create/update files | Saving artifacts, checkpoints |
| List directory | See folder structure | Discovering project layout |
| Search/grep | Find patterns in code | Locating specific implementations |
| Glob | Find files by pattern | Finding all files of a type |

### Efficient Tool Usage

**DO**: Batch related operations together
```
Instead of reading one file at a time, identify which files you need and read them together.
```

**DO**: Use configuration files to understand the project
```
Read package.json, requirements.txt, Cargo.toml to understand dependencies before searching code.
```

**DON'T**: Execute shell commands that pipe to other commands
```
Kiro cannot execute: find . -name "*.ts" | wc -l
Instead: Use glob to find files, then count the results.
```

**DON'T**: Run exhaustive searches for generic terms
```
Avoid: Search for "login" across all files
Instead: Find authentication middleware in the framework-specific location.
```

## Session State

### State File Location

`.kiro/aside/generated/init_state.json`

### State Structure

```json
{
  "currentStep": 3,
  "status": "in_progress",
  "lastUpdated": "2026-01-13T10:30:00Z",
  "completedSteps": [1, 2],
  "artifacts": {
    "projectFingerprint": ".kiro/aside/generated/Project_Fingerprint.md",
    "componentMap": ".kiro/aside/generated/Component_Map.md"
  },
  "checkpoints": {
    "step3": {
      "lastComponent": "UserService",
      "completedComponents": ["AuthService", "DataService"],
      "remainingComponents": ["PaymentService", "NotificationService"]
    }
  }
}
```

### When to Update State

1. **After completing each step**: Update `completedSteps` and `currentStep`
2. **After creating artifacts**: Add path to `artifacts`
3. **During long operations**: Update checkpoint every 5-8 items processed
4. **On error**: Save current progress before reporting error

## Context Loading Strategy

### Priority Order

Load context in this order to minimize token usage:

1. **State file first** - Know where you are
2. **Current step instruction** - Know what to do
3. **Generated artifacts** - Know what exists
4. **Context files** - Reference as needed

### Lazy Loading

Don't read files unless you need them. For example:
- Don't read compliance context unless you're on Step 6
- Don't read threat modeling context unless you're on Step 5
- Don't re-read Project_Fingerprint.md if you already loaded it

### Context File Locations

| Type | Location | When Needed |
|------|----------|-------------|
| Session instructions | `.kiro/aside/instructions/session/` | Always |
| Step instructions | `.kiro/aside/instructions/initialization/` | During init |
| Compliance context | `.kiro/aside/context/compliance/` | Step 6 |
| Analysis patterns | `.kiro/aside/context/analysis/` | Steps 2-5 |
| Technology context | `.kiro/aside/context/technology/` | As relevant |

## Checkpointing Protocol

### When to Checkpoint

- After completing each major step
- After processing a batch of components (recommended: every 5-8)
- Before any operation that might fail
- When you notice context pressure (responses getting shorter)

### How to Checkpoint

1. **Update init_state.json** with current progress
2. **Save partial artifacts** if mid-step
3. **Log checkpoint** in progress file

### Checkpoint for Step 3 (Component Profiling)

Step 3 processes multiple components. Checkpoint after each batch:

```json
{
  "checkpoints": {
    "step3": {
      "lastComponent": "PaymentService",
      "completedComponents": ["AuthService", "UserService", "DataService"],
      "remainingComponents": ["OrderService", "NotificationService"]
    }
  }
}
```

## Checkpoint-Aware Initialization

When resuming from checkpoint:

1. **Load Checkpoint**
   - Read `.kiro/aside/generated/init_state.json`
   - Note current step number and completed components

2. **Skip Completed Steps**
   - Steps 1 through (current-1) are already done
   - Skip their execution entirely
   - Do NOT regenerate already-created artifacts

3. **Resume Current Step**
   - Start from the `lastFile` and `lastLine` if available
   - Continue processing pending components

4. **Clear on Completion**
   - After step 8 completes successfully
   - Delete `init_state.json`
   - Report completion to user

---

## Continuation Protocol

### How Continuation Works

1. `aside_start.kiro.hook` triggers on session start
2. Hook reads `init_state.json`
3. If initialization is incomplete, resume from checkpoint
4. If complete, hand off to maintenance mode

### Resuming from Checkpoint

When resuming:
1. Read `init_state.json` to find `currentStep`
2. Check `checkpoints` for step-specific progress
3. Skip already-completed components
4. Continue from last position

### Context Exhaustion Recovery

If a session ends unexpectedly:
1. The `aside-init-continuation.kiro.hook` triggers
2. It reads `init_state.json` to determine status
3. If incomplete, it automatically continues from checkpoint
4. No user intervention needed

## Progress Tracking

### Progress File

Maintain `.kiro/aside/generated/progress.md` for visibility:

```markdown
# ASIDE Initialization Progress

**Status**: In Progress
**Current Step**: 3/8 - Component Profiling
**Last Updated**: 2026-01-13 10:30:00

## Completed
- [x] Step 1: Project Fingerprinting
- [x] Step 2: Component Discovery
- [ ] Step 3: Component Profiling (5/12 components)

## Next Steps
- Step 4: Technology Context
- Step 5: Threat Modeling
- Step 6: Compliance Mapping
- Step 7: Validation Hooks
- Step 8: Finalization
```

### Update Frequency

Update progress.md:
- At the start of each step
- After each batch of components
- On completion of each step

## Error Handling

### Recoverable Errors

| Error | Recovery Action |
|-------|-----------------|
| File not found | Use defaults, continue |
| Parse error | Log warning, skip item |
| Context pressure | Checkpoint and exit gracefully |

### Non-Recoverable Errors

| Error | Action |
|-------|--------|
| Cannot write to workspace | Notify user |
| Invalid project structure | Ask user for guidance |
| Permission denied | Notify user |

### Error Logging

Log errors to `.kiro/aside/metrics/errors.jsonl`:
```json
{"timestamp": "2026-01-13T10:30:00Z", "step": 3, "error": "Could not parse component", "file": "src/legacy/old-code.ts", "recovered": true}
```

## Artifact Verification

### Before Marking Step Complete

Verify the required artifact exists:

| Step | Required Artifact |
|------|-------------------|
| 1 | `Project_Fingerprint.md` |
| 2 | `Component_Map.md` |
| 3 | One `*_Profile.md` per component in Component_Map |
| 5 | `Threat_Model.md` |
| 6 | `Compliance.md` |
| 7 | At least one validation hook |
| 8 | Status file and steering docs |

### Verification Process

1. Read the artifact file
2. Confirm it contains required sections
3. Update `init_state.json` only after verification
4. If missing, do not mark step complete

## Sub-Agent Coordination

### When to Delegate

Delegate to sub-agents for:
- Analyzing components in parallel (Step 3)
- Independent MCP queries (Step 4)
- Large-scale threat enumeration (Step 5)

### Delegation Pattern

```
Main agent coordinates:
1. Identify work to delegate
2. Specify exact deliverable for sub-agent
3. Sub-agent performs analysis
4. Main agent verifies results
5. Main agent aggregates and proceeds
```

### Sub-Agent Results

Always verify sub-agent results:
- Check that output files exist
- Validate content meets requirements
- Don't trust claimed metrics - verify artifacts

## Initialization Completion

### All Steps Must Pass

Initialization is complete only when ALL conditions are met:
- Steps 1-8 all have `status: complete` in init_state.json
- All required artifacts exist and are valid
- `drift_detection.kiro.hook` is created
- `init_state.json` has `status: completed`

### Post-Initialization

After initialization completes:
1. Delete `.kiro/aside/instructions/initialization/` folder
2. Delete `aside-init-continuation.kiro.hook`
3. Enable validation hooks
4. Enable drift detection

### Features Blocked Until Complete

These features are NOT active until initialization finishes:
- Validation hooks (don't trigger)
- Drift detection (don't trigger)
- Security steering (not available)

## Silent Operation

Work silently during initialization. Only output:
- On error requiring user attention
- On completion of full initialization
- Brief progress updates: "Resuming from step 3..."

Do NOT output:
- Debug information
- File contents being processed
- Intermediate analysis details

## Quick Reference

### Session Start Checklist

1. Read `init_state.json`
2. If `status: completed` → Exit (maintenance mode handles ongoing)
3. If `status: in_progress` → Resume from `currentStep`
4. If file doesn't exist → This is first run, start Step 1

### Step Completion Checklist

1. Verify artifact was created
2. Read artifact to confirm content
3. Update `init_state.json`:
   - Add step to `completedSteps`
   - Increment `currentStep`
   - Update `lastUpdated`
4. Update `progress.md`

### Context Pressure Checklist

If responses get shorter or you're re-reading files:
1. Stop current batch
2. Save checkpoint immediately
3. Update progress.md
4. Exit gracefully
5. Continuation hook will resume next session

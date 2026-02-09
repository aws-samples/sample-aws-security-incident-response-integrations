# Session State Validation Protocol

## Purpose

Ensure session state metrics accurately reflect actual generated artifacts. This protocol prevents inflated claims and provides reliable progress tracking throughout ASIDE initialization and operation.

## Problem Statement

Session state can become inaccurate when:
- Agent claims components profiled but files weren't created
- Metrics are updated optimistically before work completes
- Subagent results aren't properly verified
- Errors occur but state isn't rolled back

## Validation Principles

1. **Artifacts Over Claims**: File counts on disk are truth; session state follows
2. **Verify Before Update**: Check actual results before updating metrics
3. **External Verification**: Use file system checks, not agent memory
4. **Fail Safe**: When uncertain, report lower numbers

## Validation Functions

### Core Validation

```javascript
const StateValidator = {
  // Validate component profiling metrics
  validateComponentProfiles: async (sessionState) => {
    const claimed = sessionState.metrics?.componentsProfiled || 0;

    // Count actual profile files
    const profileDir = '.kiro/aside/generated/Components';
    const profiles = await glob(`${profileDir}/*_Profile.md`);
    const actual = profiles.length;

    if (claimed !== actual) {
      console.warn(`VALIDATION MISMATCH: Claimed ${claimed} profiles, found ${actual}`);
      return {
        valid: false,
        claimed,
        actual,
        correction: actual
      };
    }

    return { valid: true, count: actual };
  },

  // Validate step completion status
  validateStepCompletion: async (step, sessionState) => {
    const stepConfig = {
      step1: {
        required: ['.kiro/aside/generated/Project_Fingerprint.md'],
        metrics: ['techStack', 'entryPoints']
      },
      step2: {
        required: ['.kiro/aside/generated/Component_Map.md'],
        metrics: ['componentCount', 'trustBoundaries']
      },
      step3: {
        required: ['.kiro/aside/generated/Service_Profile_Summary.md'],
        validate: async () => {
          // Special validation for step 3 - profile count check
          const componentMap = await loadFile('.kiro/aside/generated/Component_Map.md');
          const expectedCount = parseComponentCount(componentMap);
          const profiles = await glob('.kiro/aside/generated/Components/*_Profile.md');
          return {
            valid: profiles.length >= expectedCount,
            expected: expectedCount,
            actual: profiles.length
          };
        }
      },
      step5: {
        required: ['.kiro/aside/generated/Threat_Model.md'],
        metrics: ['threatsIdentified', 'criticalThreats']
      },
      step6: {
        required: ['.kiro/aside/generated/Compliance_Mapping.md'],
        metrics: ['frameworksCovered']
      }
    };

    const config = stepConfig[step];
    if (!config) return { valid: true }; // Unknown step, allow

    // Check required files exist
    for (const file of config.required || []) {
      if (!await fileExists(file)) {
        return {
          valid: false,
          reason: `Required file missing: ${file}`,
          step
        };
      }
    }

    // Run custom validation if defined
    if (config.validate) {
      const result = await config.validate();
      if (!result.valid) {
        return {
          valid: false,
          reason: `Custom validation failed`,
          details: result,
          step
        };
      }
    }

    return { valid: true, step };
  },

  // Full session state validation
  validateSessionState: async (sessionState) => {
    const issues = [];

    // Check all completed steps
    for (const [stepKey, stepData] of Object.entries(sessionState.steps || {})) {
      if (stepData.gatesPassed) {
        const validation = await StateValidator.validateStepCompletion(stepKey, sessionState);
        if (!validation.valid) {
          issues.push({
            step: stepKey,
            issue: validation.reason,
            details: validation
          });
        }
      }
    }

    // Validate component profiling specifically
    const profileValidation = await StateValidator.validateComponentProfiles(sessionState);
    if (!profileValidation.valid) {
      issues.push({
        type: 'metrics',
        field: 'componentsProfiled',
        claimed: profileValidation.claimed,
        actual: profileValidation.actual
      });
    }

    return {
      valid: issues.length === 0,
      issues,
      correctedState: issues.length > 0 ? await StateValidator.correctState(sessionState, issues) : sessionState
    };
  },

  // Correct state based on validation issues
  correctState: async (sessionState, issues) => {
    const corrected = JSON.parse(JSON.stringify(sessionState));

    for (const issue of issues) {
      if (issue.type === 'metrics' && issue.field === 'componentsProfiled') {
        corrected.metrics.componentsProfiled = issue.actual;
        console.log(`Corrected componentsProfiled: ${issue.claimed} -> ${issue.actual}`);
      }

      if (issue.step && issue.details?.valid === false) {
        // Mark step as incomplete if validation failed
        if (corrected.steps[issue.step]) {
          corrected.steps[issue.step].gatesPassed = false;
          corrected.steps[issue.step].validationFailed = true;
          corrected.steps[issue.step].validationReason = issue.issue;
        }
      }
    }

    return corrected;
  }
};
```

## Validation Triggers

### When to Validate

| Event | Action |
|-------|--------|
| Before marking step complete | Validate step artifacts exist |
| Before updating session state | Validate claimed metrics match actual |
| On session resume | Full validation of all completed steps |
| Before activating hooks | Validate initialization complete |
| After subagent returns | Validate subagent claims vs saved files |

### Validation Hook

```json
// .kiro/hooks/aside-validate-state.kiro.hook
{
  "name": "ASIDE State Validation",
  "version": "1",
  "when": {
    "type": "fileModified",
    "pattern": ".kiro/aside/generated/.session-state.json"
  },
  "then": {
    "type": "askAgent",
    "prompt": "Validate ASIDE session state against actual artifacts. Report any discrepancies."
  }
}
```

## Validation Responses

### On Validation Success

```markdown
Session state validated:
- Step completion: All verified
- Component profiles: 47/47 match
- Artifacts: All required files present
```

### On Validation Failure

```markdown
Session state validation FAILED:
- componentsProfiled: Claimed 47, found 8
- Correcting session state...
- Action required: Continue component profiling
```

## Integration Points

### With Session Management

Before saving session state:
```javascript
const saveSessionState = async (state) => {
  // Validate before save
  const validation = await StateValidator.validateSessionState(state);

  if (!validation.valid) {
    console.warn('Session state validation failed:', validation.issues);
    state = validation.correctedState;
  }

  await writeFile('.kiro/aside/generated/.session-state.json', JSON.stringify(state, null, 2));
};
```

### With Step Completion

Before marking any step complete:
```javascript
const markStepComplete = async (step, sessionState) => {
  const validation = await StateValidator.validateStepCompletion(step, sessionState);

  if (!validation.valid) {
    throw new Error(`Cannot mark ${step} complete: ${validation.reason}`);
  }

  sessionState.steps[step].gatesPassed = true;
  sessionState.steps[step].validatedAt = new Date().toISOString();
};
```

### With Subagent Results

After receiving subagent results:
```javascript
const processSubagentResults = async (results, sessionState) => {
  // Don't trust claimed counts - verify actual files
  for (const result of results) {
    if (result.type === 'component_profile') {
      // Verify file was actually created
      const path = `.kiro/aside/generated/Components/${result.componentName}_Profile.md`;
      if (!await fileExists(path)) {
        console.error(`Subagent claimed profile created but file missing: ${path}`);
        continue;
      }
      // Only count verified profiles
      sessionState.metrics.componentsProfiled++;
    }
  }
};
```

## Error Recovery

### On Validation Mismatch

1. Log the discrepancy
2. Correct session state to match reality
3. Report to user what was corrected
4. Do NOT proceed if critical artifacts missing

### On Missing Artifacts

1. Check if partial results exist
2. Offer options:
   - Resume and complete missing work
   - Proceed with partial (if user approves)
   - Restart from last valid checkpoint

## Best Practices

1. **Validate Early, Validate Often**
   - Check after every batch
   - Don't wait until end to discover issues

2. **Trust Files, Not Memory**
   - File system is source of truth
   - Agent memory can be unreliable

3. **Fail Loudly**
   - Report validation failures immediately
   - Don't silently correct and continue

4. **Audit Trail**
   - Log all validations
   - Track corrections made

## Metrics for Monitoring

```json
// .kiro/aside/metrics/validation-log.json
{
  "validations": [
    {
      "timestamp": "ISO-8601",
      "trigger": "step_completion",
      "step": "step3",
      "valid": false,
      "issues": [
        {
          "type": "artifact_count",
          "claimed": 47,
          "actual": 8
        }
      ],
      "correction_applied": true
    }
  ],
  "summary": {
    "total_validations": 15,
    "failures": 2,
    "corrections": 2
  }
}
```

## Constraints

- Never skip validation for step completion
- Always use file system checks, not memory
- Report mismatches transparently
- Correct state before continuing
- Log all validation events

## Success Criteria

- Session state always matches actual artifacts
- No inflated claims pass validation
- Validation runs at every critical checkpoint
- Corrections are logged and reported
- Users trust metrics because they're verified

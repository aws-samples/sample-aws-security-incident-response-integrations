# Command Injection (CWE-78)

## Vulnerability Overview
- **CWE**: CWE-78 - Improper Neutralization of Special Elements used in an OS Command
- **OWASP**: A03:2021 - Injection
- **Severity**: Critical
- **CVSS Base**: 9.8

## Detection Patterns

### Node.js

**Dangerous Patterns:**
```javascript
// child_process with string command
const { exec, execSync } = require('child_process');

exec(`ls ${userInput}`);
execSync(`cat ${filename}`);
exec(command + userInput);

// spawn with shell: true
spawn('sh', ['-c', userCommand], { shell: true });
spawn(userInput, { shell: true });

// Template literals in commands
exec(`convert ${inputFile} ${outputFile}`);
```

**Safe Patterns:**
```javascript
// execFile with array arguments (no shell)
const { execFile } = require('child_process');
execFile('ls', ['-la', validatedPath]);

// spawn without shell
spawn('node', ['script.js', '--arg', sanitizedValue], { shell: false });

// Whitelist approach
const allowedCommands = ['list', 'info', 'status'];
if (allowedCommands.includes(userCommand)) {
  execFile(COMMAND_MAP[userCommand], []);
}
```

### Python

**Dangerous Patterns:**
```python
# os.system
os.system(f"ls {user_input}")
os.system("cat " + filename)

# subprocess with shell=True
subprocess.call(f"grep {pattern} {file}", shell=True)
subprocess.Popen(user_command, shell=True)

# os.popen
os.popen(f"ls {directory}")
```

**Safe Patterns:**
```python
# subprocess with array args
subprocess.run(['ls', '-la', validated_path], check=True)
subprocess.call(['grep', pattern, file])

# shlex.split for parsing
import shlex
args = shlex.split(command)  # Still validate!
subprocess.run(args, shell=False)

# Use specific libraries instead of shell
import glob
files = glob.glob(pattern)  # Instead of shell glob
```

### Java

**Dangerous Patterns:**
```java
// Runtime.exec with string
Runtime.getRuntime().exec("cmd.exe /c " + userInput);
Runtime.getRuntime().exec(command + " " + args);

// ProcessBuilder with shell
new ProcessBuilder("sh", "-c", userCommand).start();
```

**Safe Patterns:**
```java
// ProcessBuilder with array
ProcessBuilder pb = new ProcessBuilder("ls", "-la", validatedPath);
pb.start();

// Separate command and arguments
List<String> command = new ArrayList<>();
command.add("grep");
command.add(pattern);
command.add(file);
new ProcessBuilder(command).start();
```

## Detection Regex

```regex
# Node.js exec with user input
exec(Sync)?\s*\(\s*[`'"].*\$\{|exec(Sync)?\s*\(\s*.*\+

# Node.js spawn with shell
spawn\s*\([^)]*shell\s*:\s*true

# Python os.system with f-string
os\.system\s*\(\s*f['\"]

# Python subprocess shell=True
subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True

# Java Runtime.exec with concatenation
Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+
```

## Shell Metacharacters

Characters that can modify command behavior:
- **Command separators**: `;`, `&&`, `||`, `|`, `\n`
- **Command substitution**: `` `cmd` ``, `$(cmd)`
- **Redirection**: `>`, `>>`, `<`, `2>`
- **Globbing**: `*`, `?`, `[...]`
- **Variables**: `$VAR`, `${VAR}`

## False Positive Indicators

- **Hardcoded commands**: `exec('ls -la')` with no user input
- **Environment variables only**: `exec(process.env.COMMAND)`
- **Validated/whitelisted input**: Input checked against allowlist
- **Test utilities**: Commands in test setup/teardown
- **Build scripts**: npm/gradle/maven commands

## Remediation

### Input Validation
```javascript
// Whitelist validation
const allowedFiles = ['report.txt', 'summary.txt', 'log.txt'];
if (!allowedFiles.includes(filename)) {
  throw new Error('Invalid filename');
}

// Pattern validation
const filenamePattern = /^[a-zA-Z0-9_-]+\.(txt|log)$/;
if (!filenamePattern.test(filename)) {
  throw new Error('Invalid filename format');
}
```

### Use Libraries Instead of Shell
```javascript
// File operations
const fs = require('fs').promises;
const content = await fs.readFile(path, 'utf-8');

// Path operations
const path = require('path');
const resolved = path.resolve(baseDir, userInput);

// HTTP requests
const axios = require('axios');
await axios.get(url);  // Instead of curl
```

### Escaping (Last Resort)
```javascript
// Use shell-escape library
const shellescape = require('shell-escape');
const safeArgs = shellescape([filename]);
// Still dangerous - prefer execFile
```

## Confidence Scoring

| Factor | Score Impact |
|--------|-------------|
| User input in exec/spawn | +0.4 |
| shell: true or os.system | +0.3 |
| No input validation | +0.2 |
| Command concatenation | +0.2 |
| Whitelisted commands | -0.4 |
| execFile with array | -0.4 |
| Test file | -0.5 |

**Report threshold**: >= 0.7

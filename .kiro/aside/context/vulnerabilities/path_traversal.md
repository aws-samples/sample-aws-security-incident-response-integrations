# Path Traversal (CWE-22)

## Vulnerability Overview
- **CWE**: CWE-22 - Improper Limitation of a Pathname to a Restricted Directory
- **OWASP**: A01:2021 - Broken Access Control
- **Severity**: High
- **CVSS Base**: 7.5

## Detection Patterns

### Node.js

**Dangerous Patterns:**
```javascript
// Direct user input in file paths
fs.readFile(req.params.filename);
fs.readFileSync(userInput);

// Path.join still vulnerable without validation
const filePath = path.join(baseDir, req.query.file);
fs.readFile(filePath);  // Can escape baseDir!

// Express static with user-controlled paths
app.get('/files/:path', (req, res) => {
  res.sendFile(req.params.path);
});

// Archive extraction
const unzip = require('unzipper');
fs.createReadStream(zipFile).pipe(unzip.Extract({ path: userDir }));
```

**Safe Patterns:**
```javascript
// Validate resolved path stays within base
const baseDir = path.resolve('/allowed/directory');
const requestedPath = path.resolve(baseDir, userInput);

if (!requestedPath.startsWith(baseDir + path.sep)) {
  throw new Error('Path traversal attempt detected');
}
fs.readFile(requestedPath);

// Sanitize filename
const safeName = path.basename(userInput);  // Removes directory components
const filePath = path.join(baseDir, safeName);

// Express static with root option
app.use('/files', express.static('/allowed/directory', { dotfiles: 'deny' }));
```

### Python

**Dangerous Patterns:**
```python
# Direct user input
with open(user_filename, 'r') as f:
    content = f.read()

# os.path.join still vulnerable
file_path = os.path.join(base_dir, user_input)
with open(file_path) as f:
    pass

# Flask send_file
@app.route('/download/<filename>')
def download(filename):
    return send_file(filename)  # Dangerous!
```

**Safe Patterns:**
```python
# Validate with realpath
import os

base_dir = os.path.realpath('/allowed/directory')
requested_path = os.path.realpath(os.path.join(base_dir, user_input))

if not requested_path.startswith(base_dir + os.sep):
    raise ValueError('Path traversal attempt')

# Flask safe_join
from werkzeug.utils import safe_join
safe_path = safe_join(base_dir, filename)
if safe_path is None:
    abort(400)

# send_from_directory
return send_from_directory('/allowed/directory', filename)
```

### Java

**Dangerous Patterns:**
```java
// Direct user input
File file = new File(userInput);
FileInputStream fis = new FileInputStream(file);

// Path concatenation
String filePath = baseDir + "/" + fileName;
File file = new File(filePath);
```

**Safe Patterns:**
```java
// Canonical path validation
File baseDir = new File("/allowed/directory").getCanonicalFile();
File requestedFile = new File(baseDir, userInput).getCanonicalFile();

if (!requestedFile.getPath().startsWith(baseDir.getPath() + File.separator)) {
    throw new SecurityException("Path traversal attempt");
}

// Java NIO with normalize
Path basePath = Paths.get("/allowed/directory").toRealPath();
Path requestedPath = basePath.resolve(userInput).normalize().toRealPath();

if (!requestedPath.startsWith(basePath)) {
    throw new SecurityException("Path traversal attempt");
}
```

## Detection Regex

```regex
# Node.js file operations with user input
(readFile|writeFile|createReadStream|unlink|rmdir)\s*\(\s*(req\.|params\.|query\.|user)

# Path.join without validation
path\.join\s*\([^)]*,\s*(req\.|params\.|query\.|user)

# Python open with user input
open\s*\(\s*(?!['"])

# Express sendFile with user input
(sendFile|download)\s*\(\s*(req\.|params)

# Java File constructor with user input
new\s+File\s*\([^)]*\+[^)]*\)
```

## Attack Payloads

Common path traversal sequences:
- `../` - Parent directory
- `..%2f` - URL-encoded
- `..%252f` - Double URL-encoded
- `....//` - Bypass simple filter
- `..\/` - Windows alternative
- `..;/` - Tomcat specific

## False Positive Indicators

- **Static paths**: `fs.readFile('./config.json')`
- **Environment variables**: `fs.readFile(process.env.CONFIG_PATH)`
- **Validated paths**: Path checked against whitelist or validated
- **Basename extraction**: `path.basename(userInput)` removes directory components
- **sendFromDirectory**: Flask's safe method

## Remediation

### Path Validation Pattern
```javascript
function validatePath(baseDir, userInput) {
  // Normalize both paths
  const base = path.resolve(baseDir);
  const requested = path.resolve(base, userInput);

  // Check requested path starts with base
  if (!requested.startsWith(base + path.sep)) {
    throw new Error('Invalid path');
  }

  // Optional: Check for symlinks
  const realPath = fs.realpathSync(requested);
  if (!realPath.startsWith(base + path.sep)) {
    throw new Error('Symlink escape detected');
  }

  return requested;
}
```

### Whitelist Approach
```javascript
// Only allow specific files
const allowedFiles = new Set(['report.pdf', 'summary.txt', 'data.json']);

if (!allowedFiles.has(path.basename(userInput))) {
  throw new Error('File not allowed');
}
```

## Confidence Scoring

| Factor | Score Impact |
|--------|-------------|
| User input in file operation | +0.4 |
| No path validation | +0.3 |
| Path.join without check | +0.2 |
| sendFile/download | +0.2 |
| realpath/canonical check | -0.4 |
| basename extraction | -0.3 |
| Whitelist validation | -0.4 |

**Report threshold**: >= 0.7

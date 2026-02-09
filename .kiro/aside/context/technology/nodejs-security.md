# Node.js Security Context

## Overview
Core Node.js security patterns, vulnerabilities, and best practices applicable across frameworks.

## Process and Environment Security

### Environment Variables
```javascript
// GOOD - using environment variables
const dbPassword = process.env.DB_PASSWORD;
const apiKey = process.env.API_KEY;

// BAD - hardcoded secrets
const dbPassword = 'supersecret123'; // NEVER DO THIS
```

### Secure Configuration
```javascript
// config/secure.js
module.exports = {
  // Load from environment with validation
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT, 10) || 5432,
    password: process.env.DB_PASSWORD,
    ssl: process.env.NODE_ENV === 'production'
  },

  // Validate required secrets exist
  validateConfig() {
    const required = ['DB_PASSWORD', 'JWT_SECRET', 'API_KEY'];
    const missing = required.filter(key => !process.env[key]);
    if (missing.length > 0) {
      throw new Error(`Missing required env vars: ${missing.join(', ')}`);
    }
  }
};
```

## Cryptography

### Password Hashing
```javascript
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

// Using bcrypt (widely supported)
const SALT_ROUNDS = 12;

async function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Using argon2 (recommended for new projects)
async function hashPasswordArgon(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4
  });
}
```

### Encryption/Decryption
```javascript
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const SALT_LENGTH = 64;

function encrypt(text, key) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  return iv.toString('hex') + encrypted + tag.toString('hex');
}

function decrypt(encryptedData, key) {
  const iv = Buffer.from(encryptedData.slice(0, IV_LENGTH * 2), 'hex');
  const tag = Buffer.from(encryptedData.slice(-TAG_LENGTH * 2), 'hex');
  const encrypted = encryptedData.slice(IV_LENGTH * 2, -TAG_LENGTH * 2);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
```

### Secure Random Generation
```javascript
const crypto = require('crypto');

// Generate secure random tokens
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Generate secure random integers
function secureRandomInt(min, max) {
  const range = max - min;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  let randomValue;
  do {
    randomValue = crypto.randomBytes(bytesNeeded).readUIntBE(0, bytesNeeded);
  } while (randomValue >= Math.floor(256 ** bytesNeeded / range) * range);
  return min + (randomValue % range);
}
```

## Command Execution

### Safe Child Process Usage
```javascript
const { spawn, execFile } = require('child_process');

// DANGEROUS - shell injection possible
const { exec } = require('child_process');
exec(`ls ${userInput}`); // NEVER DO THIS

// SAFE - using spawn with array arguments
function safeListDirectory(directory) {
  // Validate directory path first
  const validPath = path.resolve(directory);
  if (!validPath.startsWith('/allowed/path')) {
    throw new Error('Invalid directory');
  }

  return new Promise((resolve, reject) => {
    const ls = spawn('ls', ['-la', validPath], {
      shell: false,
      timeout: 5000
    });

    let output = '';
    ls.stdout.on('data', (data) => { output += data; });
    ls.on('close', (code) => {
      if (code === 0) resolve(output);
      else reject(new Error(`Process exited with code ${code}`));
    });
  });
}
```

## File System Security

### Path Traversal Prevention
```javascript
const path = require('path');
const fs = require('fs').promises;

const ALLOWED_BASE = '/app/uploads';

async function safeReadFile(userPath) {
  // Resolve and normalize the path
  const resolvedPath = path.resolve(ALLOWED_BASE, userPath);

  // Verify it's within allowed directory
  if (!resolvedPath.startsWith(ALLOWED_BASE)) {
    throw new Error('Access denied: Path traversal attempt');
  }

  // Check file exists and is a file (not directory/symlink)
  const stats = await fs.lstat(resolvedPath);
  if (!stats.isFile()) {
    throw new Error('Access denied: Not a regular file');
  }

  return fs.readFile(resolvedPath);
}
```

### Secure File Uploads
```javascript
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const storage = multer.diskStorage({
  destination: '/app/uploads',
  filename: (req, file, cb) => {
    // Generate random filename to prevent overwrites
    const ext = path.extname(file.originalname);
    const allowedExts = ['.jpg', '.png', '.pdf'];

    if (!allowedExts.includes(ext.toLowerCase())) {
      return cb(new Error('Invalid file type'));
    }

    const randomName = crypto.randomBytes(16).toString('hex');
    cb(null, `${randomName}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf'];
    cb(null, allowedMimes.includes(file.mimetype));
  }
});
```

## HTTP Client Security

### Secure HTTP Requests
```javascript
const https = require('https');
const axios = require('axios');

// Configure secure defaults
const secureClient = axios.create({
  timeout: 10000,
  maxRedirects: 5,
  validateStatus: (status) => status < 500,
  httpsAgent: new https.Agent({
    rejectUnauthorized: true, // Verify TLS certificates
    minVersion: 'TLSv1.2'
  })
});

// SSRF prevention
const BLOCKED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
const BLOCKED_RANGES = ['10.', '172.16.', '192.168.', '169.254.'];

async function safeRequest(url) {
  const parsed = new URL(url);

  // Block internal hosts
  if (BLOCKED_HOSTS.includes(parsed.hostname)) {
    throw new Error('Access to internal hosts is not allowed');
  }

  // Block private IP ranges
  if (BLOCKED_RANGES.some(range => parsed.hostname.startsWith(range))) {
    throw new Error('Access to private networks is not allowed');
  }

  // Only allow HTTPS
  if (parsed.protocol !== 'https:') {
    throw new Error('Only HTTPS is allowed');
  }

  return secureClient.get(url);
}
```

## Deserialization Safety

### Safe JSON Parsing
```javascript
// JSON.parse is generally safe but validate the result
function safeJsonParse(jsonString, maxSize = 1000000) {
  if (jsonString.length > maxSize) {
    throw new Error('JSON too large');
  }

  const parsed = JSON.parse(jsonString);

  // Validate expected structure
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Invalid JSON structure');
  }

  return parsed;
}

// DANGEROUS - never use eval for JSON
// eval(`(${userJson})`); // NEVER DO THIS
```

### Avoid Dangerous Deserialization
```javascript
// DANGEROUS - node-serialize can execute code
const serialize = require('node-serialize');
serialize.unserialize(userInput); // NEVER DO THIS

// DANGEROUS - YAML can execute code
const yaml = require('js-yaml');
yaml.load(userInput); // Can be dangerous

// SAFER - use safe loading options
yaml.load(userInput, { schema: yaml.SAFE_SCHEMA });
```

## Dependency Security

### Package.json Best Practices
```json
{
  "scripts": {
    "audit": "npm audit --audit-level=moderate",
    "audit:fix": "npm audit fix",
    "preinstall": "npx npm-force-resolutions"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "resolutions": {
    "vulnerable-package": "^2.0.0"
  }
}
```

### Lockfile Integrity
```bash
# Always commit package-lock.json
# Use npm ci in CI/CD (uses lockfile exactly)
# Regularly update dependencies
npm outdated
npm update
npm audit
```

## Common Vulnerabilities

### Prototype Pollution
```javascript
// VULNERABLE
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// SAFE - block dangerous properties
function safeMerge(target, source) {
  const BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype'];

  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.includes(key)) continue;

    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
      target[key] = safeMerge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

### ReDoS (Regular Expression DoS)
```javascript
// VULNERABLE - exponential backtracking
const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;

// SAFER - use validated regex or libraries
const validator = require('validator');
validator.isEmail(input);

// Or use safe-regex to check patterns
const safeRegex = require('safe-regex');
if (!safeRegex(pattern)) {
  throw new Error('Unsafe regex pattern');
}
```

## Detection Patterns for ASIDE

### High-Risk Patterns
```
# Command injection
exec(userInput)
spawn(command, {shell: true})
child_process.execSync(userInput)

# Unsafe deserialization
serialize.unserialize()
yaml.load() without safe schema

# Prototype pollution
obj[userKey] = userValue
Object.assign(target, userInput)

# Path traversal
fs.readFile(userPath)
require(userModule)

# Hardcoded secrets
const key = 'abc123'
password: 'secret'
```

### Validation Requirements
```yaml
nodejs_application:
  environment_variables: required
  dependency_audit: required
  input_validation: required
  error_handling: required
  logging: required

cryptography:
  algorithm_strength: AES-256, RSA-2048+
  hash_algorithm: bcrypt, argon2
  random_generation: crypto.randomBytes
```

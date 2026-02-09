# Authentication Vulnerabilities (CWE-287)

## Vulnerability Overview
- **CWE**: CWE-287 - Improper Authentication
- **OWASP**: A07:2021 - Identification and Authentication Failures
- **Severity**: High to Critical
- **CVSS Base**: 7.5-9.8

## Detection Patterns

### Missing Authentication

**Dangerous Patterns:**
```javascript
// Sensitive route without auth middleware
app.get('/api/admin/users', getUsers);
app.delete('/api/users/:id', deleteUser);
app.post('/api/settings', updateSettings);

// Auth check after processing
app.post('/api/payment', (req, res) => {
  processPayment(req.body);  // Processed before auth check!
  if (!req.user) return res.status(401).send('Unauthorized');
});
```

**Safe Patterns:**
```javascript
// Auth middleware on protected routes
app.get('/api/admin/users', requireAuth, adminOnly, getUsers);
app.delete('/api/users/:id', requireAuth, deleteUser);

// Auth middleware applied first
app.use('/api/admin', requireAuth, adminOnly);

// Route-level protection
router.use(authMiddleware);
router.get('/protected', handler);
```

### Weak Password Requirements

**Dangerous Patterns:**
```javascript
// Weak password validation
if (password.length >= 4) { ... }
if (password.length >= 6) { ... }
/^.{4,}$/.test(password)

// No complexity requirements
const isValidPassword = (pwd) => pwd.length >= 8;
```

**Safe Patterns:**
```javascript
// Strong password validation
const validatePassword = (password) => {
  if (password.length < 12) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[^A-Za-z0-9]/.test(password)) return false;
  return true;
};

// Using zxcvbn for strength checking
const zxcvbn = require('zxcvbn');
if (zxcvbn(password).score < 3) {
  throw new Error('Password too weak');
}
```

### Insecure Password Storage

**Dangerous Patterns:**
```javascript
// Plain text storage
user.password = req.body.password;
await user.save();

// MD5/SHA1 without salt
const hash = crypto.createHash('md5').update(password).digest('hex');
const hash = crypto.createHash('sha1').update(password).digest('hex');

// Single iteration hashing
const hash = crypto.createHash('sha256').update(password).digest('hex');
```

**Safe Patterns:**
```javascript
// bcrypt
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);
const match = await bcrypt.compare(password, hash);

// argon2
const argon2 = require('argon2');
const hash = await argon2.hash(password);
const match = await argon2.verify(hash, password);

// scrypt
const crypto = require('crypto');
const salt = crypto.randomBytes(16);
const hash = crypto.scryptSync(password, salt, 64);
```

### JWT Vulnerabilities

**Dangerous Patterns:**
```javascript
// jwt.decode without verify
const decoded = jwt.decode(token);  // No signature verification!

// Algorithm none attack
jwt.verify(token, secret, { algorithms: ['none', 'HS256'] });

// Weak secret
jwt.sign(payload, 'secret');
jwt.sign(payload, 'password123');

// No expiration
const token = jwt.sign({ userId }, secret);  // No exp claim
```

**Safe Patterns:**
```javascript
// Always use verify
const decoded = jwt.verify(token, secret, {
  algorithms: ['HS256'],  // Explicit algorithm
  issuer: 'your-app',
  audience: 'your-users'
});

// Strong secret from environment
const secret = process.env.JWT_SECRET; // At least 256 bits

// Include expiration
const token = jwt.sign(
  { userId, exp: Math.floor(Date.now() / 1000) + (60 * 60) },  // 1 hour
  secret
);

// Asymmetric keys for production
const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

### Session Management

**Dangerous Patterns:**
```javascript
// Insecure session configuration
app.use(session({
  secret: 'secret',
  cookie: { secure: false, httpOnly: false }
}));

// Session ID in URL
app.get('/dashboard?sessionId=' + sessionId);

// Predictable session ID
const sessionId = `user_${userId}`;
```

**Safe Patterns:**
```javascript
// Secure session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  name: '__Host-sessionId',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000  // 1 hour
  }
}));

// Regenerate session on auth
req.session.regenerate((err) => {
  if (err) throw err;
  req.session.userId = user.id;
});
```

## Detection Regex

```regex
# Routes without middleware
(app|router)\.(get|post|put|delete)\s*\(\s*['\"][^'\"]*admin[^'\"]*['\"],\s*(?!.*Middleware|.*auth|.*require)

# Weak password length check
password.*\.length\s*>=?\s*[1-9](?![0-9])

# Plain MD5/SHA1 hashing
crypto\.createHash\s*\(\s*['\"]md5|crypto\.createHash\s*\(\s*['\"]sha1

# jwt.decode usage
jwt\.decode\s*\(

# Insecure session cookie
cookie\s*:\s*\{[^}]*secure\s*:\s*false

# Algorithm none in JWT
algorithms\s*:\s*\[[^\]]*none
```

## False Positive Indicators

- **Public routes**: Routes explicitly intended to be public (/login, /register, /health)
- **Test files**: Mock authentication in tests
- **Auth middleware applied at router level**: Not visible on individual routes
- **Password validation for different purpose**: Not login password
- **JWT decode for token inspection**: Followed by proper verify

## Remediation

### Authentication Middleware Pattern
```javascript
const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Apply to all protected routes
app.use('/api', requireAuth);
```

### Rate Limiting for Auth Endpoints
```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,  // 5 attempts
  message: 'Too many login attempts'
});

app.post('/login', loginLimiter, loginHandler);
```

## Confidence Scoring

| Factor | Score Impact |
|--------|-------------|
| Sensitive route without auth | +0.4 |
| jwt.decode without verify | +0.4 |
| Weak password validation | +0.3 |
| Plain text/weak hash storage | +0.4 |
| Auth middleware present | -0.4 |
| Public route pattern | -0.3 |
| Test file | -0.5 |

**Report threshold**: >= 0.7

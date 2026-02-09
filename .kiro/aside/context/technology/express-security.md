# Express.js Security Context

## Overview
Security patterns, vulnerabilities, and best practices for Express.js applications.

## Common Security Middleware

### Helmet
Security headers middleware:
```javascript
const helmet = require('helmet');

// Recommended configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  hsts: { maxAge: 31536000, includeSubDomains: true },
  noSniff: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true
}));
```

### Rate Limiting
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', limiter);
```

### CORS Configuration
```javascript
const cors = require('cors');

const corsOptions = {
  origin: ['https://trusted-domain.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
};

app.use(cors(corsOptions));
```

## Authentication Patterns

### Session Management
```javascript
const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  name: 'sessionId', // Change default name
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // Requires HTTPS
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  }
}));
```

### JWT Verification
```javascript
const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'your-app',
      audience: 'your-app-users'
    });
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};
```

## Input Validation

### Express Validator
```javascript
const { body, validationResult } = require('express-validator');

const validateUser = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .escape(),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  body('name')
    .trim()
    .escape()
    .isLength({ min: 1, max: 100 })
];

app.post('/users', validateUser, (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  // Process valid input
});
```

### Sanitization
```javascript
const sanitizeHtml = require('sanitize-html');

const sanitizeInput = (req, res, next) => {
  if (req.body) {
    for (const key in req.body) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = sanitizeHtml(req.body[key], {
          allowedTags: [],
          allowedAttributes: {}
        });
      }
    }
  }
  next();
};
```

## Common Vulnerabilities

### Prototype Pollution
**Vulnerable Pattern:**
```javascript
// DANGEROUS - prototype pollution
const merge = (target, source) => {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
};
```

**Safe Pattern:**
```javascript
// SAFE - using Object.assign with null prototype
const merge = (target, source) => {
  return Object.assign(
    Object.create(null),
    target,
    JSON.parse(JSON.stringify(source))
  );
};
```

### Path Traversal
**Vulnerable Pattern:**
```javascript
// DANGEROUS - path traversal
app.get('/files/:filename', (req, res) => {
  res.sendFile(req.params.filename); // No validation
});
```

**Safe Pattern:**
```javascript
// SAFE - validated path
const path = require('path');

app.get('/files/:filename', (req, res) => {
  const filename = path.basename(req.params.filename);
  const filepath = path.join(__dirname, 'uploads', filename);

  // Verify path doesn't escape uploads directory
  if (!filepath.startsWith(path.join(__dirname, 'uploads'))) {
    return res.status(400).send('Invalid path');
  }

  res.sendFile(filepath);
});
```

### NoSQL Injection
**Vulnerable Pattern:**
```javascript
// DANGEROUS - NoSQL injection
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password // Could be { $gt: '' }
  });
});
```

**Safe Pattern:**
```javascript
// SAFE - type checking and sanitization
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }

  const user = await User.findOne({ username });
  if (user && await bcrypt.compare(password, user.password)) {
    // Authentication successful
  }
});
```

### SQL Injection (with Sequelize/Knex)
**Vulnerable Pattern:**
```javascript
// DANGEROUS - SQL injection
app.get('/users', async (req, res) => {
  const users = await sequelize.query(
    `SELECT * FROM users WHERE name = '${req.query.name}'`
  );
});
```

**Safe Pattern:**
```javascript
// SAFE - parameterized query
app.get('/users', async (req, res) => {
  const users = await sequelize.query(
    'SELECT * FROM users WHERE name = ?',
    {
      replacements: [req.query.name],
      type: QueryTypes.SELECT
    }
  );
});
```

## Error Handling

### Secure Error Handler
```javascript
// Production error handler - no stack traces
app.use((err, req, res, next) => {
  console.error(err); // Log full error internally

  // Send generic error to client
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'An error occurred'
      : err.message
  });
});
```

### Custom Error Classes
```javascript
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
  }
}

// Usage
if (!user) {
  throw new AppError('User not found', 404);
}
```

## Security Checklist

### Request Handling
- [ ] Input validation on all user inputs
- [ ] Request body size limits
- [ ] Content-Type validation
- [ ] Query parameter sanitization

### Authentication
- [ ] Secure session configuration
- [ ] Password hashing with bcrypt/argon2
- [ ] Account lockout mechanism
- [ ] MFA support for sensitive operations

### Authorization
- [ ] Role-based access control
- [ ] Resource ownership verification
- [ ] API key rotation support

### Headers & Transport
- [ ] HTTPS enforcement
- [ ] Security headers via Helmet
- [ ] Strict CORS policy
- [ ] CSRF protection for forms

### Dependencies
- [ ] Regular npm audit
- [ ] Lockfile committed
- [ ] Minimal dependencies
- [ ] No deprecated packages

## Detection Patterns for ASIDE

### High-Risk Patterns
```
# Direct user input in queries
db.query(`SELECT * FROM ${req.params.table}`)
User.find(req.body)

# Unsafe file operations
fs.readFile(req.params.path)
res.sendFile(userInput)

# Dangerous eval/exec
eval(req.body.code)
new Function(req.body.function)

# Missing authentication middleware
app.get('/admin/*', adminHandler) # No auth check

# Hardcoded secrets
const secret = 'hardcoded-secret'
jwt.sign(payload, 'my-secret-key')
```

### Validation Requirements
```yaml
express_routes:
  authentication_required: true
  input_validation: required
  rate_limiting: recommended
  audit_logging: required

express_middleware:
  security_headers: required
  cors_configuration: required
  body_parser_limits: required
  error_handling: required
```

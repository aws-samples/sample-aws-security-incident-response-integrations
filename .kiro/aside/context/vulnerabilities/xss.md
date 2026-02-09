# Cross-Site Scripting (XSS) (CWE-79)

## Vulnerability Overview
- **CWE**: CWE-79 - Improper Neutralization of Input During Web Page Generation
- **OWASP**: A03:2021 - Injection
- **Severity**: High
- **CVSS Base**: 6.1-8.2

## XSS Types

### Reflected XSS
User input immediately reflected in response without sanitization.

### Stored XSS
Malicious script stored in database, served to other users.

### DOM-based XSS
Client-side JavaScript modifies DOM with untrusted data.

## Detection Patterns

### React/JSX

**Dangerous Patterns:**
```jsx
// dangerouslySetInnerHTML without sanitization
<div dangerouslySetInnerHTML={{ __html: userContent }} />

// Direct HTML injection from props
function Component({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// URL injection in href
<a href={userProvidedUrl}>Link</a>

// javascript: protocol
<a href={`javascript:${code}`}>Click</a>
```

**Safe Patterns:**
```jsx
// Sanitized HTML
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />

// Text content (auto-escaped by React)
<div>{userContent}</div>

// Validated URL
const isValidUrl = (url) => {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch { return false; }
};
<a href={isValidUrl(url) ? url : '#'}>Link</a>
```

### JavaScript (DOM)

**Dangerous Patterns:**
```javascript
// innerHTML with user data
element.innerHTML = userInput;
document.getElementById('content').innerHTML = data.html;

// document.write
document.write(userContent);

// eval-like functions
eval(userInput);
new Function(userInput);
setTimeout(userInput, 0);

// Location manipulation
location.href = userInput;
location.hash = userInput;
```

**Safe Patterns:**
```javascript
// textContent (auto-escaped)
element.textContent = userInput;

// createElement for dynamic content
const div = document.createElement('div');
div.textContent = userInput;
parent.appendChild(div);

// Sanitization library
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

### Server-Side (Express/Node.js)

**Dangerous Patterns:**
```javascript
// Direct response with user input
app.get('/search', (req, res) => {
  res.send(`<p>You searched for: ${req.query.q}</p>`);
});

// Template without escaping
app.get('/user', (req, res) => {
  res.render('user', { name: req.params.name }); // depends on engine config
});
```

**Safe Patterns:**
```javascript
// HTML encoding
import { encode } from 'html-entities';
app.get('/search', (req, res) => {
  res.send(`<p>You searched for: ${encode(req.query.q)}</p>`);
});

// Template engine auto-escaping (EJS, Pug, Handlebars)
// Ensure autoescape is enabled
res.render('user', { name: req.params.name }); // with proper config

// CSP headers
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"]
  }
}));
```

## Detection Regex

```regex
# React dangerouslySetInnerHTML without DOMPurify
dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*(?!DOMPurify|sanitize)

# innerHTML assignment
\.innerHTML\s*=\s*(?![`'"]<)

# document.write
document\.write\s*\(

# eval-like with user data
(eval|new\s+Function|setTimeout|setInterval)\s*\(\s*(?!['"`])

# location.href with user input
location\.(href|hash|pathname)\s*=\s*(?!['"`])
```

## False Positive Indicators

- **Static HTML**: `innerHTML = '<p>Static content</p>'`
- **Sanitized content**: DOMPurify.sanitize() or similar before assignment
- **CSP enabled**: Content Security Policy blocks inline scripts
- **Admin-only content**: Content from trusted admin users
- **Markdown renderers**: Configured with safe defaults

## Remediation

### Content Security Policy
```javascript
// Recommended CSP for XSS prevention
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  }
}));
```

### Output Encoding
```javascript
// Context-specific encoding
const escapeHtml = (str) => str
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

// URL encoding
const escapeUrl = (str) => encodeURIComponent(str);

// JavaScript string encoding
const escapeJs = (str) => JSON.stringify(str);
```

## Confidence Scoring

| Factor | Score Impact |
|--------|-------------|
| User input flows to DOM/HTML | +0.4 |
| No sanitization found | +0.3 |
| innerHTML/dangerouslySetInnerHTML | +0.2 |
| In production code | +0.1 |
| CSP configured | -0.3 |
| DOMPurify/sanitization present | -0.5 |
| Static content only | -0.5 |

**Report threshold**: >= 0.7

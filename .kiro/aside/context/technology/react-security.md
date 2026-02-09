# React Security Context

## Overview
Security patterns, vulnerabilities, and best practices for React applications (both client-side and Next.js/SSR).

## XSS Prevention

### JSX Auto-Escaping
React automatically escapes values in JSX, making it safe by default:
```jsx
// SAFE - auto-escaped
const UserGreeting = ({ name }) => {
  return <div>Hello, {name}</div>; // name is escaped
};

// SAFE - attributes are also escaped
const Link = ({ href, label }) => {
  return <a href={href}>{label}</a>;
};
```

### Dangerous Patterns

#### dangerouslySetInnerHTML
```jsx
// DANGEROUS - bypasses React's escaping
const RawHtml = ({ content }) => {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
};

// SAFER - if you must use it, sanitize first
import DOMPurify from 'dompurify';

const SafeHtml = ({ content }) => {
  const sanitized = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href', 'target']
  });
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
};
```

#### URL Injection
```jsx
// DANGEROUS - javascript: URLs
const UserLink = ({ url }) => {
  return <a href={url}>Click here</a>; // Can execute JS
};

// SAFE - validate URL protocol
const SafeLink = ({ url }) => {
  const safeUrl = url.match(/^https?:\/\//) ? url : '#';
  return <a href={safeUrl}>Click here</a>;
};

// Or use a library
import { sanitizeUrl } from '@braintree/sanitize-url';

const SafeLink = ({ url }) => {
  return <a href={sanitizeUrl(url)}>Click here</a>;
};
```

## Authentication & Authorization

### Protected Routes
```jsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './auth-context';

const ProtectedRoute = ({ children, requiredRole }) => {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return <LoadingSpinner />;
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRole && user.role !== requiredRole) {
    return <Navigate to="/unauthorized" replace />;
  }

  return children;
};

// Usage
<Route
  path="/admin"
  element={
    <ProtectedRoute requiredRole="admin">
      <AdminDashboard />
    </ProtectedRoute>
  }
/>
```

### Token Storage
```jsx
// AVOID - localStorage is vulnerable to XSS
localStorage.setItem('token', token);

// BETTER - httpOnly cookies (set by server)
// Server sets cookie with:
// Set-Cookie: token=xxx; HttpOnly; Secure; SameSite=Strict

// For SPA with API:
// 1. Use httpOnly cookies for refresh tokens
// 2. Use short-lived access tokens in memory

// Token management in memory
const TokenManager = {
  token: null,

  setToken(newToken) {
    this.token = newToken;
  },

  getToken() {
    return this.token;
  },

  clearToken() {
    this.token = null;
  }
};
```

## Form Security

### CSRF Protection
```jsx
// For forms submitted to your backend
const SecureForm = () => {
  const [csrfToken, setCsrfToken] = useState('');

  useEffect(() => {
    // Fetch CSRF token from server
    fetch('/api/csrf-token')
      .then(res => res.json())
      .then(data => setCsrfToken(data.token));
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    await fetch('/api/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify(formData)
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input type="hidden" name="_csrf" value={csrfToken} />
      {/* form fields */}
    </form>
  );
};
```

### Input Validation
```jsx
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';

const schema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[0-9]/, 'Must contain number'),
  name: z.string()
    .min(1, 'Name is required')
    .max(100, 'Name too long')
    .regex(/^[\w\s-]+$/, 'Invalid characters')
});

const SecureForm = () => {
  const { register, handleSubmit, errors } = useForm({
    resolver: zodResolver(schema)
  });

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('email')} />
      {errors.email && <span>{errors.email.message}</span>}
      {/* ... */}
    </form>
  );
};
```

## State Management Security

### Sensitive Data in State
```jsx
// AVOID - sensitive data in Redux/context visible in devtools
const authReducer = (state, action) => ({
  ...state,
  user: action.payload,
  accessToken: action.payload.token // Visible in devtools
});

// BETTER - store minimal info in state
const authReducer = (state, action) => ({
  ...state,
  isAuthenticated: true,
  userId: action.payload.userId,
  role: action.payload.role
  // Token stored in memory/httpOnly cookie, not state
});
```

### Environment Variables
```jsx
// Vite - only VITE_ prefixed vars are exposed
const apiUrl = import.meta.env.VITE_API_URL;

// Create React App - only REACT_APP_ prefixed vars are exposed
const apiUrl = process.env.REACT_APP_API_URL;

// NEVER include secrets in client-side env vars
// These are embedded in the bundle and visible to users
// BAD:
// REACT_APP_API_SECRET=xxx // Exposed in bundle!
```

## Content Security Policy

### CSP Headers
```jsx
// In Next.js next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: `
      default-src 'self';
      script-src 'self' 'unsafe-inline' 'unsafe-eval';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data: https:;
      font-src 'self';
      connect-src 'self' https://api.example.com;
      frame-ancestors 'none';
    `.replace(/\n/g, '')
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY'
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders
      }
    ];
  }
};
```

## Third-Party Dependencies

### Safe Package Usage
```jsx
// Audit dependencies regularly
// npm audit
// yarn audit

// Use exact versions for security-critical packages
{
  "dependencies": {
    "dompurify": "3.0.6",  // Exact version
    "react": "^18.2.0"     // Range okay for well-maintained packages
  }
}

// Verify package integrity
// npm/yarn use lockfiles with integrity hashes
```

### iframe Security
```jsx
// Embedding external content
const SafeEmbed = ({ src }) => {
  return (
    <iframe
      src={src}
      sandbox="allow-scripts allow-same-origin"
      referrerPolicy="no-referrer"
      loading="lazy"
    />
  );
};

// Prevent clickjacking
// Add X-Frame-Options: DENY header
// Or CSP: frame-ancestors 'none'
```

## Server-Side Security (Next.js)

### API Route Protection
```jsx
// pages/api/protected.js
import { getServerSession } from 'next-auth';

export default async function handler(req, res) {
  const session = await getServerSession(req, res);

  if (!session) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Validate CSRF for mutations
  if (req.method !== 'GET') {
    const csrfToken = req.headers['x-csrf-token'];
    if (!validateCsrf(csrfToken, session)) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }

  // Handle request
}
```

### Server-Side Data Fetching
```jsx
// getServerSideProps - data never exposed to client bundle
export async function getServerSideProps(context) {
  // Safe to use server secrets here
  const data = await fetch('https://api.example.com', {
    headers: {
      Authorization: `Bearer ${process.env.API_SECRET}` // Server-only secret
    }
  });

  return {
    props: {
      // Only serializable data, no functions or secrets
      publicData: data.publicFields
    }
  };
}
```

## Common Vulnerabilities

### Open Redirects
```jsx
// VULNERABLE
const Redirect = () => {
  const { returnUrl } = useParams();
  useEffect(() => {
    window.location.href = returnUrl; // Can redirect anywhere
  }, []);
};

// SAFE - validate redirect URL
const Redirect = () => {
  const { returnUrl } = useParams();

  useEffect(() => {
    const url = new URL(returnUrl, window.location.origin);
    if (url.origin === window.location.origin) {
      window.location.href = returnUrl;
    } else {
      window.location.href = '/';
    }
  }, []);
};
```

### Sensitive Data Exposure
```jsx
// AVOID - logging sensitive data
console.log('User data:', user); // May contain PII

// AVOID - error messages with sensitive info
catch (error) {
  setError(error.message); // May expose internal details
}

// BETTER
catch (error) {
  console.error('API Error:', error); // Log internally
  setError('An error occurred. Please try again.'); // Generic message
}
```

## Detection Patterns for ASIDE

### High-Risk Patterns
```
# XSS vectors
dangerouslySetInnerHTML={{ __html: userInput }}
href={userInput} # without validation
eval(userInput)
new Function(userInput)

# Sensitive data exposure
localStorage.setItem('token', ...)
console.log(password)
console.log(user)

# Missing security
fetch() without credentials handling
<form> without CSRF token
```

### Validation Requirements
```yaml
react_components:
  xss_prevention: required
  input_validation: required
  auth_checks: required_for_protected_routes

next_js_api_routes:
  authentication: required
  csrf_protection: required_for_mutations
  input_validation: required
  rate_limiting: recommended
```

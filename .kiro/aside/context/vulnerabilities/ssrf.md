# Server-Side Request Forgery (SSRF) (CWE-918)

## Vulnerability Overview
- **CWE**: CWE-918 - Server-Side Request Forgery
- **OWASP**: A10:2021 - Server-Side Request Forgery
- **Severity**: High
- **CVSS Base**: 7.5-9.8

## Detection Patterns

### Node.js

**Dangerous Patterns:**
```javascript
// User-controlled URL in HTTP requests
const axios = require('axios');
app.get('/fetch', async (req, res) => {
  const response = await axios.get(req.query.url);
  res.json(response.data);
});

// fetch with user URL
const data = await fetch(userUrl);

// Request library
const request = require('request');
request(userProvidedUrl, (err, resp, body) => { ... });

// URL in image/file processing
const sharp = require('sharp');
sharp(imageUrl).resize(200).toBuffer();

// PDF generation with user URLs
const puppeteer = require('puppeteer');
await page.goto(userUrl);
```

**Safe Patterns:**
```javascript
// URL validation with allowlist
const allowedHosts = ['api.trusted.com', 'cdn.trusted.com'];
const parsedUrl = new URL(userUrl);

if (!allowedHosts.includes(parsedUrl.hostname)) {
  throw new Error('Host not allowed');
}

// Block internal addresses
function isInternalUrl(url) {
  const parsed = new URL(url);
  const ip = parsed.hostname;

  // Block localhost
  if (['localhost', '127.0.0.1', '::1'].includes(ip)) return true;

  // Block private ranges
  if (/^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\./.test(ip)) return true;

  // Block metadata endpoints
  if (ip === '169.254.169.254') return true;

  return false;
}

// Protocol validation
if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
  throw new Error('Invalid protocol');
}
```

### Python

**Dangerous Patterns:**
```python
# requests with user URL
import requests
response = requests.get(user_url)

# urllib
urllib.request.urlopen(user_url)

# aiohttp
async with aiohttp.ClientSession() as session:
    async with session.get(user_url) as response:
        pass

# Image processing
from PIL import Image
img = Image.open(user_url)
```

**Safe Patterns:**
```python
# URL validation
from urllib.parse import urlparse
import ipaddress

def validate_url(url: str) -> bool:
    parsed = urlparse(url)

    # Check protocol
    if parsed.scheme not in ['http', 'https']:
        return False

    # Check against allowlist
    allowed_hosts = ['api.trusted.com']
    if parsed.hostname not in allowed_hosts:
        return False

    # Check for internal IPs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        pass  # hostname, not IP

    return True
```

### Java

**Dangerous Patterns:**
```java
// URL connection with user input
URL url = new URL(userInput);
URLConnection conn = url.openConnection();

// HttpClient
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create(userUrl))
    .build();

// RestTemplate
RestTemplate restTemplate = new RestTemplate();
restTemplate.getForObject(userUrl, String.class);
```

**Safe Patterns:**
```java
// URL validation
public boolean isValidUrl(String urlString) {
    try {
        URL url = new URL(urlString);

        // Check protocol
        if (!Arrays.asList("http", "https").contains(url.getProtocol())) {
            return false;
        }

        // Check against allowlist
        if (!allowedHosts.contains(url.getHost())) {
            return false;
        }

        // Check for private IPs
        InetAddress address = InetAddress.getByName(url.getHost());
        if (address.isLoopbackAddress() || address.isSiteLocalAddress()) {
            return false;
        }

        return true;
    } catch (Exception e) {
        return false;
    }
}
```

## Detection Regex

```regex
# Node.js HTTP libraries with user input
(axios|fetch|request|got|superagent)\.(get|post|put|delete|request)\s*\(\s*(req\.|params\.|query\.|user)

# Python requests with user input
requests\.(get|post|put|delete)\s*\(\s*(?!['"])

# URL constructor with user input
new\s+URL\s*\(\s*(req\.|params\.|query\.|user)

# URLConnection/HttpClient with user input
(openConnection|newBuilder)\s*\([^)]*\+
```

## Common Attack Targets

### Cloud Metadata Services
- **AWS**: `http://169.254.169.254/latest/meta-data/`
- **GCP**: `http://169.254.169.254/computeMetadata/v1/`
- **Azure**: `http://169.254.169.254/metadata/instance`
- **DigitalOcean**: `http://169.254.169.254/metadata/v1/`

### Internal Services
- `http://localhost:6379/` - Redis
- `http://localhost:9200/` - Elasticsearch
- `http://localhost:27017/` - MongoDB
- `http://localhost:5432/` - PostgreSQL

### Protocol Attacks
- `file:///etc/passwd`
- `gopher://internal:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a`
- `dict://localhost:11211/stats`

## False Positive Indicators

- **Hardcoded URLs**: `axios.get('https://api.example.com/data')`
- **Environment variables**: `axios.get(process.env.API_URL)`
- **URL from database with trust boundary**: Internal service URLs
- **Webhook callbacks**: User-configured webhooks (still risky but different threat)

## Remediation

### URL Allowlist Pattern
```javascript
const ALLOWED_HOSTS = new Set([
  'api.trusted.com',
  'cdn.trusted.com'
]);

function validateExternalUrl(urlString) {
  const url = new URL(urlString);

  // Protocol check
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Invalid protocol');
  }

  // Host allowlist
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    throw new Error('Host not allowed');
  }

  // Block internal IPs (defense in depth)
  const blocked = ['localhost', '127.0.0.1', '::1', '169.254.169.254'];
  if (blocked.includes(url.hostname)) {
    throw new Error('Internal address blocked');
  }

  return url.toString();
}
```

### DNS Rebinding Protection
```javascript
// Resolve hostname and validate IP before request
const dns = require('dns').promises;

async function safeRequest(urlString) {
  const url = new URL(urlString);
  const addresses = await dns.resolve4(url.hostname);

  for (const ip of addresses) {
    if (isPrivateIP(ip)) {
      throw new Error('Private IP resolved - possible DNS rebinding');
    }
  }

  return axios.get(urlString);
}
```

## Confidence Scoring

| Factor | Score Impact |
|--------|-------------|
| User input in URL | +0.4 |
| No URL validation | +0.3 |
| HTTP library identified | +0.2 |
| No protocol check | +0.1 |
| Allowlist validation | -0.4 |
| Internal IP check | -0.3 |
| Hardcoded URL | -0.5 |

**Report threshold**: >= 0.7

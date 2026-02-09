# Python Security Context

## Overview
Security patterns, vulnerabilities, and best practices for Python applications including Django, Flask, and FastAPI.

## Input Validation

### Type Validation with Pydantic
```python
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional
import re

class UserInput(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=100)
    age: int = Field(..., ge=0, le=150)
    password: str = Field(..., min_length=8)

    @validator('name')
    def validate_name(cls, v):
        if not re.match(r'^[\w\s-]+$', v):
            raise ValueError('Name contains invalid characters')
        return v.strip()

    @validator('password')
    def validate_password(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain uppercase')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain number')
        return v

# Usage
try:
    user = UserInput(**request_data)
except ValidationError as e:
    return {"errors": e.errors()}
```

### SQL Injection Prevention
```python
# DANGEROUS - SQL injection
def get_user_unsafe(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

# SAFE - parameterized queries
def get_user_safe(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))

# SQLAlchemy ORM (safe by default)
user = session.query(User).filter(User.id == user_id).first()

# SQLAlchemy with raw SQL
result = session.execute(
    text("SELECT * FROM users WHERE id = :id"),
    {"id": user_id}
)

# Django ORM (safe by default)
user = User.objects.get(id=user_id)
```

## Command Injection Prevention

### Subprocess Safety
```python
import subprocess
import shlex

# DANGEROUS - shell injection
def run_command_unsafe(user_input):
    subprocess.run(f"ls {user_input}", shell=True)  # NEVER DO THIS

# SAFE - using list arguments
def run_command_safe(directory):
    # Validate input first
    if not os.path.isdir(directory):
        raise ValueError("Invalid directory")

    result = subprocess.run(
        ['ls', '-la', directory],
        shell=False,
        capture_output=True,
        text=True,
        timeout=30
    )
    return result.stdout

# SAFE - using shlex for argument parsing (if needed)
def run_with_args(command_args):
    # Only if you must parse a command string
    args = shlex.split(command_args)
    # Validate each argument
    allowed_commands = {'ls', 'cat', 'grep'}
    if args[0] not in allowed_commands:
        raise ValueError("Command not allowed")

    subprocess.run(args, shell=False)
```

## Path Traversal Prevention

### File Operations
```python
import os
from pathlib import Path

UPLOAD_DIR = Path('/app/uploads').resolve()

def safe_file_read(filename):
    # Resolve the full path
    requested_path = (UPLOAD_DIR / filename).resolve()

    # Verify it's within allowed directory
    if not str(requested_path).startswith(str(UPLOAD_DIR)):
        raise ValueError("Access denied: Path traversal attempt")

    # Verify it exists and is a file
    if not requested_path.is_file():
        raise ValueError("File not found")

    return requested_path.read_text()

def safe_file_write(filename, content):
    # Sanitize filename
    safe_name = os.path.basename(filename)
    if not safe_name or safe_name.startswith('.'):
        raise ValueError("Invalid filename")

    file_path = UPLOAD_DIR / safe_name
    file_path.write_text(content)
```

## Authentication

### Password Hashing
```python
from passlib.context import CryptContext
import bcrypt
import argon2

# Using passlib (recommended)
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

# Using argon2 directly
ph = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4
)

def hash_password_argon(password: str) -> str:
    return ph.hash(password)

def verify_password_argon(password: str, hashed: str) -> bool:
    try:
        ph.verify(hashed, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
```

### JWT Handling
```python
import jwt
from datetime import datetime, timedelta

SECRET_KEY = os.environ['JWT_SECRET']
ALGORITHM = "HS256"

def create_token(user_id: int, expires_delta: timedelta = timedelta(hours=1)):
    payload = {
        "sub": str(user_id),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + expires_delta,
        "iss": "your-app",
        "aud": "your-app-users"
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer="your-app",
            audience="your-app-users"
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
```

## Deserialization Safety

### Pickle Warning
```python
import pickle
import json

# DANGEROUS - pickle can execute arbitrary code
def load_data_unsafe(data):
    return pickle.loads(data)  # NEVER with untrusted data

# SAFE - use JSON for untrusted data
def load_data_safe(data):
    return json.loads(data)

# If you must use pickle, use restricted unpickler
import io

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow specific safe classes
        SAFE_CLASSES = {
            ('collections', 'OrderedDict'),
            ('datetime', 'datetime'),
        }
        if (module, name) not in SAFE_CLASSES:
            raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")
        return super().find_class(module, name)

def restricted_loads(data):
    return RestrictedUnpickler(io.BytesIO(data)).load()
```

### YAML Safety
```python
import yaml

# DANGEROUS - can execute arbitrary code
data = yaml.load(user_input)  # NEVER DO THIS

# SAFE - use safe_load
data = yaml.safe_load(user_input)

# Or specify SafeLoader explicitly
data = yaml.load(user_input, Loader=yaml.SafeLoader)
```

## Framework-Specific Security

### Django Security Settings
```python
# settings.py

# Security settings
DEBUG = False  # Never True in production
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# HTTPS settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Security headers
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# CSRF settings
CSRF_TRUSTED_ORIGINS = ['https://example.com']

# Session settings
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

### Flask Security
```python
from flask import Flask, request
from flask_talisman import Talisman
from flask_limiter import Limiter

app = Flask(__name__)

# Security headers with Talisman
Talisman(app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'"
    }
)

# Rate limiting
limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Rate-limited login endpoint
    pass

# Session configuration
app.config.update(
    SECRET_KEY=os.environ['FLASK_SECRET'],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)
```

### FastAPI Security
```python
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from slowapi import Limiter
from slowapi.util import get_remote_address

app = FastAPI()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# OAuth2 authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    user = await get_user(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    return user

# API key authentication
api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Security(api_key_header)):
    if not is_valid_api_key(api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key

@app.post("/protected")
@limiter.limit("10/minute")
async def protected_route(
    request: Request,
    user: User = Depends(get_current_user)
):
    return {"user": user.email}
```

## Cryptography

### Secure Random
```python
import secrets
import os

# Generate secure random token
token = secrets.token_hex(32)  # 64 character hex string
token_url = secrets.token_urlsafe(32)  # URL-safe token

# Secure random integer
random_int = secrets.randbelow(100)  # 0-99

# Secure random bytes
random_bytes = os.urandom(32)
```

### Encryption
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Symmetric encryption with Fernet
key = Fernet.generate_key()  # Store securely
cipher = Fernet(key)

encrypted = cipher.encrypt(b"secret data")
decrypted = cipher.decrypt(encrypted)

# AES-GCM for more control
def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_aes_gcm(data: bytes, key: bytes) -> bytes:
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
```

## Detection Patterns for ASIDE

### High-Risk Patterns
```python
# Command injection
os.system(user_input)
subprocess.run(user_input, shell=True)
eval(user_input)
exec(user_input)

# SQL injection
f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# Deserialization
pickle.loads(user_data)
yaml.load(user_data)  # Without Loader parameter

# Path traversal
open(user_path)
os.path.join(base, user_input)  # Without validation

# Hardcoded secrets
SECRET_KEY = "hardcoded"
password = "admin123"
```

### Validation Requirements
```yaml
python_application:
  input_validation: required
  sql_injection_prevention: required
  authentication: required
  encryption: required_for_sensitive_data

django:
  debug_mode: must_be_false_in_production
  security_middleware: required
  csrf_protection: required
  secure_cookies: required

flask:
  secret_key: must_be_from_environment
  session_security: required
  input_validation: required

fastapi:
  pydantic_validation: required
  authentication: required_for_protected_routes
  rate_limiting: recommended
```

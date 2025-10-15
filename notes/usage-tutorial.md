# BigScoots v2 API Gateway - Usage Guide

> **Complete guide for Frontend and Backend teams on how to integrate with the BigScoots v2 API Gateway**

---

## Table of Contents
1. [Quick Start](#quick-start)
2. [Gateway Overview](#gateway-overview)
3. [Authentication Methods](#authentication-methods)
4. [JWT Authentication (Users)](#jwt-authentication-users)
5. [HMAC Authentication (Enterprise/API Clients)](#hmac-authentication-enterpriseapi-clients)
6. [Public Endpoints](#public-endpoints)
7. [Request/Response Format](#requestresponse-format)
8. [Error Handling](#error-handling)
9. [Rate Limiting](#rate-limiting)
10. [Code Examples](#code-examples)
11. [Testing Guide](#testing-guide)
12. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Gateway URL
```
Production: https://v2-cloudflare.bigscoots.dev
```

### Basic Request Flow
```
1. Client sends request to Gateway
2. Gateway authenticates request (JWT or HMAC)
3. Gateway routes to appropriate backend service
4. Backend processes request
5. Response returned through Gateway
```

### Supported Authentication
- ✅ **JWT (Auth0)** - For end users
- ✅ **HMAC Signed Requests** - For enterprise/API clients
- ✅ **Public Routes** - No authentication required

---

## Gateway Overview

### What is the API Gateway?

The BigScoots v2 API Gateway is a **Cloudflare Worker** that acts as a single entry point for all API requests. It handles:

- **Authentication** - Validates JWT tokens and HMAC signatures
- **Authorization** - Checks scopes and permissions (To do)
- **Routing** - Forwards requests to appropriate backend services
- **Security** - Replay attack prevention, rate limiting
- **Identity Injection** - Adds standardized headers for backend services

### Architecture Diagram

```
┌─────────────┐
│   Client    │
│ (Web/Mobile)│
└──────┬──────┘
       │ HTTPS Request
       ↓
┌──────────────────────────────┐
│  API Gateway (Cloudflare)    │
│  v2-cloudflare.bigscoots.dev │
│                              │
│  1. Authenticate (JWT/HMAC)  │
│  2. Validate Permissions     │
│  3. Inject Identity Headers  │
│  4. Route to Backend         │
└──────────────┬───────────────┘
               │
       ┌───────┴────────┐
       ↓                ↓
┌─────────────┐  ┌──────────────┐
│User Service │  │ Site Service │
│             │  │              │
│ v2-user     │  │  v2-sites    │
│.bigscoots   │  │  .bigscoots  │
│.dev         │  │  .dev        │
└─────────────┘  └──────────────┘
```

### Backend Service Mapping

| Path Prefix | Backend Service | Description |
|-------------|----------------|-------------|
| `/user-mgmt/*` | `https://v2-user.bigscoots.dev` | User management, authentication |
| `/site-mgmt/*` | `https://v2-sites.bigscoots.dev` | Site management (primary) |
| `/sites/*` | `https://v2-sites.bigscoots.dev` | Site operations (legacy support) |
| `/authentication/*` | `https://v2-sites.bigscoots.dev` | Authentication operations |
| `/dashboard/*` | `https://v2-sites.bigscoots.dev` | Dashboard data |
| `/management/*` | `https://v2-sites.bigscoots.dev` | Management operations |
| `/service/*` | `https://v2-sites.bigscoots.dev` | Service operations (legacy support) |
| `/plans/*` | `https://v2-sites.bigscoots.dev` | Plan management |

---

## Authentication Methods

### How the Gateway Detects Auth Method

The Gateway automatically detects which authentication method to use based on request headers:

```javascript
// JWT Authentication
if (request has "Authorization: Bearer <token>") {
  → Use JWT validation
}

// HMAC Authentication  
else if (request has "X-Key-Id" header) {
  → Use HMAC validation
}

// No Authentication
else {
  → Check if public route, otherwise reject
}
```

### Authentication Decision Tree

```
Incoming Request
    │
    ├─ Has "Authorization: Bearer ..." header?
    │   ├─ YES → JWT Authentication
    │   │         ├─ Validate token signature
    │   │         ├─ Check expiration
    │   │         └─ Extract user claims
    │   │
    │   └─ NO → Check for HMAC headers
    │       │
    │       ├─ Has "X-Key-Id" header?
    │       │   ├─ YES → HMAC Authentication
    │       │   │         ├─ Validate signature
    │       │   │         ├─ Check timestamp
    │       │   │         ├─ Verify nonce
    │       │   │         └─ Extract API key metadata
    │       │   │
    │       │   └─ NO → Check if public route
    │       │       │
    │       │       ├─ Public route → Allow
    │       │       └─ Protected route → 401 Unauthorized
```

---

## JWT Authentication (Users)

### Overview

JWT authentication is for **end users** authenticating through Auth0. The Gateway validates JWT tokens at the edge before routing to backend services.

### Auth0 Configuration

```
Issuer:   http://auth.scoots-test.com/
Audience: http://auth.scoots-test.com/api/v2/
JWKS URL: http://auth.scoots-test.com/.well-known/jwks.json
```

### JWT Request Headers

**Required Headers:**
```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...
Content-Type: application/json
```

**Optional Headers:**
```
Accept: application/json
```

### What the Gateway Does

1. **Extracts JWT** from `Authorization: Bearer <token>` header
2. **Validates Signature** using Auth0 public keys (JWKS)
3. **Checks Claims:**
   - `iss` (issuer) must match Auth0 issuer
   - `aud` (audience) must match configured audience
   - `exp` (expiration) must be in future
4. **Extracts User Info** from custom claims
5. **Injects Identity Headers** for backend:
   ```
   X-Auth-Type: jwt
   X-User-Id: <user_id from sub claim>
   X-Client-Id: <user_id>
   X-Org-Id: null
   X-Scopes: ["scope1", "scope2"] (Todo)
   X-Email: user@example.com
   X-Role: user
   ```
6. **Routes to Backend** with original JWT token preserved

### JWT Token Structure

```json
{
  "https://v2-bigscoots.com/role": [
    "customer"
  ],
  "https://v2-bigscoots.com/hostbill": {
    "customerId": 103,
    "name": "mahnoor"
  },
  "https://v2-bigscoots.com/email": "mahnoor.feroz09@gmail.com",
  "https://v2-bigscoots.com/email_verified": true,
  "iss": "https://dev-luzn47z5slx3svx7.us.auth0.com/",
  "sub": "auth0|68ecfd6de83e92ee1be5c4bb",
  "aud": [
    "https://dev-luzn47z5slx3svx7.us.auth0.com/api/v2/",
    "https://dev-luzn47z5slx3svx7.us.auth0.com/userinfo"
  ],
  "iat": 1760512535,
  "exp": 1760598935,
  "scope": "openid email profile read:current_user update:current_user_metadata delete:current_user_metadata create:current_user_metadata create:current_user_device_credentials delete:current_user_device_credentials update:current_user_identities offline_access",
  "gty": "password",
  "azp": "Cwtk6oOvqiyKzDEp3m2ETGgVEUnW0fdt"
}
```

### JWT Error Responses

| Error Code | Reason | Response |
|------------|--------|----------|
| **401** | Token expired | `{"statusCode":401,"message":"Token has expired","data":"Unauthorized"}` |
| **401** | Invalid signature | `{"statusCode":401,"message":"Invalid JWT signature","data":"Unauthorized"}` |
| **401** | Wrong issuer | `{"statusCode":401,"message":"Invalid issuer","data":"Unauthorized"}` |
| **401** | Wrong audience | `{"statusCode":401,"message":"Invalid audience","data":"Unauthorized"}` |
| **401** | Missing token | `{"statusCode":401,"message":"Bearer token is required","data":"Unauthorized"}` |

---

## HMAC Authentication (Enterprise/API Clients)

### Overview

HMAC authentication is for **enterprise clients** and **server-to-server** integrations. Requests are signed with a shared secret using HMAC-SHA256.

### Getting API Credentials

Enterprise Clients will receive:
- **Key ID** (public identifier) - Example: `live_org_test123`
- **Secret** (private key) - Example: `base64randomsecret`

**⚠️ Keep your secret safe! Never commit it to version control.**

### HMAC Signature Process

#### Step 1: Build Canonical String

```
METHOD
PATH
QUERY (sorted)
SIGNED-HEADERS (lowercase, sorted)
TIMESTAMP
NONCE
BODY-SHA256
```

#### Step 2: Sign Canonical String

```javascript
// Pseudocode
canonical_string = build_canonical_string(request)
signature = HMAC-SHA256(secret, canonical_string)
base64_signature = Base64(signature)
```

#### Step 3: Send Request with HMAC Headers

```javascript
// Required headers for HMAC request
{
  'X-Key-Id': 'live_org_test123',
  'X-Timestamp': '1728200000',
  'X-Nonce': 'uuid-v4-here',
  'X-Signature': 'base64-signature-here',
  'X-Content-SHA256': 'sha256-body-hash-or-UNSIGNED-PAYLOAD',
  'Host': 'v2-cloudflare.bigscoots.dev',
  'Content-Type': 'application/json'
}
```

### HMAC Request Headers

| Header | Description | Example |
|--------|-------------|---------|
| **X-Key-Id** | Your API key ID | `live_org_test123` |
| **X-Timestamp** | Unix timestamp (seconds) | `1728200000` |
| **X-Nonce** | Unique UUID v4 per request | `7d6b6a1c-6f55-4e8a-bf4a-58c5a70f1d2e` |
| **X-Signature** | Base64 HMAC-SHA256 signature | `AbCdEf...==` |
| **X-Content-SHA256** | SHA256 of body (hex) or `UNSIGNED-PAYLOAD` | `3f786850e387550...` |
| **Host** | Gateway hostname | `v2-cloudflare.bigscoots.dev` |
| **Content-Type** | Request content type | `application/json` |

### Canonical String Format

**Example for POST request:**
```
POST
/sites/service-123
domain=example.com&plan=basic
content-type:application/json
host:v2-cloudflare.bigscoots.dev
1728200000
7d6b6a1c-6f55-4e8a-bf4a-58c5a70f1d2e
3f786850e387550fdab836ed7e6dc881de23001b
```

**Example for GET request (no body):**
```
GET
/sites/service-123/site-456
limit=10&page=2
content-type:
host:v2-cloudflare.bigscoots.dev
1728200000
a1b2c3d4-5e6f-7g8h-9i0j-k1l2m3n4o5p6
UNSIGNED-PAYLOAD
```

### Signed Headers

The Gateway expects these headers to be included in the signature:
- `host` (required)
- `content-type` (required, even if empty for GET requests)

**Important:** Headers must be:
- **Lowercase** in the canonical string
- **Sorted alphabetically**
- Included even if empty (use empty string)

### Body Hash Computation

**For requests WITH body (POST, PUT, PATCH):**
```javascript
// Compute SHA256 hash of raw body bytes
const bodyHash = SHA256(requestBody).toString('hex');
// Example: "3f786850e387550fdab836ed7e6dc881de23001b"
```

**For requests WITHOUT body (GET, DELETE):**
```javascript
// Use literal string "UNSIGNED-PAYLOAD"
const bodyHash = "UNSIGNED-PAYLOAD";
```

### Timestamp Validation

- **Accepted Window:** ±300 seconds (±5 minutes)
- **Recommended:** Sync your clock with NTP
- **Rejection:** Requests outside window get `401` error

### Nonce Requirements

- **Format:** UUID v4 (lowercase recommended)
- **Uniqueness:** Must be unique per request
- **Replay Protection:** Same nonce cannot be reused within 5 minutes
- **Generation:** Use `crypto.randomUUID()` or equivalent

### What the Gateway Does

1. **Validates Headers** - All required HMAC headers present
2. **Checks Timestamp** - Within ±300 seconds window
3. **Verifies Nonce** - Not seen before (replay protection via Durable Objects)
4. **Validates Body Hash** - Recomputes and compares
5. **Looks Up Secret** - Fetches from Workers KV by Key ID
6. **Rebuilds Canonical String** - From actual request received
7. **Verifies Signature** - Recomputes HMAC and compares (constant-time)
8. **Injects Identity Headers** for backend:
   ```
   X-Auth-Type: hmac
   X-Client-Id: live_org_test123
   X-Org-Id: org_abc123
   X-Scopes: ["sites:read", "sites:write"]
   ```
9. **Routes to Backend** (removes HMAC headers, keeps identity headers)

### HMAC Error Responses

| Error Code | Reason | Response |
|------------|--------|----------|
| **401** | Missing headers | `{"statusCode":401,"message":"Missing required HMAC headers","data":"Unauthorized"}` |
| **401** | Timestamp outside window | `{"statusCode":401,"message":"Request timestamp is outside acceptable window","data":"Unauthorized"}` |
| **401** | Replay attack (nonce reused) | `{"statusCode":401,"message":"Nonce has already been used","data":"Unauthorized"}` |
| **401** | Body hash mismatch | `{"statusCode":401,"message":"Body hash mismatch","data":"Unauthorized"}` |
| **401** | Invalid signature | `{"statusCode":401,"message":"HMAC signature verification failed","data":"Unauthorized"}` |
| **401** | API key not found | `{"statusCode":401,"message":"API key not found","data":"Unauthorized"}` |

---

## Public Endpoints

### No Authentication Required

These endpoints can be accessed without any authentication:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/user-mgmt/auth/login` | POST | User login |
| `/user-mgmt/auth/refresh` | GET | Refresh access token |
| `/user-mgmt/auth/verify-oob-code` | GET | Verify OOB code |
| `/user-mgmt/auth/social-login` | GET | Social login |


---

## Request/Response Format

### Request Structure

**Standard Request Headers:**
```
Host: v2-cloudflare.bigscoots.dev
Content-Type: application/json
Accept: application/json

// Plus authentication headers (JWT or HMAC)
```

**Standard Request Body (if applicable):**
```json
{
  "field1": "value1",
  "field2": "value2"
}
```

### Response Structure

**Success Response (2xx):**
```json
{
  "data": {
    // Response payload from backend service
  },
  "status": 200
}
```

**Error Response (4xx, 5xx):**
```json
{
  "statusCode": 401,
  "message": "Human-readable error message",
  "data": "Unauthorized"
}
```

### Identity Headers Injected by Gateway

**Backend services receive these headers:**

| Header | Description | JWT Example | HMAC Example |
|--------|-------------|-------------|--------------|
| **X-Auth-Type** | Authentication method used | `jwt` | `hmac` |
| **X-User-Id** | User identifier (JWT only) | `auth0\|user123` | - |
| **X-Client-Id** | Client identifier | `auth0\|user123` | `live_org_test123` |
| **X-Org-Id** | Organization ID | `null` | `org_abc123` |
| **X-Scopes** | JSON array of scopes | `["openid","profile"]` | `["sites:read","sites:write"]` |
| **X-Email** | User email (JWT only) | `user@example.com` | - |
| **X-Role** | User role (JWT only) | `admin` | - |

**⚠️ Backend Security:** Backends must ONLY trust headers injected by the Gateway, not raw client headers.

---

## Error Handling

### Error Response Format

All errors follow this structure:

```json
{
  "statusCode": 401,
  "message": "Detailed error message",
  "data": "Unauthorized"
}
```

### Common Error Codes

| Status | Error Code | Description | Resolution |
|--------|-----------|-------------|------------|
| **400** | `bad_request` | Malformed request | Check request format |
| **401** | `unauthorized` | No authentication provided | Add JWT or HMAC headers |
| **401** | `invalid_token` | JWT validation failed | Check token validity |
| **401** | `token_expired` | JWT token expired | Refresh token |
| **401** | `invalid_signature` | HMAC signature invalid | Check signature generation |
| **401** | `invalid_request` | HMAC validation failed | Check timestamp/nonce/body hash |
| **401** | `invalid_key` | API key not found | Verify Key ID |
| **403** | `forbidden` | Insufficient permissions | Check scopes |
| **404** | `not_found` | Route not found | Check endpoint URL |
| **429** | `too_many_requests` | Rate limit exceeded | Implement backoff |
| **500** | `internal_server_error` | Server error | Contact support |

## Rate Limiting (To do)

### Current Rate Limits

**JWT (End Users):**
- Enforced at IP level via Cloudflare WAF
- Standard limits apply to all JWT users

**HMAC (API Clients):**
- Per-API-key limits (configurable)
- Multiple time windows enforced

### Rate Limit Headers (Future)

When rate limiting is fully implemented, responses will include:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1728474120
```

### Handling Rate Limits

```javascript
async function makeRequestWithBackoff(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    const response = await fetch(url, options);
    
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After') || 60;
      console.log(`Rate limited. Retrying after ${retryAfter}s`);
      await sleep(retryAfter * 1000);
      continue;
    }
    
    return response;
  }
  
  throw new Error('Max retries exceeded');
}
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. **401 Unauthorized (JWT)**

**Symptom:** Getting `401` with JWT authentication

**Possible Causes:**
- Token expired
- Wrong issuer/audience
- Invalid signature
- Token not yet valid (nbf claim)

**Solutions:**
```javascript
// Check token expiration
const decoded = jwt_decode(token);
console.log('Token expires:', new Date(decoded.exp * 1000));

// Refresh token
const newToken = await auth0.getTokenSilently({ cacheMode: 'off' });

// Verify issuer/audience match
console.log('Issuer:', decoded.iss);
console.log('Audience:', decoded.aud);
```

#### 2. **401 Signature Verification Failed (HMAC)**

**Symptom:** Getting `invalid_signature` error

**Possible Causes:**
- Canonical string mismatch
- Headers not lowercase/sorted
- Body hash incorrect
- Wrong secret

**Solutions:**
```javascript
// Debug canonical string
console.log('Canonical String:');
console.log(canonicalString);

// Verify body hash
const computedHash = crypto.createHash('sha256').update(body).digest('hex');
console.log('Computed:', computedHash);
console.log('Sent:', sentHash);

// Check header order (must be sorted)
const headers = ['content-type', 'host'].sort();

// Verify empty headers included
// content-type: (empty string, not omitted)
```

#### 3. **401 Timestamp Outside Window**

**Symptom:** Getting timestamp error

**Possible Causes:**
- Clock skew between client and server
- Timestamp in milliseconds instead of seconds

**Solutions:**
```javascript
// Use seconds, not milliseconds
const timestamp = Math.floor(Date.now() / 1000); // ✅ Correct
const timestamp = Date.now(); // ❌ Wrong (milliseconds)

// Sync with NTP
// Linux: sudo ntpdate pool.ntp.org
// macOS: sudo sntp -sS pool.ntp.org
```

#### 4. **401 Replay Attack Detected**

**Symptom:** Getting nonce reused error

**Possible Causes:**
- Reusing same nonce
- Retry logic using same nonce

**Solutions:**
```javascript
// Generate NEW nonce for each request
const nonce = crypto.randomUUID(); // ✅ Fresh nonce

// Don't reuse nonce from previous request
const nonce = cachedNonce; // ❌ Wrong
```

#### 5. **404 Not Found**

**Symptom:** Getting `404` on valid endpoint

**Possible Causes:**
- Wrong path prefix
- Typo in endpoint URL
- Backend endpoint doesn't exist

**Solutions:**
```javascript
// Check path prefix mapping
'/user-mgmt/' → User Service ✅
'/users/'     → Not mapped ❌

// Verify full URL
const url = 'https://v2-cloudflare.bigscoots.dev/user-mgmt/profile'; // ✅
const url = 'https://v2-cloudflare.bigscoots.dev/profile'; // ❌
```

#### 6. **Body Hash Mismatch**

**Symptom:** Getting body hash error

**Possible Causes:**
- Hashing modified body
- String encoding issues
- Wrong hash algorithm

**Solutions:**
```javascript
// Hash EXACT body bytes sent
const body = JSON.stringify(data);
const hash = crypto.createHash('sha256').update(body).digest('hex');

// For GET/DELETE, use UNSIGNED-PAYLOAD
const hash = 'UNSIGNED-PAYLOAD'; // ✅ For bodyless requests
const hash = ''; // ❌ Wrong
```

## Quick Reference

### Gateway URL
```
https://v2-cloudflare.bigscoots.dev
```

### JWT Headers
```
Authorization: Bearer <token>
Content-Type: application/json
```

### HMAC Headers
```
X-Key-Id: <your-key-id>
X-Timestamp: <unix-seconds>
X-Nonce: <uuid-v4>
X-Signature: <base64-hmac-sha256>
X-Content-SHA256: <sha256-hex-or-UNSIGNED-PAYLOAD>
Host: v2-cloudflare.bigscoots.dev
Content-Type: application/json
```


### Error Codes Quick Reference

| Code | Meaning | Action |
|------|---------|--------|
| 400 | Bad Request | Fix request format |
| 401 | Unauthorized | Check authentication |
| 403 | Forbidden | Check permissions |
| 404 | Not Found | Verify endpoint |
| 429 | Too Many Requests | Implement backoff |
| 500 | Server Error | Contact support |

---

## Summary

### For Frontend Teams (JWT)

1. **Get JWT token** from Auth0
2. **Add to requests** as `Authorization: Bearer <token>`
3. **Handle 401 errors** by refreshing token
4. **Use provided examples** for React/Vue/Angular

### For Backend Teams (HMAC)

1. **Get API credentials** from BigScoots
2. **Generate signature** using HMAC-SHA256
3. **Include all required headers** (Key-Id, Timestamp, Nonce, Signature, Content-SHA256)
4. **Use provided client libraries** for Node.js/Python
5. **Handle errors** appropriately (timestamp, nonce, signature)

Happy coding! 🚀

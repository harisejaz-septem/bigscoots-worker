# HMAC Authentication Implementation Update

**Date: September 30, 2025**

## Overview

Extended the BigScoots v2 authentication gateway to support HMAC-signed requests for enterprise clients alongside existing JWT authentication. Both authentication methods now work on the same endpoints with consistent identity header injection.

## Implementation Details

### Body Hash Policy

**Decision Made: September 30, 2025**

For GET/DELETE requests (or requests without body), we use `"UNSIGNED-PAYLOAD"` instead of empty string SHA256 hash.

**Reasoning:**
- Clearer intent than cryptographic hash of empty string
- Matches AWS API Gateway convention
- Shorter and more explicit

### Signed Headers

**Headeluded in HMAC signature:**
- `host` - Prevents subdomars incin/domain attacks
- `content-type` - Prevents content-type confusion attacks

**Canonical String Format:**
```
METHOD
PATH
QUERY (sorted)
content-type:application/json
host:api.bigscoots.com
TIMESTAMP
NONCE
BODY-SHA256-OR-UNSIGNED-PAYLOAD
```

## Headers Comparison Table

### Incoming Headers (Client → Worker)

| Auth Method | Required Headers |
|-------------|------------------|
| **JWT** | `Authorization: Bearer <jwt-token>` |
| **HMAC** | `X-Key-Id: live_org_test123`<br>`X-Timestamp: 1727712000`<br>`X-Nonce: uuid-v4-string`<br>`X-Signature: base64-hmac-signature`<br>`X-Content-SHA256: UNSIGNED-PAYLOAD`<br>`Host: api.bigscoots.com`<br>`Content-Type: application/json` |

### Outgoing Headers (Worker → Backend Services)

| Header | JWT Value | HMAC Value | Purpose |
|--------|-----------|------------|---------|
| **X-Auth-Type** | `jwt` | `hmac` | Authentication method used |
| **X-User-Id** | `auth0\|68cbea0228b131ec7437b5cc` | `—` (not applicable) | Individual user identifier |
| **X-Client-Id** | `auth0\|68cbea0228b131ec7437b5cc` | `live_org_test123` | Client making the request |
| **X-Org-Id** | `null` | `enterprise-1` | Organization for isolation |
| **X-Scopes** | `["openid","email","profile"]` | `["users:read","sites:write"]` | Permission scopes |
| **X-Role** | `customer` | `—` (not applicable) | User role (JWT only) |
| **X-Email** | `user@example.com` | `—` (not applicable) | User email (JWT only) |

### Headers Stripped by Worker

| Auth Method | Headers Removed Before Forwarding |
|-------------|-----------------------------------|
| **JWT** | `Authorization` |
| **HMAC** | `X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`, `X-Content-SHA256` |

## Backend Service Security Requirements

### HeadersVerifiedGuard Implementation

**CRITICAL:** Backend microservices MUST implement a guard to verify that requests come through the Worker and contain expected identity headers.

**Required Check:**
```typescript
// Pseudo-code for backend services
if (!request.headers['X-Auth-Type'] || 
    !request.headers['X-Client-Id'] || 
    !request.headers['X-Scopes']) {
  throw new UnauthorizedException('Request must come through authentication gateway');
}

// Additional validation
if (request.headers['Authorization'] || 
    request.headers['X-Key-Id'] || 
    request.headers['X-Signature']) {
  throw new UnauthorizedException('Direct authentication headers not allowed');
}
```

**Why This Matters:**
- Prevents direct access to backend services bypassing authentication
- Ensures all requests have been validated by the Worker
- Protects against header injection attacks

## KV Storage Schema

**API Key Storage:**
```json
Key: "api_key:{keyId}"
Value: {
  "secret": "base64randomsecret",
  "orgId": "enterprise-1", 
  "scopes": ["users:read", "sites:write"],
  "rateLimit": {
    "minute": 60,
    "hour": 1000,
    "day": 20000
  }
}
```

## Security Features

### Replay Protection
- **In-Memory Nonce Tracking**: Per worker instance (temporary)
- **Timestamp Window**: ±300 seconds tolerance
- **Future Enhancement**: Move to Durable Objects for global nonce tracking

### HMAC Validation Steps
1. Extract required headers (`X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`, `X-Content-SHA256`)
2. Validate timestamp freshness (±300s window)
3. Check nonce uniqueness (prevent replay)
4. Verify body hash matches `X-Content-SHA256`
5. Fetch API key metadata from Workers KV
6. Rebuild canonical string from request
7. Verify HMAC-SHA256 signature using WebCrypto
8. Inject identity headers and forward to backend

### Error Responses

| Error Type | HTTP Status | Error Code |
|------------|-------------|------------|
| Missing headers | 401 | `invalid_request` |
| Expired timestamp | 401 | `invalid_request` |
| Replay attack | 401 | `invalid_request` |
| Invalid signature | 401 | `invalid_signature` |
| Unknown API key | 401 | `invalid_key` |

## Testing

### Test API Key (Preview Environment)
```bash
npx wrangler kv key put "api_key:live_org_test123" \
  '{"secret":"base64randomsecret","orgId":"enterprise-1","scopes":["users:read","sites:write"]}' \
  --binding KV --preview
```

### Example HMAC Request
```http
POST /api/test
Host: api.bigscoots.com
Content-Type: application/json
X-Key-Id: live_org_test123
X-Timestamp: 1727712000
X-Nonce: 550e8400-e29b-41d4-a716-446655440000
X-Content-SHA256: UNSIGNED-PAYLOAD
X-Signature: <computed-hmac-signature>

{"test": "data"}
```

## Future Enhancements

1. **Durable Objects**: Replace in-memory nonce tracking with global state
2. **Rate Limiting**: Implement per-client quotas using rate limit metadata
3. **Key Rotation**: Support multiple active secrets per key
4. **Audit Logging**: Enhanced logging for security monitoring

---

**Implementation completed:** September 30, 2025  
**Next Phase:** Testing and Durable Objects integration

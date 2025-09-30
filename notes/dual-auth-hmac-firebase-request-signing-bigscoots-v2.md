# Authentication Strategy — BigScoots v2 (HMAC + JWT)

## Purpose and Scope

The purpose of this document is to define and finalize the authentication strategy for **BigScoots v2 APIs**, ensuring that both **normal end-users** and **enterprise/agency clients** can securely access the system while using the same API endpoints.

This document covers two parallel authentication mechanisms:

* **JWT Authentication (Firebase/Auth0)**
  For normal users who log in via Firebase SDK or Auth0. JWT validation is handled by Cloudflare Workers at the edge, with custom claims used for org mapping and scope authorization. We support both Firebase ID tokens and Auth0 access tokens for flexibility during migration.

* **HMAC-Signed Request Authentication (API Keys v2)**
  For enterprise or agency clients who integrate programmatically. Uses signed requests with HMAC-SHA256, timestamp, and nonce to prevent replay attacks. Validated by Cloudflare Workers at the edge and optionally re-verified by the backend API.

Both mechanisms must coexist on the **same API endpoints**. Cloudflare Workers will choose the verification path based on headers provided. Backend services will see a **unified identity model** regardless of which authentication path was used.

---

## TL;DR (executive summary)

* We support **two auth types** side by side:

  * JWT tokens (Firebase ID tokens or Auth0 access tokens for users)
  * HMAC-signed requests (for enterprise)
* Both hit the **same endpoints** — no separate paths.
* **Cloudflare Workers** decide which verification path to use:

  * `Authorization: Bearer …` → validate JWT (Firebase or Auth0) with cached JWKS.
  * `X-API-Key` / `X-Key-Id`, `X-Signature`, headers → HMAC verification with Workers KV lookup.
* Both inject **identity headers** (`X-Auth-Type`, `X-Org-Id`, `X-Client-Id`, `X-Scopes`) into requests passed to backend services.
* Backend authorization is uniform: scope + org isolation enforced consistently.
* Rate limiting, replay protection, rotation, and quotas are applied per org/client using Durable Objects.

---

# Section 1 — JWT Authentication (Firebase/Auth0)



## Purpose

This section defines the **JWT authentication flow** for normal users (Basic Plan). These are individual customers authenticating through Firebase SDK, Auth0 SDK, or other OIDC-compliant providers (mobile, web, desktop).

## TL;DR (executive summary)

* Users authenticate via Firebase SDK or Auth0 and obtain a **JWT (ID Token or Access Token)**.
* Requests include `Authorization: Bearer <jwt_token>`.
* Cloudflare Workers validate the JWT using cached JWKS from the provider.
* If valid, Workers inject identity headers (`X-Auth-Type: jwt`, `X-User-Id`, `X-Org-Id`, `X-Scopes`).
* Backend services authorize based on these headers.
* Invalid tokens are blocked at the edge with `401 Unauthorized`.

---

## The headers (what/why/who)

We support both Firebase and Auth0 JWT tokens. Configuration (project ID, issuer, audience) is provided during onboarding. The client generates tokens via Firebase SDK or Auth0 SDK.

| Header        | What it means                                          | Who CREATES it           | Server USES it for                 | Server STORES it |
| ------------- | ------------------------------------------------------ | ------------------------ | ---------------------------------- | ---------------- |
| Authorization | Bearer token with JWT (Firebase ID or Auth0 Access)   | Client (via SDK)         | Validate signature/claims via JWKS | No               |
| X-User-Id     | User identifier (Firebase UID or Auth0 sub claim)     | Worker (from JWT)        | User identity mapping              | No               |
| X-Org-Id      | Organization from custom claim                         | Worker (from JWT)        | Org isolation enforcement          | No               |
| X-Scopes      | Scope claims (array/string)                            | Worker (from JWT)        | Authorization checks               | No               |
| X-Auth-Type   | Fixed: `jwt`                                           | Worker                   | Identity type differentiation      | No               |

---

## Flow

### Client

* User signs in via Firebase SDK (web/mobile).
* Firebase returns an **ID Token (JWT)** valid for \~1 hour.
* Client attaches the token:

  ```
  Authorization: Bearer <firebase-id-token>
  ```

### Cloudflare Worker (Edge)

* Worker validates the token using cached JWKS from the provider.
* Required claim checks vary by provider:

**Firebase JWT:**
| Claim | Expected Value                                      |
| ----- | --------------------------------------------------- |
| `iss` | `https://securetoken.google.com/<firebase-project>` |
| `aud` | `<firebase-project-id>`                             |
| `exp` | Not expired                                         |
| `nbf` | Not in the future                                   |
| `kid` | Must exist in Firebase JWKS                         |

**Auth0 JWT:**
| Claim | Expected Value                                      |
| ----- | --------------------------------------------------- |
| `iss` | `https://<auth0-domain>/`                          |
| `aud` | `<auth0-audience>`                                  |
| `exp` | Not expired                                         |
| `nbf` | Not in the future                                   |
| `kid` | Must exist in Auth0 JWKS                            |

* If valid: Worker injects identity headers.
* If invalid: reject with `401 Unauthorized`.

### API Service

* Backend reads injected headers (`X-User-Id`, `X-Org-Id`, `X-Scopes`).
* Applies org isolation + scope enforcement.
* Example:

  * `sites:read` required for `GET /site-mgmt/sites`.
  * `users:write` required for `POST /user-mgmt/users`.

---

## Error Handling

| Error              | Description                                             | Response                             |
| ------------------ | ------------------------------------------------------- | ------------------------------------ |
| `401 Unauthorized` | Invalid signature, expired token, wrong issuer/audience | JSON error with `invalid_token`      |
| `403 Forbidden`    | Token valid but missing required scope                  | JSON error with `insufficient_scope` |

Example:

```json
{
  "error": "invalid_token",
  "message": "JWT validation failed",
  "statusCode": 401,
  "requestId": "abc123",
  "ts": "2025-09-05T12:34:56Z"
}
```

---

## Developer Experience

* Firebase SDKs handle login and token refresh.
* Required custom claims: `org_id`, `scopes`.

---

## Security Notes

* Always validate `iss`, `aud`, `exp`, `nbf`.
* Reject tokens without required custom claims.
* HTTPS only.
* Backend must not trust raw Authorization header, only headers injected by Cloudflare Workers.

---

# Section 2 — HMAC Request Signing (Enterprise)

## Purpose

Authenticate and protect every API request with a signature that proves the sender knows a shared secret, and that the request wasn't altered or replayed.

**Scope:** applies to enterprise/API-key access via Cloudflare Workers → backend services (User-Mgmt, Site-Mgmt, Job-Scheduler, etc.).

---

## TL;DR (executive summary)

* We issue each enterprise client a `keyId` (public) and a `secret` (private).
* The client builds a canonical string from the request (method, path, query, selected headers, timestamp, nonce, body hash), signs it with `HMAC-SHA256`, and sends the signature + metadata in headers.
* The server rebuilds the same canonical string from what it actually received, recomputes the HMAC, and compares in constant time.
* We reject replays (nonce seen before) and stale requests (timestamp outside ±5 minutes).
* Cloudflare Workers validate at the edge before requests hit our apps; the app can optionally re-verify (defense-in-depth).

---

## Addendum — clarifications & improvements (read once)

### Cloudflare Worker vs API service verification

We do freshness + nonce + secret lookup in **both** Cloudflare Workers and the API. That's safe but adds overhead. Choose one operating mode:

| Mode                           | What it means                                                             | Pros                                        | Cons                                                                  | Recommended when                             |
| ------------------------------ | ------------------------------------------------------------------------- | ------------------------------------------- | --------------------------------------------------------------------- | -------------------------------------------- |
| **Authoritative Edge**         | API trusts Worker; API does *minimal* checks (e.g., headers present)     | Lowest latency per request                  | Edge verifier is critical path; misconfig there affects all routes   | You have mature, well-monitored edge auth   |
| **Defense-in-depth (default)** | Worker filters early; API **re-verifies everything**                     | Hard to bypass; easier incident containment | Slightly higher CPU/Durable Object calls                             | General case; keeps teams honest             |

> **Default here:** Defense-in-depth. API remains the source of truth.

### Signed headers (normalize & keep small)

* **Lowercase** all header names; **sort alphabetically** when building the "signed headers" block.
* **Exclude** proxy-added headers (e.g., `x-forwarded-for`, `x-forwarded-proto`) unless you 100% control them.
* **Fix the set** to stable, minimal headers: `host`, `content-type` (if body), and tenant/org header(s) such as `x-tenant-id`.

### Body hash for GET/DELETE

For methods with no body:

* Either send **SHA256 of empty string** (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`), **or**
* Send the literal **`UNSIGNED-PAYLOAD`** (string) in `X-Content-SHA256` and in the canonical line.
  Pick one policy; document it for clients. (Examples below.)

### Skew window (observability)

* Keep **±300s** acceptance, **and** log any request outside **±60s** (warning). This catches slow clocks and abuse.
* Optionally return `401 {"error":"timestamp out of range"}` for DX clarity.

### Key rotation (make it explicit)

* Issue **v2** while **v1** remains active.
* Server validates against **both**.
* After the cutover window, revoke **v1**.
* Implement either `X-Key-Version` or multiple active secrets under one `keyId`.

### Quotas & rate limiting

* **Quotas (per org/client) = Durable Object counters** incremented on every **accepted** request; if above monthly/daily cap → **429**.
* **Edge shaping** via Cloudflare WAF rules, with **fine-grained quotas** enforced via Durable Objects.

### Scopes / authorization

* After HMAC auth, enforce **scopes** in the API (e.g., key with `reports:read` cannot call `POST /reports`).
* Put the scope check in **S6 Handler**.

### Error codes (canonical)

* **401** → invalid/missing signature, expired timestamp, replayed nonce.
* **403** → unknown/disabled key, or missing scope.
* **429** → quota exceeded.
* **200+** → success.

---

## Vocabulary

* **Public identifier (`keyId`)** — safe to show/log; maps to a secret we store.
* **Secret** — random 32+ bytes shared with the client (never logged).
* **Nonce** — a one-time random value per request (UUID v4) to block replays.
* **Skew** — the allowed clock drift between client and server (±5 min).
* **Raw body bytes** — the exact byte sequence on the wire (before parsing).
* **Canonical string** — fixed, newline-joined representation we sign.

---

## High-level flow (plain text)

```
Client
  1) Hash raw body bytes → BODY_SHA256
  2) Build CANONICAL = join(
       METHOD, PATH, SORTED_QUERY,
       SIGNED_HEADERS(lowercased+sorted),
       X-Timestamp, X-Nonce, BODY_SHA256
     )
  3) X-Signature = Base64(HMAC_SHA256(secret, CANONICAL))
  4) Send HTTP + headers: X-Key-Id, X-Timestamp, X-Nonce, X-Alg=HMAC-SHA256,
                         X-Content-SHA256, X-Signature
     (+ the headers we decided to sign, e.g., Host, Content-Type, X-Tenant-Id)

Cloudflare Worker (edge validation)
  5) Validate headers + algorithm
  6) Check timestamp (±5 min; log beyond ±60s)
  7) Replay check: Durable Object nonce registry with ~300s TTL
  8) Recompute BODY_SHA256 from raw bytes, compare to X-Content-SHA256
  9) Rebuild CANONICAL from actual request
 10) Look up secret from Workers KV by X-Key-Id (consider versions)
 11) Recompute expected signature, timing-safe compare
 12) If valid, inject identity headers and route to backend

API Server (optional re-verification)
 13) Optionally re-verify HMAC (defense-in-depth mode)
 14) Enforce scopes/authorization
 15) Accept (200+) or 401/403/429
```


## The headers (what/why/who)

> **We provide** the `keyId` and the **secret** during onboarding. The client generates the rest per request.

| Header               | What it means                                                                                                                                                              | Who CREATES it                 | Server USES it for                                                     | Server STORES it                                  |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------- |
| **X-Key-Id**         | Public identifier for the API key                                                                                                                                          | **BigScoots issues** to client | Fetch `secret` (`keyId → secret`)                                      | **Yes** (DB/KMS mapping, status, owner, versions) |
| **X-Timestamp**      | Unix seconds when request was signed                                                                                                                                       | Client                         | Freshness window (reject stale; log drift >±60s)                       | No                                                |
| **X-Nonce**          | One-time random value (UUID v4)                                                                                                                                            | Client                         | **Replay** defense (must be unseen)                                    | **Ephemeral** (Durable Object, TTL \~300s)         |
| **X-Alg**            | Algorithm used                                                                                                                                                             | Client                         | Must be allowed (`HMAC-SHA256`)                                        | No                                                |
| **X-Content-SHA256** | SHA256(hex) of **raw body bytes**. **GET/DELETE:** either SHA256 of empty string (`e3b0…b855`) **or** literal `UNSIGNED-PAYLOAD` (policy must be documented consistently). | Client                         | Body integrity (no tamper); special-case handling for bodyless methods | No                                                |
| **X-Signature**      | `Base64(HMAC(secret, CANONICAL))`                                                                                                                                          | Client                         | Final verification (constant-time compare)                             | No                                                |

> Additionally, the client **sends the headers we decided to sign** (e.g., `Host`, `Content-Type`, `X-Tenant-Id`). Names must be **lowercased** and **sorted** in the canonical block. **Do not** include proxy-added headers like `x-forwarded-for`.

---

## Canonical string (our contract)

> **We must never change this without versioning.** Every line is joined with `\n` (LF).

```
METHOD
PATH
QUERY                  (sorted; preserve duplicate keys; RFC3986-encoded)
SIGNED-HEADERS         (each line: lowercase "name:value", sorted by name)
TIMESTAMP              (the X-Timestamp string)
NONCE                  (the X-Nonce value)
BODY-SHA256            (hex sha256 of raw body bytes, or 'UNSIGNED-PAYLOAD' if policy allows)
```

* **METHOD**: uppercase (`GET`, `POST`, …).
* **PATH**: URL path only (`/v2/widgets`), percent-encoded.
* **QUERY**: sort by key then value; encode spaces as `%20` (not `+`).
* **SIGNED-HEADERS**: minimal, stable set → `host`, `content-type` (if body), optional `x-tenant-id`; **lowercase names**, **sorted by name**.
* **BODY-SHA256**: hash the **exact bytes** received; for bodyless methods, use the chosen policy (empty-sha or `UNSIGNED-PAYLOAD`).

---

## Example (request + canonical + signature)

**Request**

```
POST https://api.example.com/api/v1/invoices?customer=123&status=open
Host: api.example.com
Content-Type: application/json
X-Key-Id: live_org_abc123
X-Timestamp: 1725550000
X-Nonce: 7d6b6a1c-6f55-4e8a-bf4a-58c5a70f1d2e
X-Alg: HMAC-SHA256
X-Content-SHA256: 3f786850e387550fdab836ed7e6dc881de23001b
X-Signature: AbCdEf...==

{"amount":1000,"currency":"USD"}
```

**Canonical (7 lines)**

```
POST
/api/v1/invoices
customer=123&status=open
host:api.example.com
content-type:application/json
1725550000
7d6b6a1c-6f55-4e8a-bf4a-58c5a70f1d2e
3f786850e387550fdab836ed7e6dc881de23001b
```

**Bodyless GET example (policy A: empty-sha)**

```
GET /reports?from=2024-01-01&to=2024-01-31
X-Content-SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**Bodyless GET example (policy B: unsigned)**

```
GET /reports?from=2024-01-01&to=2024-01-31
X-Content-SHA256: UNSIGNED-PAYLOAD
```

**Signature**

```
X-Signature = Base64( HMAC_SHA256( secret, canonical ) )
```

---

## "Raw bytes" explained (why it matters)

Two bodies that "look" the same can be **different bytes**:

* `{"a":1}`  → bytes: `7B 22 61 22 3A 31 7D`
* `{ "a": 1 }` → bytes: `7B 20 22 61 22 3A 20 31 20 7D`

Different bytes → different SHA256 → signature fails.

**Rule:** compute the hash over the exact bytes placed on the wire; on the server, compute over the exact bytes **received** (before parsing).

---

## Client responsibilities (checklist)

* Generate `X-Nonce` (UUID v4) and `X-Timestamp` (unix seconds).
* Hash **raw body bytes** → `X-Content-SHA256`. For GET/DELETE: follow the chosen policy (empty-sha or `UNSIGNED-PAYLOAD`).
* Build canonical string exactly as specified (lowercased, sorted signed headers).
* Compute `X-Signature`.
* Send the **signed headers** themselves (e.g., `Host`, `Content-Type`).
* Handle `401/403/429` appropriately; backoff on 429; correct clock drift on 401 timestamp errors.

---

## Server responsibilities (checklist)

1. Validate presence of all `X-*` headers; `X-Alg` must be allowed.
2. **Timestamp window:** `abs(now - X-Timestamp) ≤ 300s`. **Log** if outside ±60s; optionally return `401 {"error":"timestamp out of range"}`.
3. **Replay defense:** Durable Object stores `nonce:{keyId}:{ts}:{nonce}` with TTL \~300s; if exists → **401 replay**.
4. **Raw body hash:** compute SHA256 over raw bytes; compare to `X-Content-SHA256` (treat `UNSIGNED-PAYLOAD` per policy).
5. Rebuild **canonical** from actual request pieces (lowercased + sorted signed headers).
6. Look up `secret` by `X-Key-Id`; support **two active secrets** or `X-Key-Version`.
7. Compute expected signature and compare with `crypto.timingSafeEqual`.
8. **Enforce scopes** against the route/action (e.g., `reports:read` vs `POST /reports`).
9. **Quotas:** increment Durable Object counters per `{org_id, client_id}` and enforce caps (429).
10. Return **200+** (or forward to handler) or **401/403/429**.
11. Log minimal details (internally mark which check failed), never log secrets/signatures.

---

## Provisioning, storage, rotation

### Secret Storage in Workers KV

**Enhanced Storage Schema with Per-Client Rate Limits:**
```
Key: `api_key:{keyId}`
Value: {
  "secrets": [
    {
      "version": "v1",
      "secret": "base64-encoded-32-byte-secret",
      "created_at": "2025-01-15T10:30:00Z",
      "status": "active|deprecated"
    },
    {
      "version": "v2", 
      "secret": "base64-encoded-32-byte-secret",
      "created_at": "2025-02-15T10:30:00Z",
      "status": "active"
    }
  ],
  "metadata": {
    "org_id": "org_abc123",
    "client_name": "Acme Corp API Client",
    "scopes": ["sites:read", "sites:write", "users:read"],
    "status": "active|disabled|revoked",
    "plan_tier": "enterprise",
    "rate_limits": {
      "requests_per_minute": 1000,
      "requests_per_hour": 50000,
      "requests_per_day": 1000000,
      "burst_limit": 150,
      "concurrent_requests": 50
    },
    "created_at": "2025-01-15T10:30:00Z",
    "last_used_at": "2025-09-23T14:22:00Z"
  }
}
```

### Per-Client Rate Limiting Tiers

Define standard tiers that can be assigned to API keys:

| Tier | Requests/Min | Requests/Hour | Requests/Day | Burst | Concurrent |
|------|-------------|---------------|--------------|-------|------------|
| **Free** | 60 | 3,000 | 50,000 | 10 | 5 |
| **Basic** | 300 | 15,000 | 300,000 | 50 | 10 |  
| **Pro** | 1,000 | 50,000 | 1,000,000 | 150 | 25 |
| **Enterprise** | 5,000 | 200,000 | 5,000,000 | 500 | 100 |
| **Custom** | Variable | Variable | Variable | Variable | Variable |

### Key Management Process

* **Issuing keys:** 
  1. BigScoots portal generates `keyId` (format: `live_org_{orgId}_{random}`)
  2. Admin selects tier (Free/Basic/Pro/Enterprise/Custom) or sets custom limits
  3. Generate 32-byte secret using `crypto.getRandomValues()`
  4. Store in Workers KV with metadata and rate limits
  5. Show secret once to client for download
  6. Store audit log in primary DB

* **Rotation process:**
  1. Generate new secret version while keeping old active
  2. Update Workers KV with both secrets marked as active
  3. Client tests with new secret
  4. Mark old secret as deprecated after successful validation
  5. Remove deprecated secret after grace period (7-30 days)

* **Worker Lookup Logic:**
  - Try current active secret first
  - If signature fails, try deprecated secrets
  - Log which version was used for monitoring rotation progress
  - Extract rate limits from metadata for quota enforcement

* **Revocation:** 
  - Set status = `disabled` in Workers KV
  - Worker returns **403** for disabled keys
  - Optionally purge from KV after retention period

---

## Replay & skew (what/why/how)

* **Replay:** attacker resends a previously valid request.

  * Fix: server stores `(keyId, timestamp, nonce)` for a short time. If seen again → **reject**.
* **Skew:** client/server clocks drift.

  * Fix: accept timestamps within **±300s**; **log** if beyond ±60s; use NTP on both ends.

**Defaults:** Skew window = ±300s; Nonce TTL = 300s.

---

## Cloudflare Worker implementation (edge verification)

> Edge verification reduces load on apps, but the app **should still verify** (default mode).

### Single Worker Approach (recommended)

* Deploy a **single Cloudflare Worker** that handles both JWT and HMAC verification.
* Worker uses **Workers KV** for API key/secret storage (`keyId → {secret, scopes, status, rate_limits}`).
* Worker uses **Durable Objects** for nonce replay prevention and per-key quotas.
* Worker validates requests and injects identity headers before routing to backend.

### Worker Architecture

* **JWT validation:** Cache provider JWKS, verify signatures, extract claims.
* **HMAC validation:** Lookup secrets from KV, verify signatures with WebCrypto, check replay via Durable Objects.
* **Per-client rate limiting:** Extract client-specific limits from KV, enforce via Durable Objects across multiple time windows.
* **Routing:** Based on path, route to appropriate backend service with `fetch()`.

### Benefits over Traefik

* **No SPOF:** Cloudflare's global network provides HA out of the box.
* **Simplified architecture:** Single Worker handles all authentication vs multiple Traefik components.
* **Edge performance:** Validation happens closer to users globally.

---

## Error handling (canonical map)

* **400** — malformed/missing required headers/values.
* **401** — bad/missing signature, **expired timestamp**, **replay detected**.
* **403** — **unknown/disabled key**, or **missing scope**.
* **429** — **quota exceeded** (per org/client).
* **200+** — success.

Return generic text to external clients ("Unauthorized", "Forbidden", "Too Many Requests"); keep detailed reasons in internal logs.

---

## Per-Client Rate Limiting Implementation

### Enhanced Durable Object for Multi-Window Quotas

```
Purpose: Track usage across multiple time windows per client
Key Structure: `quota:{keyId}:{window}` where window = "1m", "1h", "1d"
Data: {
  count: number,
  resetTime: timestamp,
  limits: { minute: 1000, hour: 50000, day: 1000000 }
}

Methods:
- checkAllQuotas(keyId, limits) → { allowed: boolean, violations: string[], remaining: object }
- incrementAll(keyId) → boolean
- getRemainingQuotas(keyId) → { minute: number, hour: number, day: number }
```

### Worker Implementation Steps

1. **Lookup Client-Specific Limits**
   - After HMAC validation, extract `rate_limits` from Workers KV
   - Pass limits to Durable Object quota tracker

2. **Multi-Window Quota Check**
   - Check against minute, hour, and daily limits simultaneously
   - Return specific violation details for better client feedback

3. **Rate Limit Response Headers**
   - Include current usage and limits in all responses
   - Provide clear guidance on when limits reset

### Example Response Headers

```
X-RateLimit-Limit-Minute: 1000
X-RateLimit-Remaining-Minute: 847
X-RateLimit-Reset-Minute: 1695474120
X-RateLimit-Limit-Hour: 50000  
X-RateLimit-Remaining-Hour: 48234
X-RateLimit-Limit-Day: 1000000
X-RateLimit-Remaining-Day: 923456
```

### Portal Management Features

* **Tier Selection:** Choose from predefined tiers or set custom limits
* **Real-time Updates:** Modify limits without Worker redeployment
* **Usage Analytics:** Track consumption patterns per client
* **Upgrade Recommendations:** Identify clients approaching limits

---

## Worker Implementation Steps

### Core Worker Architecture

1. **Main Request Handler**
   - Check request method (handle OPTIONS for CORS)
   - Determine auth method by inspecting headers (`Authorization` vs `X-API-Key`)
   - Route to appropriate validation function
   - Apply client-specific rate limiting checks via Durable Objects
   - Forward to backend service with injected identity headers

2. **JWT Validation Logic**
   - Extract Bearer token from Authorization header
   - Determine provider (Firebase vs Auth0) based on token issuer
   - Fetch and cache JWKS from provider endpoint
   - Verify token signature using WebCrypto API
   - Validate standard claims (`iss`, `aud`, `exp`, `nbf`)
   - Extract custom claims (`org_id`, `scopes`) for authorization

3. **HMAC Validation Logic**
   - Validate presence of required headers (`X-Key-Id`, `X-Timestamp`, `X-Nonce`, `X-Signature`)
   - Check timestamp within ±300s window (log drift >±60s)
   - Verify nonce uniqueness via Durable Object
   - Rebuild canonical string from request components
   - Lookup secret and rate limits from Workers KV by `keyId`
   - Compute expected signature using WebCrypto HMAC-SHA256
   - Compare signatures using timing-safe equality

4. **Per-Client Rate Limiting**
   - Extract client-specific rate limits from KV metadata
   - Check against multiple time windows (minute, hour, day)
   - Return detailed rate limit information in response headers
   - Block requests that exceed any time window limit

5. **Body Hash Handling**
   - For requests with body: compute SHA256 of raw request body bytes
   - For GET/DELETE: use either empty string hash or `UNSIGNED-PAYLOAD` (document policy)
   - Always hash raw bytes before any parsing/transformation

6. **Backend Routing**
   - Map request paths to backend service URLs
   - Create new request with identity headers injected
   - Forward using `fetch()` API

---

## Test matrix (use in CI)

* Change **one** query value → **401**.
* Reuse the same `(timestamp, nonce)` → **401 (replay)**.
* Timestamp > 5 minutes old/new → **401 (stale)**; also check log shows drift beyond ±60s.
* Flip one body byte → **401 (body mismatch)**.
* Unknown `keyId` → **401**; disabled key → **403**; missing scope → **403**.
* Exceed per-minute quota → **429** with minute-specific headers.
* Exceed per-hour quota → **429** with hour-specific headers.
* Exceed per-day quota → **429** with day-specific headers.
* Happy path → **200** with rate limit headers.

---

## FAQ (answers you'll be asked)

**Where does the client get `keyId` and `secret`?**
From our portal (BigScoots issues them). We store the mapping; the client stores the secret on their side.

**Will the client know the secret?**
Yes. HMAC is **symmetric**: both sides must know it. If you don't want that, use asymmetric signing or OAuth/JWT.

**What if the secret leaks?**
Treat as credential compromise: **rotate/revoke** immediately, throttle, optionally IP-allowlist/mTLS/scopes, and review audit logs.

**What is a Cloudflare Worker?**
A serverless function that runs on Cloudflare's global edge network. It processes requests before they reach your backend, providing authentication, routing, and rate limiting at the edge.

**What are "raw bytes"?**
The exact byte sequence transmitted in the HTTP body. We hash those bytes before any parsing/rewrites; the server hashes exactly what it received.

**How do per-client rate limits work?**
Each API key has its own rate limits stored in Workers KV. The Worker enforces these limits using Durable Objects that track usage across multiple time windows (minute, hour, day) simultaneously.

**Can I change a client's rate limits without redeploying?**
Yes. Rate limits are stored in Workers KV and can be updated via the portal. The Worker picks up new limits on the next request automatically.

**Replay vs Skew?**
Replay = same `(keyId, timestamp, nonce)` seen again → reject.
Skew = clock drift; accept timestamps within ±5 minutes; log drift >±60s.

---

# Section 3: Cloudflare Worker configuration for dual auth on the same endpoints

## Purpose

Document how Cloudflare Workers enforce **both** authentication methods (JWT for users, HMAC for enterprise) **on the same API URLs**, and how per-client rate limiting/throttling is applied.

## TL;DR

* Deploy a **single Cloudflare Worker** that handles both JWT and HMAC verification.
* Use **header-based logic** so the *same paths* accept either auth:

  * If the request has `Authorization: Bearer …` → run **JWT validation** (Firebase/Auth0).
  * If it has `X-API-Key` / `X-Key-Id`, `X-Signature` → run **HMAC validation**.
* Apply **WAF rate limits** globally and **per-client quotas** via Durable Objects.
* Worker routes authenticated requests to appropriate backend services with identity headers injected.

---

## Current Worker setup requirements

```toml
# wrangler.toml
name = "bigscoots-api-gateway"
main = "src/worker.ts"
compatibility_date = "2025-09-01"

[[kv_namespaces]]
binding = "API_KEYS_KV"
id = "your-kv-namespace-id"

[[durable_objects.bindings]]
name = "NONCE_DO"
class_name = "NonceReplayGuard"

[[durable_objects.bindings]]
name = "QUOTA_DO"
class_name = "PerClientQuota"

[vars]
# Firebase config
FIREBASE_PROJECT_ID = "bigscoots-e4acb"
FIREBASE_ISS = "https://securetoken.google.com/bigscoots-e4acb"
FIREBASE_JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"

# Auth0 config (optional)
AUTH0_DOMAIN = "your-auth0-domain.auth0.com"
AUTH0_AUDIENCE = "your-auth0-api-identifier"
AUTH0_JWKS_URL = "https://your-auth0-domain.auth0.com/.well-known/jwks.json"

# HMAC config
CLOCK_SKEW_SECS = "300"
NONCE_TTL_SECS = "300"

# Backend services
SITE_SERVICE_URL = "https://site-mgmt.internal"
USER_SERVICE_URL = "https://user-mgmt.internal"
BILLING_SERVICE_URL = "https://billing.internal"
REPORTS_SERVICE_URL = "https://reports.internal"
```

**Current capabilities**

* ✅ JWT validation for both Firebase and Auth0
* ✅ HMAC validation with Workers KV secret lookup
* ✅ Nonce replay protection via Durable Objects
* ✅ **Per-client quotas with custom rate limits** via Durable Objects
* ✅ Multi-time-window rate limiting (minute/hour/day)
* ✅ Routing to multiple backend services

---

## Worker Architecture (header-based dual auth, same URLs)

A **single Worker** handles both auth methods with conditional logic based on request headers. The Worker routes to appropriate backend services after authentication and rate limiting.

### Authentication & routing matrix

| Auth Method | Triggered when…                             | Validation Steps                        | Rate Limiting | Identity Headers Injected | Backend Routing |
| ----------- | -------------------------------------------- | --------------------------------------- | ------------- | ------------------------- | --------------- |
| JWT         | `Authorization: Bearer <token>` present     | JWKS validation, claim extraction       | Per-IP (WAF)  | `X-Auth-Type: jwt`, `X-User-Id`, `X-Client-Id`, `X-Org-Id`, `X-Scopes` | Path-based routing |
| HMAC        | `X-API-Key` header present                   | KV lookup, signature verification      | **Per-client custom limits** | `X-Auth-Type: hmac`, `X-Client-Id`, `X-Org-Id`, `X-Scopes` | Path-based routing |

### Backend Service Mapping

| Path Pattern    | Environment Variable     | Description        | Headers Required |
| --------------- | ------------------------ | ------------------ | ---------------- |
| `/site-mgmt/*`  | `SITE_SERVICE_URL`       | Site management    | All identity headers |
| `/user-mgmt/*`  | `USER_SERVICE_URL`       | User management    | All identity headers |
| `/billing/*`    | `BILLING_SERVICE_URL`    | Billing operations | All identity headers |
| `/reports/*`    | `REPORTS_SERVICE_URL`    | Analytics/reports  | All identity headers |

---

## Per-Client Rate Limiting Strategy

### Three-tier Rate Limiting Approach

1. **WAF Rate Limiting Rules (Global Protection)**
   - Blunt limits for DDoS protection (e.g., 10,000 req/min per IP)
   - Applied before Worker execution
   - Configured via Cloudflare dashboard

2. **Per-Client Custom Quotas (HMAC clients)**
   - Individual rate limits per API key based on their tier/plan
   - Multiple time windows enforced simultaneously (minute/hour/day)
   - Keyed by `{keyId}` with client-specific limits from Workers KV
   - Returns `429` with detailed rate limit headers

3. **Per-IP Limits (JWT users)**
   - Standard per-IP limits via WAF rules
   - Uniform limits for all JWT-authenticated users

### Enhanced Durable Object Implementation

```
Class: PerClientQuota
Purpose: Enforce client-specific rate limits across multiple time windows

Storage Structure:
- `quota:{keyId}:1m` → { count: 450, resetTime: 1695474180, limit: 1000 }
- `quota:{keyId}:1h` → { count: 15234, resetTime: 1695477600, limit: 50000 }
- `quota:{keyId}:1d` → { count: 234567, resetTime: 1695513600, limit: 1000000 }

Methods:
- checkAllQuotas(keyId, limits) → { 
    allowed: boolean, 
    violations: ["minute", "hour"], 
    remaining: { minute: 550, hour: 34766, day: 765433 },
    resetTimes: { minute: 1695474180, hour: 1695477600, day: 1695513600 }
  }
- incrementAll(keyId) → boolean
- getUsageStats(keyId) → detailed usage breakdown
```

### Rate Limit Response Headers

**Successful Request (within limits):**
```
X-RateLimit-Limit-Minute: 1000
X-RateLimit-Remaining-Minute: 550
X-RateLimit-Reset-Minute: 1695474180
X-RateLimit-Limit-Hour: 50000  
X-RateLimit-Remaining-Hour: 34766
X-RateLimit-Limit-Day: 1000000
X-RateLimit-Remaining-Day: 765433
```

**Rate Limited Request (429 response):**
```
X-RateLimit-Limit-Minute: 1000
X-RateLimit-Remaining-Minute: 0
X-RateLimit-Reset-Minute: 1695474180
Retry-After: 60
X-RateLimit-Violated: minute
```

---

## Security hardening (recommended)

**Cloudflare Security Features:**
* **TLS everywhere:** Cloudflare automatically provides TLS termination and certificates
* **WAF rules:** Enable Cloudflare's WAF to block common attacks (SQL injection, XSS, etc.)
* **API Shield:** Use schema validation to reject malformed requests early
* **Bot Management:** Detect and block automated attacks

**Worker Security:**
* **Secret management:** Store API secrets in Workers KV with proper access controls
* **Minimal headers:** Only forward necessary headers to backend services
* **Input validation:** Validate all request components before processing
* **Error handling:** Return generic errors externally, log details internally
* **Never log secrets:** Log only key metadata and request patterns

---

## Operational notes

**Monitoring & Observability:**
* **Worker Analytics:** Use Cloudflare Analytics to monitor request patterns, errors, and performance
* **Structured Logging:** Emit logs with `org_id`, `client_id`, route, status, latency, `requestId`, quota usage
* **Logpush:** Configure Logpush to send logs to your SIEM/analytics platform
* **Alerts:** Set up alerts on error rates, latency spikes, and quota violations per client

**Performance Optimization:**
* **JWKS Caching:** Cache provider JWKS in Worker memory with appropriate TTL (1 hour)
* **KV Performance:** Structure KV keys for optimal lookup performance
* **Durable Object Placement:** Use location hints for Durable Objects when possible
* **Rate Limit Caching:** Cache client rate limits in Worker memory briefly to reduce KV lookups

**Deployment & Testing:**
* **Canary Deployments:** Use Cloudflare's traffic splitting for gradual rollouts
* **Environment Management:** Separate dev/staging/prod configurations in wrangler.toml
* **Testing:** Validate both auth flows and rate limiting in staging before production deployment

---

## Implementation checklist

### Phase 1: Setup & Configuration
1. **Create Cloudflare Resources**
   - Set up Workers KV namespace for API keys with rate limit metadata
   - Configure Durable Object bindings for nonce/quota tracking
   - Set up WAF rate limiting rules for global protection

2. **Environment Configuration**
   - Configure Firebase/Auth0 settings in wrangler.toml
   - Set up backend service URLs
   - Configure logging and monitoring
   - Define rate limit tiers and default limits

### Phase 2: Core Implementation
3. **Implement Worker Logic**
   - Main request handler with auth method detection
   - JWT validation for Firebase/Auth0
   - HMAC validation with KV lookup including rate limits
   - Enhanced Durable Objects for per-client multi-window quotas

4. **Backend Integration**
   - Identity header injection
   - Path-based routing to backend services
   - Error handling and response formatting
   - Rate limit header injection

### Phase 3: Testing & Deployment
5. **Testing Strategy**
   - Unit tests for auth validation logic
   - Integration tests with staging backends
   - Load testing for per-client quota enforcement
   - Rate limiting boundary testing (minute/hour/day limits)

6. **Production Deployment**
   - Gradual rollout using traffic splitting
   - Monitor metrics and error rates per client
   - Verify identity headers reach backends correctly
   - Validate rate limiting works across time windows

---

## Durable Objects Implementation Guide

### Nonce Replay Guard
```
Purpose: Prevent replay attacks by tracking used nonces
Key Structure: `nonce:{keyId}:{timestamp}:{nonce}`
TTL: 300 seconds
Methods:
- checkAndStore(keyId, timestamp, nonce) → boolean
- cleanup() → removes expired entries
```

### Per-Client Quota Tracker  
```
Purpose: Enforce client-specific rate limits across multiple time windows
Key Structure: `quota:{keyId}:{window}` where window = "1m", "1h", "1d"
Data: { 
  count: number, 
  resetTime: timestamp, 
  limit: number,
  tier: string 
}
Methods:
- checkAllQuotas(keyId, limits) → { allowed: boolean, violations: string[], remaining: object, resetTimes: object }
- incrementAll(keyId) → boolean
- getUsageStats(keyId) → { current: object, limits: object, tier: string }
- resetWindow(keyId, window) → void
```

---

## Backend Service Requirements

### Required Identity Headers
All backend services MUST validate these headers from the Worker:

| Header | Description | Example Value |
|--------|-------------|---------------|
| `X-Auth-Type` | Authentication method used | `jwt` or `hmac` |
| `X-Client-Id` | Client identifier | `user_123` or `key_abc` |
| `X-Org-Id` | Organization identifier | `org_company123` |
| `X-Scopes` | JSON array of granted scopes | `["sites:read", "users:write"]` |
| `X-User-Id` | User ID (JWT only) | `firebase_uid_123` |

### Security Validation
- **Never trust** raw `Authorization` or `X-API-Key` headers from clients
- **Only trust** identity headers injected by the Worker
- **Validate** that required scopes match the requested action
- **Enforce** org isolation using `X-Org-Id`

---

## Monitoring & Alerting

### Key Metrics to Track
- Authentication success/failure rates by method
- Request latency at edge vs backend
- **Per-client quota utilization and violations**
- JWKS cache hit rates
- Durable Object performance metrics
- **Rate limiting effectiveness per tier**

### Alert Conditions
- Auth failure rate > 5% for 5 minutes
- Average request latency > 500ms
- **Any client exceeding 90% of any rate limit**
- Worker error rate > 1%
- KV lookup failures > 0.1%
- **Clients consistently hitting rate limits (upgrade candidates)**

### Enhanced Logging Requirements
```json
{
  "timestamp": "2025-09-23T14:30:00Z",
  "requestId": "req_abc123",
  "method": "POST",
  "path": "/site-mgmt/sites",
  "authType": "hmac",
  "clientId": "key_enterprise_123", 
  "orgId": "org_company456",
  "status": 200,
  "latencyMs": 125,
  "rateLimits": {
    "tier": "enterprise",
    "minute": { "used": 450, "limit": 1000, "remaining": 550 },
    "hour": { "used": 15234, "limit": 50000, "remaining": 34766 },
    "day": { "used": 234567, "limit": 1000000, "remaining": 765433 }
  }
}
```


# Addendum — Shared Clarifications

## Dual Authentication Model

* Both **JWT (Firebase/Auth0)** and **HMAC** are valid on the same API endpoints.
* Cloudflare Worker determines which to apply based on headers:

  * `Authorization: Bearer …` → JWT validation path.
  * `X-API-Key` + related headers → HMAC validation path.
* Both inject identity headers into backend requests.

---

## Unified Identity Model

Regardless of auth type, backend services see:

| Header      | JWT (Firebase/Auth0) | HMAC              |
| ----------- | -------------------- | ----------------- |
| X-Auth-Type | `jwt`                | `hmac`            |
| X-User-Id   | Firebase UID/Auth0 sub | —               |
| X-Client-Id | Firebase UID/Auth0 sub | API key id      |
| X-Org-Id    | From custom claims   | From key metadata |
| X-Scopes    | From custom claims   | From key metadata |

---

## Rate Limiting and Quotas

* **JWT users**: per-IP limits via WAF rules.
* **HMAC clients**: **per-client custom limits** via Durable Objects with multiple time windows.
* Global quotas tracked in Durable Objects for HMAC clients.
* Exceeded quota → `429 Too Many Requests` with detailed rate limit headers.

---

## Key Rotation

* **JWT (Firebase/Auth0)**: keys rotate automatically (JWKS cached in Worker).
* **HMAC**: two active secrets per key stored in Workers KV; verify against both during cutover; revoke old after transition.

---

## Example Headers Table

| Auth Method  | Request Headers                                                                                                               | Injected by Cloudflare Worker                                              |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| JWT (Firebase/Auth0) | `Authorization: Bearer <jwt_token>`                                                                                   | `X-Auth-Type: jwt`<br>`X-User-Id`<br>`X-Client-Id`<br>`X-Org-Id`<br>`X-Scopes` |
| HMAC         | `X-Key-Id`, `X-Timestamp`, `X-Nonce`,<br>`X-Alg`, `X-Content-SHA256`, `X-Signature`,<br>`Host`, `Content-Type`, `X-Tenant-Id` | `X-Auth-Type: hmac`<br>`X-Client-Id`<br>`X-Org-Id`<br>`X-Scopes` |

---


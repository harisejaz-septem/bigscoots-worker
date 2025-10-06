// bigscoots-v2-gateway-test
// JWT Authentication Gateway for BigScoots API

import { DurableObject } from "cloudflare:workers";

interface Env {
  AUTH0_ISSUER: string;
  AUTH0_AUDIENCE: string;
  JWKS_URL: string;
  KV: KVNamespace;
  NONCE_TRACKER: DurableObjectNamespace;
}

interface NonceReplayGuardStub {
  checkAndStore(nonce: string, timestamp: number): Promise<boolean>;
  getStats(): Promise<{ activeNonces: number; oldestTimestamp: number | null; newestTimestamp: number | null }>;
}

interface JWKSKey {
  kty: string;
  use: string;
  kid: string;
  x5c: string[];
  n: string;
  e: string;
  alg: string;
}

interface JWKS {
  keys: JWKSKey[];
}

interface JWTHeader {
  alg: string;
  typ: string;
  kid: string;
}

interface JWTPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  scope?: string;
  "https://v2-bigscoots.com/role"?: string;
  "https://v2-bigscoots.com/email"?: string;
  "https://v2-bigscoots.com/email_verified"?: boolean;
}

interface AuthError {
  error: string;
  error_description: string;
  status: number;
}

interface HMACHeaders {
  keyId: string;
  timestamp: string;
  nonce: string;
  signature: string;
  contentSHA256: string;
}

interface APIKeyMetadata {
  secret: string;
  orgId: string;
  scopes: string[];
  rateLimit?: {
    minute: number;
    hour: number;
    day: number;
  };
}

interface HMACPayload {
  keyId: string;
  orgId: string;
  scopes: string[];
}

// Public routes that bypass authentication
const PUBLIC_ROUTES: string[] = [];

// HMAC Configuration
const CLOCK_SKEW_SECONDS = 300; // ±5 minutes
const SIGNED_HEADERS = ['host', 'content-type']; // Headers included in signature
const NONCE_TTL = 300000; // 5 minutes in milliseconds

// Nonce tracking now handled by Durable Objects (NonceReplayGuard class)

// Global JWKS cache (simple in-memory for now)
let jwksCache: JWKS | null = null;
let jwksCacheTime = 0;
const JWKS_CACHE_TTL = 3600000; // 1 hour in milliseconds

/**
 * JWT Step 1: Fetch and cache JWKS from Auth0
 * 
 * Downloads RSA public keys from Auth0's JWKS endpoint and caches them for 1 hour.
 * JWKS (JSON Web Key Set) contains the public keys needed to verify JWT signatures.
 * 
 * @param jwksUrl - Auth0 JWKS endpoint URL (e.g., "https://dev-xyz.auth0.com/.well-known/jwks.json")
 * @returns Promise resolving to JWKS containing RSA public keys
 * 
 * @example
 * const jwks = await fetchJWKS("https://dev-xyz.auth0.com/.well-known/jwks.json");
 * // Returns: { keys: [{ kid: "abc123", kty: "RSA", n: "...", e: "AQAB" }] }
 */
async function fetchJWKS(jwksUrl: string): Promise<JWKS> {
  const now = Date.now();
  
  // Return cached JWKS if still valid
  if (jwksCache && (now - jwksCacheTime) < JWKS_CACHE_TTL) {
    return jwksCache;
  }

  try {
    const response = await fetch(jwksUrl);
    if (!response.ok) {
      throw new Error(`JWKS fetch failed: ${response.status}`);
    }
    
    jwksCache = await response.json() as JWKS;
    jwksCacheTime = now;
    
    console.log("🔐 [JWKS] Successfully fetched and cached JWKS");
    return jwksCache;
  } catch (error) {
    console.error("❌ [JWKS] Failed to fetch JWKS:", error);
    throw error;
  }
}

/**
 * JWT Step 2: Find matching public key by key ID
 * 
 * Searches through JWKS keys to find the one with matching 'kid' (key ID) from JWT header.
 * Each JWT header contains a 'kid' field that identifies which key was used to sign it.
 * 
 * @param jwks - JWKS object containing array of public keys
 * @param kid - Key ID from JWT header (e.g., "9E5ZC9HGi1BFyjH49M5OU")
 * @returns Matching JWK or null if not found
 * 
 * @example
 * const jwk = findJWKByKid(jwks, "9E5ZC9HGi1BFyjH49M5OU");
 * // Returns: { kid: "9E5ZC9HGi1BFyjH49M5OU", kty: "RSA", n: "...", e: "AQAB" }
 */
function findJWKByKid(jwks: JWKS, kid: string): JWKSKey | null {
  return jwks.keys.find(key => key.kid === kid) || null;
}

/**
 * JWT Step 3: Convert JWK to WebCrypto key for verification
 * 
 * Transforms Auth0's JWK format into a WebCrypto CryptoKey object that can verify RS256 signatures.
 * Configures the key specifically for RSASSA-PKCS1-v1_5 with SHA-256 hashing.
 * 
 * @param jwk - JSON Web Key with RSA components (n, e, kty, alg)
 * @returns Promise resolving to CryptoKey for signature verification
 */
async function jwkToCryptoKey(jwk: JWKSKey): Promise<CryptoKey> {
  const keyData = {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: jwk.alg,
    use: jwk.use,
  };

  return await crypto.subtle.importKey(
    "jwk",
    keyData,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["verify"]
  );
}

/**
 * JWT Step 4: Decode JWT token without verification
 * 
 * Splits JWT into header and payload parts and base64url decodes them for inspection.
 * Does NOT verify signature - only extracts data for subsequent validation steps.
 * 
 * @param token - Complete JWT string (header.payload.signature)
 * @returns Object with decoded header and payload
 * 
 * @example
 * const { header, payload } = decodeJWT("eyJhbGc...header.eyJpc3M...payload.signature");
 * // Returns: { header: { alg: "RS256", kid: "abc123" }, payload: { sub: "user123", exp: 1234567890 } }
 */
function decodeJWT(token: string): { header: JWTHeader; payload: JWTPayload } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  try {
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'))) as JWTHeader;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))) as JWTPayload;
    
    return { header, payload };
  } catch (error) {
    throw new Error("Invalid JWT encoding");
  }
}

/**
 * JWT Step 5: Verify JWT signature using WebCrypto
 * 
 * Cryptographically verifies that the JWT signature matches the header+payload using RSA public key.
 * Protects against token tampering by ensuring signature was created with the private key.
 * 
 * @param token - Complete JWT string
 * @param publicKey - RSA public key (from jwkToCryptoKey)
 * @returns Promise resolving to true if signature is valid, false otherwise
 */
async function verifyJWTSignature(token: string, publicKey: CryptoKey): Promise<boolean> {
  const parts = token.split('.');
  const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  
  // Decode signature from base64url
  const signature = Uint8Array.from(
    atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), 
    c => c.charCodeAt(0)
  );

  try {
    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signature,
      data
    );
  } catch (error) {
    console.error("❌ [JWT] Signature verification failed:", error);
    return false;
  }
}

/**
 * JWT Step 6: Validate JWT claims (security checks)
 * 
 * Verifies standard JWT claims to prevent security vulnerabilities:
 * - exp: Token not expired
 * - iss: Token issued by trusted Auth0 tenant
 * - aud: Token intended for our API
 * 
 * @param payload - Decoded JWT payload
 * @param expectedIssuer - Our Auth0 issuer URL
 * @param expectedAudience - Our API identifier
 * @throws Error if any claim validation fails
 */
function validateJWTClaims(payload: JWTPayload, expectedIssuer: string, expectedAudience: string): void {
  const now = Math.floor(Date.now() / 1000);

  // Check expiration
  if (payload.exp <= now) {
    throw new Error("Token has expired");
  }

  // Check issuer
  if (payload.iss !== expectedIssuer) {
    throw new Error(`Invalid issuer. Expected: ${expectedIssuer}, Got: ${payload.iss}`);
  }

  // Check audience
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(expectedAudience)) {
    throw new Error(`Invalid audience. Expected: ${expectedAudience}, Got: ${audiences.join(', ')}`);
  }
}

/**
 * JWT Main Function: Complete JWT validation pipeline
 * 
 * Orchestrates the full JWT verification process from token to validated user data.
 * Combines all JWT steps: decode → find key → verify signature → validate claims.
 * 
 * @param token - Raw JWT from Authorization header
 * @param env - Worker environment with Auth0 configuration
 * @returns Promise resolving to validated JWT payload with user data
 * @throws Error if any validation step fails
 */
async function validateJWT(token: string, env: Env): Promise<JWTPayload> {
  try {
    // Decode JWT to get header and payload
    const { header, payload } = decodeJWT(token);

    // Validate algorithm
    if (header.alg !== "RS256") {
      throw new Error(`Unsupported algorithm: ${header.alg}`);
    }

    // Fetch JWKS and find matching key
    const jwks = await fetchJWKS(env.JWKS_URL);
    const jwk = findJWKByKid(jwks, header.kid);
    
    if (!jwk) {
      throw new Error(`No matching key found for kid: ${header.kid}`);
    }

    // Convert JWK to CryptoKey
    const publicKey = await jwkToCryptoKey(jwk);

    // Verify signature
    const isValidSignature = await verifyJWTSignature(token, publicKey);
    if (!isValidSignature) {
      throw new Error("Invalid JWT signature");
    }

    // Validate claims
    validateJWTClaims(payload, env.AUTH0_ISSUER, env.AUTH0_AUDIENCE);

    console.log(`✅ [JWT] Token validated for user: ${payload.sub}`);
    return payload;

  } catch (error) {
    console.error("❌ [JWT] Validation failed:", error);
    throw error;
  }
}

/**
 * JWT Utility: Parse space-separated scope string into array
 * 
 * Converts OAuth2 scope string format into array for easier processing.
 * Handles empty/missing scope strings gracefully.
 * 
 * @param scope - Space-separated scope string from JWT (e.g., "read write admin")
 * @returns Array of individual scope strings
 * 
 * @example
 * const scopes = parseScopes("sites:read users:write billing:admin");
 * // Returns: ["sites:read", "users:write", "billing:admin"]
 */
function parseScopes(scope?: string): string[] {
  if (!scope) return [];
  return scope.split(' ').filter(s => s.length > 0);
}

/**
 * Auth Utility: Create standardized JSON error response
 * 
 * Generates consistent error responses with proper HTTP status codes and JSON format.
 * Used for both JWT and HMAC authentication failures.
 * 
 * @param error - Error code (e.g., "invalid_token", "unauthorized")
 * @param description - Human-readable error description
 * @param status - HTTP status code (401, 403, 429, etc.)
 * @returns Response object with JSON error body and appropriate headers
 * 
 * @example
 * return createErrorResponse("invalid_token", "JWT signature verification failed", 401);
 * // Returns: Response with {"error":"invalid_token","error_description":"...","status":401}
 */
function createErrorResponse(error: string, description: string, status: number): Response {
  const errorBody: AuthError = {
    error,
    error_description: description,
    status
  };

  return new Response(JSON.stringify(errorBody), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

/**
 * Route Utility: Check if route bypasses authentication
 * 
 * Determines whether a request path should skip JWT/HMAC validation.
 * Useful for health checks, documentation, and public endpoints.
 * 
 * @param pathname - Request path from URL (e.g., "/health", "/api/docs")
 * @returns true if route is public, false if authentication required
 * 
 * @example
 * const isPublic = isPublicRoute("/health");
 * // Returns: true (if "/health" is in PUBLIC_ROUTES array)
 */
function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some(route => pathname.startsWith(route));
}

/**
 * Auth Detection: Determine authentication method from request headers
 * 
 * Examines request headers to identify whether client is using JWT or HMAC authentication.
 * Enables dual authentication support on the same endpoints.
 * 
 * @param request - HTTP request object
 * @returns 'jwt' if Authorization header present, 'hmac' if X-Key-Id present, 'none' otherwise
 * 
 * @example
 * const authMethod = detectAuthMethod(request);
 * // Returns: "jwt", "hmac", or "none"
 */
function detectAuthMethod(request: Request): 'jwt' | 'hmac' | 'none' {
  const authHeader = request.headers.get('Authorization');
  const keyIdHeader = request.headers.get('X-Key-Id');
  
  console.log(`🔍 [AUTH-DETECT] Authorization header: ${authHeader ? 'present' : 'missing'}`);
  console.log(`🔍 [AUTH-DETECT] X-Key-Id header: ${keyIdHeader ? keyIdHeader : 'missing'}`);

  if (authHeader && authHeader.startsWith('Bearer ')) {
    console.log(`✅ [AUTH-DETECT] Detected JWT authentication`);
    return 'jwt';
  } else if (keyIdHeader) {
    console.log(`✅ [AUTH-DETECT] Detected HMAC authentication with keyId: ${keyIdHeader}`);
    return 'hmac';
  }
  
  console.log(`❌ [AUTH-DETECT] No authentication method detected`);
  return 'none';
}

/**
 * JWT Utility: Extract Bearer token from Authorization header
 * 
 * Parses Authorization header to extract JWT token, removing "Bearer " prefix.
 * Returns null if header is missing or doesn't follow Bearer token format.
 * 
 * @param request - HTTP request object
 * @returns JWT token string or null if not found/invalid format
 * 
 * @example
 * const token = extractJWTToken(request);
 * // Returns: "eyJhbGciOiJSUzI1NiIs..." (without "Bearer " prefix)
 */
function extractJWTToken(request: Request): string | null {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  return authHeader.slice(7); // Remove 'Bearer ' prefix
}

// cleanupExpiredNonces function removed - now handled automatically by Durable Objects

// checkAndStoreNonce function removed - now handled by NonceReplayGuard Durable Object

/**
 * HMAC Step 1: Extract required HMAC headers from request
 * 
 * Validates presence of all 5 required HMAC headers for signature verification.
 * Returns null if any header is missing, preventing incomplete validation attempts.
 * 
 * @param request - Incoming HTTP request
 * @returns HMACHeaders object or null if any required header is missing
 * 
 * @example
 * const headers = extractHMACHeaders(request);
 * // Returns: { keyId: "live_org_test123", timestamp: "1727712000", nonce: "uuid...", signature: "base64...", contentSHA256: "UNSIGNED-PAYLOAD" }
 */
function extractHMACHeaders(request: Request): HMACHeaders | null {
  console.log(`🔍 [HMAC-HEADERS] Starting header extraction`);
  
  const keyId = request.headers.get('X-Key-Id');
  const timestamp = request.headers.get('X-Timestamp');
  const nonce = request.headers.get('X-Nonce');
  const signature = request.headers.get('X-Signature');
  const contentSHA256 = request.headers.get('X-Content-SHA256');

  console.log(`🔍 [HMAC-HEADERS] X-Key-Id: ${keyId || 'MISSING'}`);
  console.log(`🔍 [HMAC-HEADERS] X-Timestamp: ${timestamp || 'MISSING'}`);
  console.log(`🔍 [HMAC-HEADERS] X-Nonce: ${nonce || 'MISSING'}`);
  console.log(`🔍 [HMAC-HEADERS] X-Signature: ${signature ? 'present' : 'MISSING'}`);
  console.log(`🔍 [HMAC-HEADERS] X-Content-SHA256: ${contentSHA256 || 'MISSING'}`);

  if (!keyId || !timestamp || !nonce || !signature || !contentSHA256) {
    console.log(`❌ [HMAC-HEADERS] Missing required headers - validation failed`);
    return null;
  }

  console.log(`✅ [HMAC-HEADERS] All required headers present`);
  return { keyId, timestamp, nonce, signature, contentSHA256 };
}

/**
 * HMAC Step 2: Validate request timestamp freshness
 * 
 * Ensures request was signed within ±300 seconds (5 minutes) of current time.
 * Prevents old signed requests from being replayed hours or days later.
 * 
 * @param timestamp - Unix timestamp string from X-Timestamp header
 * @returns true if timestamp is within acceptable window, false if too old/new
 * 
 * @example
 * const isValid = validateTimestamp("1727712000");
 * // Returns: true (within ±300s) or false (too old/new)
 */
function validateTimestamp(timestamp: string): boolean {
  const now = Math.floor(Date.now() / 1000);
  const requestTime = parseInt(timestamp, 10);
  
  console.log(`⏰ [TIMESTAMP] Current time: ${now}, Request time: ${requestTime}`);
  
  if (isNaN(requestTime)) {
    console.log(`❌ [TIMESTAMP] Invalid timestamp format: ${timestamp}`);
    return false;
  }
  
  const diff = Math.abs(now - requestTime);
  console.log(`⏰ [TIMESTAMP] Time difference: ${diff}s (max allowed: ${CLOCK_SKEW_SECONDS}s)`);
  
  const isValid = diff <= CLOCK_SKEW_SECONDS;
  console.log(`${isValid ? '✅' : '❌'} [TIMESTAMP] Timestamp validation: ${isValid ? 'PASSED' : 'FAILED'}`);
  
  return isValid;
}

/**
 * HMAC Step 3: Build canonical string for signature verification
 * 
 * Constructs the exact string that was signed by the client, following strict format:
 * METHOD\nPATH\nQUERY\nSIGNED-HEADERS\nTIMESTAMP\nNONCE\nBODY-HASH
 * Must match client's canonical string exactly or signature verification fails.
 * 
 * @param request - HTTP request object
 * @param timestamp - Request timestamp
 * @param nonce - Request nonce
 * @param contentSHA256 - Body hash or "UNSIGNED-PAYLOAD"
 * @returns Promise resolving to canonical string for HMAC verification
 * 
 * @example
 * const canonical = await buildCanonicalString(request, "1727712000", "uuid...", "UNSIGNED-PAYLOAD");
 * // Returns: "POST\n/api/test\nquery=value\ncontent-type:application/json\nhost:api.example.com\n1727712000\nuuid...\nUNSIGNED-PAYLOAD"
 */
async function buildCanonicalString(
  request: Request, 
  timestamp: string, 
  nonce: string, 
  contentSHA256: string
): Promise<string> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const path = url.pathname;
  
  // Sort query parameters
  const sortedQuery = Array.from(url.searchParams.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');

  // Build signed headers (lowercase and sorted)
  const signedHeaderLines: string[] = [];
  for (const headerName of SIGNED_HEADERS.sort()) {
    const headerValue = request.headers.get(headerName) || '';
    signedHeaderLines.push(`${headerName.toLowerCase()}:${headerValue}`);
  }

  // Canonical string format (each line separated by newline)
  const canonicalString = [
    method,
    path,
    sortedQuery,
    ...signedHeaderLines,
    timestamp,
    nonce,
    contentSHA256
  ].join('\n');

  return canonicalString;
}

/**
 * HMAC Step 4: Verify HMAC-SHA256 signature using WebCrypto
 * 
 * Cryptographically verifies that the signature was created using the secret key.
 * Uses HMAC-SHA256 algorithm to ensure request authenticity and integrity.
 * 
 * @param canonicalString - Reconstructed canonical string
 * @param signature - Base64 signature from X-Signature header
 * @param secret - API key secret from KV storage
 * @returns Promise resolving to true if signature is valid, false otherwise
 */
async function verifyHMACSignature(
  canonicalString: string, 
  signature: string, 
  secret: string
): Promise<boolean> {
  try {
    // Import secret as HMAC key
    const keyData = new TextEncoder().encode(secret);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // Decode signature from base64
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const canonicalBytes = new TextEncoder().encode(canonicalString);

    // Verify signature
    return await crypto.subtle.verify('HMAC', cryptoKey, signatureBytes, canonicalBytes);
  } catch (error) {
    console.error('❌ [HMAC] Signature verification failed:', error);
    return false;
  }
}

/**
 * HMAC Utility: Compute SHA256 hash of request body
 * 
 * Calculates SHA256 hash of raw request body bytes for integrity verification.
 * For GET/DELETE/HEAD requests, returns "UNSIGNED-PAYLOAD" per our policy.
 * 
 * @param request - HTTP request object
 * @returns Promise resolving to hex SHA256 hash or "UNSIGNED-PAYLOAD"
 * 
 * @example
 * const hash = await computeBodyHash(request);
 * // Returns: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3" or "UNSIGNED-PAYLOAD"
 */
async function computeBodyHash(request: Request): Promise<string> {
  console.log(`🔐 [BODY-HASH] Computing hash for ${request.method} request`);
  
  // For GET/DELETE methods with no body, use UNSIGNED-PAYLOAD
  if (['GET', 'DELETE', 'HEAD'].includes(request.method.toUpperCase()) || !request.body) {
    console.log(`🔐 [BODY-HASH] Method ${request.method} - using UNSIGNED-PAYLOAD`);
    return 'UNSIGNED-PAYLOAD';
  }

  try {
    console.log(`🔐 [BODY-HASH] Method ${request.method} - computing SHA256 of body`);
    // Clone request to read body without consuming original
    const clonedRequest = request.clone();
    const bodyBytes = await clonedRequest.arrayBuffer();
    console.log(`🔐 [BODY-HASH] Body size: ${bodyBytes.byteLength} bytes`);
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes);
    
    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    console.log(`🔐 [BODY-HASH] Computed hash: ${hash}`);
    
    return hash;
  } catch (error) {
    console.error('❌ [HMAC] Body hash computation failed:', error);
    throw new Error('Failed to compute body hash');
  }
}

/**
 * HMAC Main Function: Complete HMAC validation pipeline
 * 
 * Orchestrates the full HMAC verification process from headers to validated client data.
 * Combines all HMAC steps: extract headers → validate timestamp → check nonce (via Durable Objects) → verify body → lookup secret → verify signature.
 * 
 * Uses Durable Objects for global nonce replay protection across all worker instances.
 * 
 * @param request - HTTP request with HMAC headers
 * @param env - Worker environment with KV access and Durable Object bindings
 * @returns Promise resolving to validated client metadata (keyId, orgId, scopes)
 * @throws Error if any validation step fails
 */
async function validateHMAC(request: Request, env: Env): Promise<HMACPayload> {
  try {
    console.log(`🚀 [HMAC-VALIDATE] Starting HMAC validation pipeline`);
    
    // 1. Extract HMAC headers
    console.log(`📋 [HMAC-VALIDATE] Step 1: Extracting HMAC headers`);
    const hmacHeaders = extractHMACHeaders(request);
    if (!hmacHeaders) {
      throw new Error('Missing required HMAC headers');
    }
    console.log(`✅ [HMAC-VALIDATE] Step 1 complete: Headers extracted successfully`);

    console.log(`🔍 [HMAC-VALIDATE] Validating request from key: ${hmacHeaders.keyId}`);

    // 2. Validate timestamp freshness
    console.log(`⏰ [HMAC-VALIDATE] Step 2: Validating timestamp freshness`);
    if (!validateTimestamp(hmacHeaders.timestamp)) {
      throw new Error('Request timestamp is outside acceptable window (±300s)');
    }
    console.log(`✅ [HMAC-VALIDATE] Step 2 complete: Timestamp is fresh`);

    // 3. Check nonce uniqueness (replay protection) using Durable Object
    console.log(`🔄 [HMAC-VALIDATE] Step 3: Checking nonce uniqueness via Durable Object`);
    const nonceTrackerId = env.NONCE_TRACKER.idFromName(`nonce-${hmacHeaders.keyId}`);
    const nonceTracker = env.NONCE_TRACKER.get(nonceTrackerId) as unknown as NonceReplayGuardStub;
    const isNonceUnique = await nonceTracker.checkAndStore(hmacHeaders.nonce, parseInt(hmacHeaders.timestamp, 10));
    
    if (!isNonceUnique) {
      throw new Error('Nonce has already been used (replay attack detected)');
    }
    console.log(`✅ [HMAC-VALIDATE] Step 3 complete: Nonce is unique and stored in DO`);

    // 4. Verify body hash
    console.log(`🔐 [HMAC-VALIDATE] Step 4: Computing and verifying body hash`);
    const computedBodyHash = await computeBodyHash(request);
    console.log(`🔐 [HMAC-VALIDATE] Computed hash: ${computedBodyHash}`);
    console.log(`🔐 [HMAC-VALIDATE] Expected hash: ${hmacHeaders.contentSHA256}`);
    if (computedBodyHash !== hmacHeaders.contentSHA256) {
      throw new Error(`Body hash mismatch. Expected: ${hmacHeaders.contentSHA256}, Got: ${computedBodyHash}`);
    }
    console.log(`✅ [HMAC-VALIDATE] Step 4 complete: Body hash matches`);

    // 5. Fetch API key metadata from KV
    console.log(`🗄️ [HMAC-VALIDATE] Step 5: Fetching API key from KV storage`);
    console.log(`🗄️ [HMAC-VALIDATE] Looking up key: api_key:${hmacHeaders.keyId}`);
    console.log(`🗄️ [HMAC-VALIDATE] KV namespace available: ${env.KV ? 'YES' : 'NO'}`);
    
    const keyData = await env.KV.get(`api_key:${hmacHeaders.keyId}`, { type: 'json' }) as APIKeyMetadata | null;
    
    console.log(`🗄️ [HMAC-VALIDATE] KV lookup result: ${keyData ? 'FOUND' : 'NOT FOUND'}`);
    if (keyData) {
      console.log(`🗄️ [HMAC-VALIDATE] Key data orgId: ${keyData.orgId}`);
      console.log(`🗄️ [HMAC-VALIDATE] Key data scopes: ${JSON.stringify(keyData.scopes)}`);
      console.log(`🗄️ [HMAC-VALIDATE] Secret present: ${keyData.secret ? 'YES' : 'NO'}`);
    }
    
    if (!keyData) {
      throw new Error(`API key not found: ${hmacHeaders.keyId}`);
    }
    console.log(`✅ [HMAC-VALIDATE] Step 5 complete: API key found in KV`);

    // 6. Build canonical string
    console.log(`📝 [HMAC-VALIDATE] Step 6: Building canonical string`);
    const canonicalString = await buildCanonicalString(
      request, 
      hmacHeaders.timestamp, 
      hmacHeaders.nonce, 
      hmacHeaders.contentSHA256
    );
    console.log(`📝 [HMAC-VALIDATE] Canonical string built (${canonicalString.length} chars)`);
    console.log(`🔐 [HMAC] Canonical string:\n${canonicalString}`);
    console.log(`✅ [HMAC-VALIDATE] Step 6 complete: Canonical string ready`);

    // 7. Verify HMAC signature
    console.log(`🔏 [HMAC-VALIDATE] Step 7: Verifying HMAC signature`);
    console.log(`🔏 [HMAC-VALIDATE] Received signature: ${hmacHeaders.signature}`);
    console.log(`🔏 [HMAC-VALIDATE] Using secret length: ${keyData.secret.length} chars`);
    
    const isValidSignature = await verifyHMACSignature(
      canonicalString, 
      hmacHeaders.signature, 
      keyData.secret
    );
    
    console.log(`🔏 [HMAC-VALIDATE] Signature verification result: ${isValidSignature ? 'VALID' : 'INVALID'}`);

    if (!isValidSignature) {
      throw new Error('HMAC signature verification failed');
    }
    console.log(`✅ [HMAC-VALIDATE] Step 7 complete: Signature verified`);

    console.log(`🎉 [HMAC-VALIDATE] All steps complete - HMAC validation successful`);
    console.log(`✅ [HMAC] Request validated for key: ${hmacHeaders.keyId}, org: ${keyData.orgId}`);

    return {
      keyId: hmacHeaders.keyId,
      orgId: keyData.orgId,
      scopes: keyData.scopes
    };

  } catch (error) {
    console.error('❌ [HMAC] Validation failed:', error);
    throw error;
  }
}

/**
 * JWT Identity: Create authenticated request with identity headers
 * 
 * Transforms JWT-authenticated request for backend by removing Authorization header
 * and injecting standardized identity headers (X-Auth-Type, X-User-Id, X-Org-Id, X-Scopes).
 * 
 * @param originalRequest - Original client request
 * @param targetUrl - Backend service URL
 * @param payload - Validated JWT payload
 * @returns New request with identity headers for backend consumption
 */
function createAuthenticatedRequest(
  originalRequest: Request, 
  targetUrl: string, 
  payload: JWTPayload
): Request {
  // Parse scopes from the standard scope field
  const scopes = parseScopes(payload.scope);

  // Create new headers with identity information
  const newHeaders = new Headers(originalRequest.headers);
  
  // Remove original auth header and add identity headers
  newHeaders.delete('Authorization');
  newHeaders.set('X-Auth-Type', 'jwt');
  newHeaders.set('X-User-Id', payload.sub);
  newHeaders.set('X-Client-Id', payload.sub);
  newHeaders.set('X-Org-Id', 'null'); // Normal users don't have org_id
  newHeaders.set('X-Scopes', JSON.stringify(scopes));
  
  // Add custom claims if present
  if (payload["https://v2-bigscoots.com/role"]) {
    newHeaders.set('X-Role', payload["https://v2-bigscoots.com/role"]);
  }
  
  if (payload["https://v2-bigscoots.com/email"]) {
    newHeaders.set('X-Email', payload["https://v2-bigscoots.com/email"]);
  }

  return new Request(targetUrl, {
    method: originalRequest.method,
    headers: newHeaders,
    body: originalRequest.body,
  });
}

/**
 * HMAC Identity: Create authenticated request with identity headers
 * 
 * Transforms HMAC-authenticated request for backend by removing HMAC headers
 * and injecting standardized identity headers (X-Auth-Type, X-Client-Id, X-Org-Id, X-Scopes).
 * 
 * @param originalRequest - Original client request
 * @param targetUrl - Backend service URL  
 * @param payload - Validated HMAC payload
 * @returns New request with identity headers for backend consumption
 */
function createHMACAuthenticatedRequest(
  originalRequest: Request,
  targetUrl: string,
  payload: HMACPayload
): Request {
  // Create new headers with identity information
  const newHeaders = new Headers(originalRequest.headers);
  
  // Remove HMAC headers and add identity headers
  newHeaders.delete('X-Key-Id');
  newHeaders.delete('X-Timestamp');
  newHeaders.delete('X-Nonce');
  newHeaders.delete('X-Signature');
  newHeaders.delete('X-Content-SHA256');
  
  // Add identity headers
  newHeaders.set('X-Auth-Type', 'hmac');
  newHeaders.set('X-Client-Id', payload.keyId);
  newHeaders.set('X-Org-Id', payload.orgId);
  newHeaders.set('X-Scopes', JSON.stringify(payload.scopes));

  return new Request(targetUrl, {
    method: originalRequest.method,
    headers: newHeaders,
    body: originalRequest.body,
  });
}

/**
 * Durable Object: Nonce Replay Guard for HMAC Authentication
 * 
 * Prevents replay attacks by tracking used nonces per API key.
 * Each API key gets its own DO instance for isolated, scalable nonce tracking.
 * Automatically cleans up expired nonces to prevent memory bloat.
 */
export class NonceReplayGuard extends DurableObject<Env> {
  private nonces: Map<string, number>;
  private cleanupInterval: number | null;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.nonces = new Map();
    this.cleanupInterval = null;
    
    // Start cleanup timer when DO is created
    this.startCleanupTimer();
  }

  /**
   * Check if nonce is unique and store it if valid
   * 
   * @param nonce - UUID nonce from request
   * @param timestamp - Request timestamp for expiration tracking
   * @returns true if nonce is unique (allowed), false if replay detected
   */
  async checkAndStore(nonce: string, timestamp: number): Promise<boolean> {
    const now = Date.now();
    const requestTime = timestamp * 1000; // Convert to milliseconds
    
    console.log(`🔄 [NONCE-DO] Checking nonce for timestamp ${timestamp}, current active: ${this.nonces.size}`);
    
    // Check if nonce already exists (replay attack)
    if (this.nonces.has(nonce)) {
      console.log(`❌ [NONCE-DO] Replay attack detected - nonce already used: ${nonce.substring(0, 8)}...`);
      return false;
    }
    
    // Store the nonce with its timestamp
    this.nonces.set(nonce, requestTime);
    console.log(`✅ [NONCE-DO] Nonce stored successfully, total active: ${this.nonces.size}`);
    
    return true;
  }

  /**
   * Get statistics about current nonce storage (for monitoring)
   */
  async getStats(): Promise<{ activeNonces: number; oldestTimestamp: number | null; newestTimestamp: number | null }> {
    const timestamps = Array.from(this.nonces.values());
    return {
      activeNonces: this.nonces.size,
      oldestTimestamp: timestamps.length > 0 ? Math.min(...timestamps) : null,
      newestTimestamp: timestamps.length > 0 ? Math.max(...timestamps) : null
    };
  }

  /**
   * Start automatic cleanup timer to remove expired nonces
   */
  private startCleanupTimer(): void {
    // Clean up every 2 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 120000) as any; // 2 minutes
  }

  /**
   * Remove expired nonces from memory
   * Called automatically every 2 minutes to prevent memory bloat
   */
  private cleanup(): void {
    const now = Date.now();
    const initialSize = this.nonces.size;
    let removedCount = 0;

    for (const [nonce, timestamp] of this.nonces.entries()) {
      // Remove nonces older than 5 minutes (NONCE_TTL)
      if (now - timestamp > NONCE_TTL) {
        this.nonces.delete(nonce);
        removedCount++;
      }
    }

    if (removedCount > 0) {
      console.log(`🧹 [NONCE-DO] Cleanup completed: removed ${removedCount} expired nonces (${initialSize} → ${this.nonces.size})`);
    }
  }

  /**
   * Cleanup resources when DO is being destroyed
   */
  async alarm(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

/**
 * Main Worker Handler: Dual authentication and request routing
 * 
 * Entry point for all requests. Handles both JWT and HMAC authentication on the same endpoints.
 * Routes authenticated requests to backend services with injected identity headers.
 * 
 * Flow: Detect auth method → Validate credentials → Inject headers → Forward to backend
 * 
 * @param request - Incoming HTTP request
 * @param env - Worker environment variables and bindings
 * @param ctx - Execution context for background tasks
 * @returns Promise resolving to HTTP response
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	  const { method, url } = request;
	  const parsedUrl = new URL(url);
  
    // Request logging
	  console.log(
		`🟢 [REQUEST] ${method} ${parsedUrl.pathname} @ ${new Date().toISOString()}`
	  );
  
    try {
      // Handle built-in test routes FIRST (no auth required)
      if (parsedUrl.pathname === "/hi") {
        console.log("🔓 [AUTH] Built-in test route - bypassing authentication");
        const response = new Response("👋 Hi from BigScoots Worker!");
        console.log(
          `🔵 [RESPONSE] ${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`
        );
        return response;
      }
      
      if (parsedUrl.pathname === "/json") {
        console.log("🔓 [AUTH] Built-in test route - bypassing authentication");
        const response = new Response(JSON.stringify({ message: "Hello JSON" }), {
		  headers: { "Content-Type": "application/json" },
		});
        console.log(
          `🔵 [RESPONSE] ${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`
        );
        return response;
      }

      // Check if route is public (bypass auth)
      if (isPublicRoute(parsedUrl.pathname)) {
        console.log("🔓 [AUTH] Public route - bypassing authentication");
        // TODO: Route to appropriate service when microservices are ready
        // For now, continue to external API
	  } else {
        // Authentication required for all other routes
        const authMethod = detectAuthMethod(request);
        console.log(`🔍 [AUTH] Detected auth method: ${authMethod}`);

        if (authMethod === 'none') {
          return createErrorResponse(
            'unauthorized',
            'Authentication required. Provide either Bearer token or API key.',
            401
          );
        }

        if (authMethod === 'jwt') {
          // Extract and validate JWT
          const token = extractJWTToken(request);
          if (!token) {
            return createErrorResponse(
              'invalid_token',
              'Bearer token is required but not provided',
              401
            );
          }

          // Validate JWT
          const payload = await validateJWT(token, env);
          console.log("✅ [AUTH] JWT authentication successful");

          // Create authenticated request for downstream services
          const externalUrl = "https://kfs-p2-be.ss1.septemsystems.com/api/v1/app/hello";
          const authenticatedRequest = createAuthenticatedRequest(request, externalUrl, payload);
          
          // Forward the request
          console.log("🌐 [ROUTING] Forwarding authenticated request to external API");
          const response = await fetch(authenticatedRequest);
          
          console.log(
            `📤 [EXTERNAL] ${externalUrl} -> ${response.status} @ ${new Date().toISOString()}`
          );
          
          return response;

        } else if (authMethod === 'hmac') {
          console.log("🚀 [AUTH] Starting HMAC authentication process");
          console.log(`🔑 [AUTH] Request URL: ${request.url}`);
          console.log(`🔑 [AUTH] Request method: ${request.method}`);
          
          // Validate HMAC signed request
          const payload = await validateHMAC(request, env);
          console.log("✅ [AUTH] HMAC authentication successful");
          console.log(`✅ [AUTH] Authenticated client: ${payload.keyId} (org: ${payload.orgId})`);

          // Create authenticated request for downstream services
          const externalUrl = "https://kfs-p2-be.ss1.septemsystems.com/api/v1/app/hello";
          const authenticatedRequest = createHMACAuthenticatedRequest(request, externalUrl, payload);
          
          // Forward the request
          console.log("🌐 [ROUTING] Forwarding HMAC authenticated request to external API");
          const response = await fetch(authenticatedRequest);
          
          console.log(
            `📤 [EXTERNAL] ${externalUrl} -> ${response.status} @ ${new Date().toISOString()}`
          );
          
          return response;
        }
      }

      // Default route to external API (requires auth)
      console.log("🌐 [ROUTING] Forwarding to external API (default route)");
      
      const externalUrl = "https://kfs-p2-be.ss1.septemsystems.com/api/v1/app/hello";
      const externalRequest = new Request(externalUrl, {
        method: request.method,
        headers: request.headers,
        body: request.body,
      });
      
      const response = await fetch(externalRequest);
      
      console.log(
        `📤 [EXTERNAL] ${externalUrl} -> ${response.status} @ ${new Date().toISOString()}`
      );
      
	  console.log(
		`🔵 [RESPONSE] ${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`
	  );
  
	  return response;

    } catch (error) {
      console.error("❌ [ERROR] Request processing failed:", error);
      
      console.error("❌ [ERROR] Request processing failed:", error);
      
      // Handle authentication errors
      if (error instanceof Error) {
        console.error(`❌ [ERROR] Error type: ${error.constructor.name}`);
        console.error(`❌ [ERROR] Error message: ${error.message}`);
        
        // JWT errors
        if (error.message.includes('expired')) {
          console.error(`❌ [ERROR] JWT token expired`);
          return createErrorResponse('token_expired', error.message, 401);
        }
        if (error.message.includes('Invalid')) {
          console.error(`❌ [ERROR] Invalid JWT token`);
          return createErrorResponse('invalid_token', error.message, 401);
        }
        
        // HMAC errors
        if (error.message.includes('timestamp') || error.message.includes('replay')) {
          console.error(`❌ [ERROR] HMAC timestamp/replay error`);
          return createErrorResponse('invalid_request', error.message, 401);
        }
        if (error.message.includes('HMAC') || error.message.includes('signature')) {
          console.error(`❌ [ERROR] HMAC signature verification failed`);
          return createErrorResponse('invalid_signature', error.message, 401);
        }
        if (error.message.includes('API key not found')) {
          console.error(`❌ [ERROR] API key not found in KV storage`);
          return createErrorResponse('invalid_key', error.message, 401);
        }
      }

      // Generic server error
      return createErrorResponse(
        'internal_server_error',
        'An unexpected error occurred',
        500
      );
    }
	},
  } satisfies ExportedHandler<Env>;
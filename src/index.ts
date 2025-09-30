// bigscoots-v2-gateway-test
// JWT Authentication Gateway for BigScoots API

interface Env {
  AUTH0_ISSUER: string;
  AUTH0_AUDIENCE: string;
  JWKS_URL: string;
  KV: KVNamespace;
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

// In-memory nonce tracking (per worker instance)
// NOTE: Move to Durable Objects for global nonce tracking
const usedNonces = new Map<string, number>(); // nonce -> timestamp

// Global JWKS cache (simple in-memory for now)
let jwksCache: JWKS | null = null;
let jwksCacheTime = 0;
const JWKS_CACHE_TTL = 3600000; // 1 hour in milliseconds

/**
 * Fetch and cache JWKS from Auth0
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
 * Find JWK by kid
 */
function findJWKByKid(jwks: JWKS, kid: string): JWKSKey | null {
  return jwks.keys.find(key => key.kid === kid) || null;
}

/**
 * Convert JWK to CryptoKey for verification
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
 * Decode JWT without verification (for header/payload inspection)
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
 * Verify JWT signature using WebCrypto
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
 * Validate JWT claims
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
 * Extract and validate JWT token
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
 * Parse scope string into array
 */
function parseScopes(scope?: string): string[] {
  if (!scope) return [];
  return scope.split(' ').filter(s => s.length > 0);
}

/**
 * Create error response
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
 * Check if route is public (bypasses authentication)
 */
function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some(route => pathname.startsWith(route));
}

/**
 * Detect authentication method from headers
 */
function detectAuthMethod(request: Request): 'jwt' | 'hmac' | 'none' {
  const authHeader = request.headers.get('Authorization');
  const keyIdHeader = request.headers.get('X-Key-Id');

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return 'jwt';
  } else if (keyIdHeader) {
    return 'hmac';
  }
  
  return 'none';
}

/**
 * Extract JWT token from Authorization header
 */
function extractJWTToken(request: Request): string | null {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  
  return authHeader.slice(7); // Remove 'Bearer ' prefix
}

/**
 * Clean up expired nonces from memory
 */
function cleanupExpiredNonces(): void {
  const now = Date.now();
  for (const [nonce, timestamp] of usedNonces.entries()) {
    if (now - timestamp > NONCE_TTL) {
      usedNonces.delete(nonce);
    }
  }
}

/**
 * Check and store nonce to prevent replay attacks
 */
function checkAndStoreNonce(nonce: string): boolean {
  cleanupExpiredNonces();
  
  if (usedNonces.has(nonce)) {
    return false; // Nonce already used (replay attack)
  }
  
  usedNonces.set(nonce, Date.now());
  return true;
}

/**
 * Extract HMAC headers from request
 */
function extractHMACHeaders(request: Request): HMACHeaders | null {
  const keyId = request.headers.get('X-Key-Id');
  const timestamp = request.headers.get('X-Timestamp');
  const nonce = request.headers.get('X-Nonce');
  const signature = request.headers.get('X-Signature');
  const contentSHA256 = request.headers.get('X-Content-SHA256');

  if (!keyId || !timestamp || !nonce || !signature || !contentSHA256) {
    return null;
  }

  return { keyId, timestamp, nonce, signature, contentSHA256 };
}

/**
 * Validate timestamp freshness (within ±300 seconds)
 */
function validateTimestamp(timestamp: string): boolean {
  const now = Math.floor(Date.now() / 1000);
  const requestTime = parseInt(timestamp, 10);
  
  if (isNaN(requestTime)) {
    return false;
  }
  
  const diff = Math.abs(now - requestTime);
  return diff <= CLOCK_SKEW_SECONDS;
}

/**
 * Build canonical string for HMAC signature verification
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
 * Verify HMAC signature using WebCrypto
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
 * Compute SHA256 hash of request body
 */
async function computeBodyHash(request: Request): Promise<string> {
  // For GET/DELETE methods with no body, use UNSIGNED-PAYLOAD
  if (['GET', 'DELETE', 'HEAD'].includes(request.method.toUpperCase()) || !request.body) {
    return 'UNSIGNED-PAYLOAD';
  }

  try {
    // Clone request to read body without consuming original
    const clonedRequest = request.clone();
    const bodyBytes = await clonedRequest.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', bodyBytes);
    
    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (error) {
    console.error('❌ [HMAC] Body hash computation failed:', error);
    throw new Error('Failed to compute body hash');
  }
}

/**
 * Validate HMAC signed request
 */
async function validateHMAC(request: Request, env: Env): Promise<HMACPayload> {
  try {
    // 1. Extract HMAC headers
    const hmacHeaders = extractHMACHeaders(request);
    if (!hmacHeaders) {
      throw new Error('Missing required HMAC headers');
    }

    console.log(`🔍 [HMAC] Validating request from key: ${hmacHeaders.keyId}`);

    // 2. Validate timestamp freshness
    if (!validateTimestamp(hmacHeaders.timestamp)) {
      throw new Error('Request timestamp is outside acceptable window (±300s)');
    }

    // 3. Check nonce uniqueness (replay protection)
    if (!checkAndStoreNonce(hmacHeaders.nonce)) {
      throw new Error('Nonce has already been used (replay attack detected)');
    }

    // 4. Verify body hash
    const computedBodyHash = await computeBodyHash(request);
    if (computedBodyHash !== hmacHeaders.contentSHA256) {
      throw new Error(`Body hash mismatch. Expected: ${hmacHeaders.contentSHA256}, Got: ${computedBodyHash}`);
    }

    // 5. Fetch API key metadata from KV
    const keyData = await env.KV.get(`api_key:${hmacHeaders.keyId}`, { type: 'json' }) as APIKeyMetadata | null;
    if (!keyData) {
      throw new Error(`API key not found: ${hmacHeaders.keyId}`);
    }

    // 6. Build canonical string
    const canonicalString = await buildCanonicalString(
      request, 
      hmacHeaders.timestamp, 
      hmacHeaders.nonce, 
      hmacHeaders.contentSHA256
    );

    console.log(`🔐 [HMAC] Canonical string:\n${canonicalString}`);

    // 7. Verify HMAC signature
    const isValidSignature = await verifyHMACSignature(
      canonicalString, 
      hmacHeaders.signature, 
      keyData.secret
    );

    if (!isValidSignature) {
      throw new Error('HMAC signature verification failed');
    }

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
 * Create authenticated request with identity headers (JWT)
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
 * Create authenticated request with identity headers (HMAC)
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
 * Main request handler
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
          // Validate HMAC signed request
          const payload = await validateHMAC(request, env);
          console.log("✅ [AUTH] HMAC authentication successful");

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
      
      // Handle authentication errors
      if (error instanceof Error) {
        // JWT errors
        if (error.message.includes('expired')) {
          return createErrorResponse('token_expired', error.message, 401);
        }
        if (error.message.includes('Invalid')) {
          return createErrorResponse('invalid_token', error.message, 401);
        }
        
        // HMAC errors
        if (error.message.includes('timestamp') || error.message.includes('replay')) {
          return createErrorResponse('invalid_request', error.message, 401);
        }
        if (error.message.includes('HMAC') || error.message.includes('signature')) {
          return createErrorResponse('invalid_signature', error.message, 401);
        }
        if (error.message.includes('API key not found')) {
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
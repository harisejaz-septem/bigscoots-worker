// bigscoots-v2-gateway-test
// JWT Authentication Gateway for BigScoots API

interface Env {
  AUTH0_ISSUER: string;
  AUTH0_AUDIENCE: string;
  JWKS_URL: string;
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

// Public routes that bypass authentication
const PUBLIC_ROUTES: string[] = [];

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
  const apiKeyHeader = request.headers.get('X-API-Key');

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return 'jwt';
  } else if (apiKeyHeader) {
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
 * Create authenticated request with identity headers
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
          // TODO: Implement HMAC validation (future)
          return createErrorResponse(
            'not_implemented',
            'HMAC authentication not yet implemented',
            501
          );
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
      
      // Handle JWT validation errors
      if (error instanceof Error) {
        if (error.message.includes('expired')) {
          return createErrorResponse('token_expired', error.message, 401);
        }
        if (error.message.includes('Invalid')) {
          return createErrorResponse('invalid_token', error.message, 401);
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
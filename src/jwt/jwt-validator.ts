import { JWTHeader, JWTPayload } from "../types/jwt-types";
import { Env } from "../types/interfaces";
import { fetchJWKS, findJWKByKid, jwkToCryptoKey } from "./jwks";

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
export function decodeJWT(token: string): { header: JWTHeader; payload: JWTPayload } {
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
export async function verifyJWTSignature(token: string, publicKey: CryptoKey): Promise<boolean> {
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
export function validateJWTClaims(payload: JWTPayload, expectedIssuer: string, expectedAudience: string): void {
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
export async function validateJWT(token: string, env: Env): Promise<JWTPayload> {
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
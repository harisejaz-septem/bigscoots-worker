import { JWKS, JWKSKey } from "../types/jwt-types";

/**
 * JWKS Configuration Constants
 */
const JWKS_CACHE_TTL = 3600000; // 1 hour in milliseconds

// Global JWKS cache (simple in-memory for now)
let jwksCache: JWKS | null = null;
let jwksCacheTime = 0;

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
export async function fetchJWKS(jwksUrl: string): Promise<JWKS> {
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
export function findJWKByKid(jwks: JWKS, kid: string): JWKSKey | null {
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
export async function jwkToCryptoKey(jwk: JWKSKey): Promise<CryptoKey> {
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
import { SIGNED_HEADERS } from "./hmac-constants";

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
export async function buildCanonicalString(
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
export async function verifyHMACSignature(
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
export async function computeBodyHash(request: Request): Promise<string> {
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

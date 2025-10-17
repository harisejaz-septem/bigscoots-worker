import { HMACHeaders } from "../types/hmac-types";
import { CLOCK_SKEW_SECONDS } from "./hmac-constants";

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
export function extractHMACHeaders(request: Request): HMACHeaders | null {
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
export function validateTimestamp(timestamp: string): boolean {
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

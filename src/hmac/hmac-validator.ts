import { Env, NonceReplayGuardStub } from "../types/interfaces";
import { HMACPayload, APIKeyMetadata } from "../types/hmac-types";
import { extractHMACHeaders, validateTimestamp } from "./hmac-headers";
import { buildCanonicalString, verifyHMACSignature, computeBodyHash } from "./hmac-signature";

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
export async function validateHMAC(request: Request, env: Env): Promise<HMACPayload> {
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

/**
 * HMAC request headers interface
 */
export interface HMACHeaders {
  keyId: string;
  timestamp: string;
  nonce: string;
  signature: string;
  contentSHA256: string;
}

/**
 * API key metadata stored in Workers KV
 */
export interface APIKeyMetadata {
  secret: string;
  orgId: string;
  scopes: string[];
  rateLimit?: {
    minute: number;
    hour: number;
    day: number;
  };
}

/**
 * HMAC authentication payload after validation
 */
export interface HMACPayload {
  keyId: string;
  orgId: string;
  scopes: string[];
}

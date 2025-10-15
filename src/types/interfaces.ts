import { DurableObject } from "cloudflare:workers";

/**
 * Core environment interface for the Cloudflare Worker
 */
export interface Env {
  AUTH0_ISSUER: string;
  AUTH0_AUDIENCE: string;
  JWKS_URL: string;
  KV: KVNamespace;
  NONCE_TRACKER: DurableObjectNamespace;
  USER_SERVICE_URL: string;
  SITE_SERVICE_URL: string;
}

/**
 * Durable Object stub interface for nonce replay protection
 */
export interface NonceReplayGuardStub {
  checkAndStore(nonce: string, timestamp: number): Promise<boolean>;
  getStats(): Promise<{ 
    activeNonces: number; 
    oldestTimestamp: number | null; 
    newestTimestamp: number | null 
  }>;
}

/**
 * Standardized error response format matching backend services
 */
export interface AuthError {
  statusCode: number;
  message: string;
  data: string;
}

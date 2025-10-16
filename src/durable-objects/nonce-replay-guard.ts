import { DurableObject } from "cloudflare:workers";
import { Env } from "../types/interfaces";

/**
 * HMAC Configuration Constants
 */
export const NONCE_TTL = 300000; // 5 minutes in milliseconds

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

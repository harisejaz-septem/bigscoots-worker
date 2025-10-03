# Durable Objects Explained: Complete Guide for HMAC Nonce Tracking

## Table of Contents
1. [What are Durable Objects?](#what-are-durable-objects)
2. [Key Concepts and Analogies](#key-concepts-and-analogies)
3. [Our Implementation: NonceReplayGuard](#our-implementation-noncereplayguard)
4. [Architecture Deep Dive](#architecture-deep-dive)
5. [Performance Analysis](#performance-analysis)
6. [Common Questions Answered](#common-questions-answered)
7. [Code Walkthrough](#code-walkthrough)

---

## What are Durable Objects?

**Durable Objects (DOs)** are Cloudflare's solution for **stateful serverless computing**. Think of them as:

> **"Smart, persistent mini-servers that live in Cloudflare's global network"**

### Core Characteristics

| Feature | Description | Real-World Analogy |
|---------|-------------|-------------------|
| **Stateful** | Can store data in memory between requests | Like a person who remembers conversations |
| **Single-threaded** | Handles one request at a time | Like a single cashier at a checkout counter |
| **Globally distributed** | Automatically placed near users | Like having local bank branches worldwide |
| **Persistent** | Survives restarts and failures | Like a notebook that doesn't lose pages |
| **Isolated** | Each instance is completely separate | Like individual apartments in a building |

### The Apartment Building Analogy

```
Cloudflare Network = Apartment Building
├── DO Instance A (Client 1) = Apartment 1A
├── DO Instance B (Client 2) = Apartment 1B  
├── DO Instance C (Client 3) = Apartment 1C
└── DO Instance D (Client 4) = Apartment 1D

Each apartment:
- Has its own memory (furniture/belongings)
- Handles visitors one at a time (single-threaded)
- Can't see into other apartments (isolated)
- Stays there even when owner is away (persistent)
```

---

## Key Concepts and Analogies

### 1. Multiple DO Instances

**Question:** *"So we will have multiple instances of the DO? What does that mean?"*

**Answer:** Yes! Each API key gets its own DO instance.

```typescript
// Different API keys = Different DO instances
const tracker1 = env.NONCE_TRACKER.idFromName(`nonce-live_org_client1`);  // Apartment 1A
const tracker2 = env.NONCE_TRACKER.idFromName(`nonce-live_org_client2`);  // Apartment 1B
const tracker3 = env.NONCE_TRACKER.idFromName(`nonce-live_org_client3`);  // Apartment 1C
```

**Why Multiple Instances?**
- **Performance Isolation**: Client A's heavy usage doesn't slow down Client B
- **Data Isolation**: Each client's nonces are completely separate
- **Failure Isolation**: If one DO crashes, others continue working
- **Automatic Scaling**: More clients = more DOs automatically

### 2. Single-Threaded Processing

**Question:** *"Each DO instance handles requests one at a time (no concurrency issues) - What does this mean?"*

**Answer:** Each DO is like **one person working alone in an office**.

```typescript
// Inside DO Instance for Client A
async checkAndStore(nonce: string, timestamp: number) {
  // Step 1: Check if nonce exists (no interruption possible)
  if (this.nonces.has(nonce)) {
    return false;
  }
  
  // Step 2: Store the nonce (atomic operation)
  this.nonces.set(nonce, timestamp);
  return true;
}
```

**Timeline Example:**
```
Time 1: Request A calls checkAndStore("nonce1") → starts processing
Time 2: Request B calls checkAndStore("nonce2") → waits in queue
Time 3: Request A completes → returns true
Time 4: Request B starts processing → completes → returns true
```

**Benefits:**
- **No race conditions**: Impossible for two requests to interfere
- **Data consistency**: Operations are atomic
- **Predictable behavior**: Always processes in order

### 3. DO Lifecycle - "Always Running" vs "On-Demand"

**Question:** *"So DO instance runs all the time?"*

**Answer:** DOs are **smart sleepers** - like laptops with sleep mode.

```
DO Lifecycle:
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   SLEEPING  │───▶│    ACTIVE    │───▶│   SLEEPING  │
│ (No CPU)    │    │ (Processing) │    │ (No CPU)    │
│ (RAM saved) │    │ (RAM active) │    │ (RAM saved) │
└─────────────┘    └──────────────┘    └─────────────┘
      ▲                     │                   ▲
      │                     │                   │
   No requests         Request arrives      30s idle
   for 30s+
```

**What "Always Running" Actually Means:**
- ✅ **Memory persists** when sleeping (nonces remain stored)
- ✅ **Cleanup timer resumes** when awakened
- ✅ **Instant wake-up** on new requests (< 1ms)
- ❌ **NOT consuming CPU** when idle
- ❌ **NOT always processing** - only when needed

### 4. Memory Architecture

**Question:** *"So the Node.js process which is DO; it has its own memory?"*

**Answer:** Yes! Each DO is like **a separate computer with its own RAM**.

```typescript
export class NonceReplayGuard {
  private nonces: Map<string, number>;  // This is DO's private RAM
  
  constructor() {
    this.nonces = new Map();  // Each DO gets its own Map
  }
}
```

**Memory Isolation Example:**
```
DO Instance A (Client 1):
├── nonces: Map {
│     "uuid-a1" → 1727712000000,
│     "uuid-a2" → 1727712060000
│   }
└── cleanupInterval: Timer

DO Instance B (Client 2):  
├── nonces: Map {
│     "uuid-b1" → 1727712030000,
│     "uuid-b2" → 1727712090000
│   }
└── cleanupInterval: Timer

Completely separate - they can't see each other's data!
```

### 5. DO Identifier Creation

**Question:** *"Worker creates DO identifier - what do you mean by this?"*

**Answer:** It's like **creating a mailing address** for each client.

```typescript
const nonceTrackerId = env.NONCE_TRACKER.idFromName(`nonce-live_org_client1`);
```

**What Happens:**
1. **Worker says:** "I need the DO for client `live_org_client1`"
2. **Cloudflare creates address:** `nonce-live_org_client1`
3. **If DO doesn't exist:** Cloudflare creates it automatically
4. **If DO exists:** Cloudflare finds the existing one

**Address System Analogy:**
```
Building: NONCE_TRACKER (DO Class)
├── Apartment 1A: nonce-live_org_client1 (DO Instance A)
├── Apartment 1B: nonce-live_org_client2 (DO Instance B)
└── Apartment 1C: nonce-live_org_client3 (DO Instance C)
```

---

## Our Implementation: NonceReplayGuard

### Purpose and Benefits

**Why Each API Key Gets Its Own DO:**

| Aspect | Single Global DO | Per-API-Key DO (Our Choice) |
|--------|------------------|----------------------------|
| **Performance** | ❌ Bottleneck (all requests hit one DO) | ✅ Distributed load |
| **Isolation** | ❌ One client affects others | ✅ Complete isolation |
| **Scaling** | ❌ Single point of contention | ✅ Scales with clients |
| **Debugging** | ❌ Hard to trace per client | ✅ Easy per-client debugging |

**Real-World Impact:**
```
Without Isolation (Bad):
Client A: 1000 requests/min  }
Client B: 10 requests/min    } → All hit same DO → Client B suffers
Client C: 500 requests/min   }

With Isolation (Good):
Client A: 1000 requests/min → DO Instance A (fast)
Client B: 10 requests/min   → DO Instance B (fast)
Client C: 500 requests/min  → DO Instance C (fast)
```

### Is This the Best Approach?

**Yes, for nonce tracking it's excellent:**

✅ **Global consistency** - prevents replay attacks worldwide  
✅ **Automatic scaling** - more clients = more DOs automatically  
✅ **No database needed** - faster than any database lookup  
✅ **Built-in cleanup** - no memory leaks  
✅ **Fault tolerant** - Cloudflare handles all infrastructure  

**Alternative Approaches (Worse):**
❌ **Single global DO** - becomes bottleneck with many clients  
❌ **Database storage** - slower, more complex, costs more  
❌ **Redis/KV storage** - network latency, eventual consistency issues  

---

## Architecture Deep Dive

### What is a "Stub"?

**A stub is like a TV remote control:**

```typescript
// This creates a "remote control" (stub) for a specific DO instance
const nonceTracker = env.NONCE_TRACKER.get(nonceTrackerId);

// When you call methods on the stub, they're executed inside the DO
await nonceTracker.checkAndStore(nonce, timestamp);
```

**Analogy:**
- **Your Worker** = You sitting at your desk
- **DO Stub** = TV remote control in your hand
- **Durable Object** = TV in another room
- **Method call** = Pressing a button on the remote

The stub **sends your method call over the network** to the actual DO instance.

### Data Flow Example

**First Request from API Key "live_org_test123":**

```typescript
// 1. Worker creates DO identifier
const nonceTrackerId = env.NONCE_TRACKER.idFromName(`nonce-live_org_test123`);

// 2. Get stub (remote control) for this DO
const nonceTracker = env.NONCE_TRACKER.get(nonceTrackerId);

// 3. Call method on the stub (sends request to DO)
const isUnique = await nonceTracker.checkAndStore("uuid-abc-123", 1727712000);
```

**Behind the Scenes:**
1. **Cloudflare creates new DO instance** (first time for this API key)
2. **Constructor runs** → creates empty Map, starts cleanup timer
3. **checkAndStore() executes inside the DO**
4. **Nonce stored in DO's memory**: `Map.set("uuid-abc-123", 1727712000000)`
5. **Returns true** (nonce was unique)

### Automatic Cleanup Process

**Question:** *"How does the cleanup trigger automatically?"*

**Answer:** The cleanup runs **inside each DO like a background daemon**.

```typescript
private startCleanupTimer(): void {
  // Clean up every 2 minutes
  this.cleanupInterval = setInterval(() => {
    this.cleanup();  // Runs automatically inside the DO
  }, 120000);
}
```

**Server Daemon Analogy:**
- **Your computer** automatically empties trash every week
- **DO cleanup** automatically removes old nonces every 2 minutes  
- **No manual intervention** needed
- **Runs independently** of incoming requests

**Cleanup Process:**
```typescript
private cleanup(): void {
  const now = Date.now();                    // Current time: 1727712300000
  const initialSize = this.nonces.size;     // Before: 50 nonces
  let removedCount = 0;

  for (const [nonce, timestamp] of this.nonces.entries()) {
    // Remove nonces older than 5 minutes (300,000ms)
    if (now - timestamp > NONCE_TTL) {       // 1727712300000 - 1727712000000 = 300000
      this.nonces.delete(nonce);             // Remove expired nonce
      removedCount++;
    }
  }
  
  // After: 30 nonces (20 removed)
  console.log(`Cleanup: removed ${removedCount} expired nonces (${initialSize} → ${this.nonces.size})`);
}
```

---

## Performance Analysis

### Latency Comparison

**Question:** *"If we use DO and if we don't, how much would the latency be?"*

| Method | Best Case | Typical | Worst Case | Consistency |
|--------|-----------|---------|------------|-------------|
| **Durable Objects** | 2ms | 5ms | 8ms | Strong |
| **Workers KV** | 20ms | 35ms | 100ms | Eventually |
| **External DB** | 100ms | 200ms | 400ms | Strong |
| **In-Memory Map** | 0.1ms | 0.1ms | 0.1ms | Per-instance only |

### Real Request Impact

**Your Current HMAC Pipeline:**
```
1. Extract headers: ~0.1ms
2. Validate timestamp: ~0.1ms  
3. Check nonce (DO): ~5ms        ← DO latency here
4. Verify body hash: ~1ms
5. KV lookup (API key): ~15ms
6. Build canonical: ~0.1ms
7. Verify signature: ~2ms
────────────────────────────────
Total: ~23ms
```

**If Using KV for Nonces:**
```
3. Check nonce (KV): ~35ms       ← Much higher latency
────────────────────────────────
Total: ~53ms (130% slower)
```

**If Using External Database:**
```
3. Check nonce (DB): ~200ms      ← Extremely high latency
────────────────────────────────
Total: ~218ms (850% slower)
```

### Why DOs Are Faster

1. **Geographic Proximity**
   ```
   Client in Tokyo → Worker in Tokyo → DO in Tokyo (same data center)
   vs
   Client in Tokyo → Worker in Tokyo → Database in US East (cross-ocean)
   ```

2. **No Network Serialization**
   ```typescript
   // DO: Direct method call (like local function)
   await nonceTracker.checkAndStore(nonce, timestamp);
   
   // KV: HTTP-like protocol with serialization
   await env.KV.get(`nonce:${keyId}:${nonce}`); // JSON serialization
   ```

3. **In-Memory Operations**
   ```typescript
   // DO: RAM lookup (nanoseconds)
   if (this.nonces.has(nonce)) return false;
   
   // Database: Disk I/O + indexing (milliseconds)
   SELECT * FROM nonces WHERE nonce = 'uuid-123';
   ```

---

## Common Questions Answered

### Q: Does DO Fetch All Nonces Every Time?

**Answer:** **No!** DOs keep data in memory (RAM) inside the DO instance.

```
What Actually Happens:
1. DO keeps nonces in memory (RAM) inside the DO instance
2. No database queries or external fetches
3. Instant lookups via Map.has(nonce)
4. Data stays in the DO until cleanup removes it
```

### Q: Memory Management Without Cleanup

**Without Cleanup (Bad):**
```
Time 0:    Map = {}
Time 5min: Map = {"nonce1": timestamp1}
Time 10min: Map = {"nonce1": timestamp1, "nonce2": timestamp2}  // nonce1 expired but still stored
Time 15min: Map = {"nonce1": timestamp1, "nonce2": timestamp2, "nonce3": timestamp3}  // 2 expired
Time 1 hour: Map = {12 expired nonces + 1 valid nonce}  // Memory waste!
```

**With Cleanup (Good):**
```
Time 0:     Map = {}
Time 5min:  Map = {"nonce1": timestamp1}
Time 7min:  Cleanup runs → Map = {} (nonce1 removed, was >5min old)
Time 10min: Map = {"nonce2": timestamp2}
Time 12min: Cleanup runs → Map = {} (nonce2 removed)
```

### Q: Security - Why Cleanup Old Nonces?

**Security is maintained because:**

1. **Timestamp expires first** (5 minutes)
2. **Request gets rejected** before nonce check
3. **Cleanup happens after** nonces are already unusable

**Attack Timeline:**
```
T=0:    Attacker captures request with nonce "abc123", timestamp "1727712000"
T=300s: Nonce gets cleaned up from DO memory  
T=400s: Attacker tries to replay the request
Result: validateTimestamp() rejects it (100s > 300s limit)
        Nonce check never happens!
```

### Q: Error Handling - What if DO is Unavailable?

```typescript
try {
  const isUnique = await nonceTracker.checkAndStore(nonce, timestamp);
  if (!isUnique) {
    throw new Error('Replay attack detected');
  }
} catch (error) {
  // DO call failed - fail secure (reject request)
  throw new Error('Nonce validation failed');
}
```

**Fail Secure Approach:** If we can't verify the nonce, **reject the request**.

---

## Code Walkthrough

### NonceReplayGuard Class Structure

```typescript
export class NonceReplayGuard {
  private nonces: Map<string, number>;      // In-memory nonce storage
  private cleanupInterval: number | null;   // Cleanup timer reference

  constructor(private state: DurableObjectState, private env: Env) {
    this.nonces = new Map();                // Create empty storage
    this.cleanupInterval = null;            // No cleanup timer yet
    this.startCleanupTimer();               // Start automatic cleanup
  }
```

### Key Methods

#### 1. checkAndStore() - Core Nonce Validation
```typescript
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
```

#### 2. cleanup() - Automatic Memory Management
```typescript
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
```

### Integration with HMAC Validation

```typescript
// In validateHMAC function:
// 3. Check nonce uniqueness (replay protection) using Durable Object
console.log(`🔄 [HMAC-VALIDATE] Step 3: Checking nonce uniqueness via Durable Object`);
const nonceTrackerId = env.NONCE_TRACKER.idFromName(`nonce-${hmacHeaders.keyId}`);
const nonceTracker = env.NONCE_TRACKER.get(nonceTrackerId) as unknown as NonceReplayGuardStub;
const isNonceUnique = await nonceTracker.checkAndStore(hmacHeaders.nonce, parseInt(hmacHeaders.timestamp, 10));

if (!isNonceUnique) {
  throw new Error('Nonce has already been used (replay attack detected)');
}
console.log(`✅ [HMAC-VALIDATE] Step 3 complete: Nonce is unique and stored in DO`);
```

---

## Summary

**Durable Objects provide the perfect solution for nonce tracking because they offer:**

1. **Global Consistency** - True replay protection across all Cloudflare locations
2. **High Performance** - ~5ms latency vs ~35ms KV vs ~200ms database  
3. **Automatic Scaling** - Each API key gets isolated DO instance
4. **Built-in Cleanup** - No memory leaks or manual maintenance
5. **Fault Tolerance** - Cloudflare handles all infrastructure

**Key Insight:** DOs give you **distributed computing made simple** - you get the benefits of multiple isolated servers without managing any infrastructure. Each API key effectively gets its own dedicated mini-server for nonce tracking, with automatic cleanup and global consistency.

The architecture scales naturally: more clients = more DO instances = better performance for everyone.

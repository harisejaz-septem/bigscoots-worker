// test/hmac-test.js
import crypto from 'crypto';

class HMACTester {
  constructor(baseUrl, keyId, secret) {
    this.baseUrl = baseUrl;
    this.keyId = keyId;
    this.secret = secret;
  }

  // Generate HMAC signature
  async generateSignature(method, path, query, headers, timestamp, nonce, bodyHash) {
    // Build canonical string (same format as Worker)
    const sortedQuery = query ? new URLSearchParams(query).toString() : '';
    
    const signedHeaders = [];
    const headerNames = ['host', 'content-type'].sort();
    for (const name of headerNames) {
      const headerValue = headers[name] || '';  // Always include header, use empty string if missing
      signedHeaders.push(`${name.toLowerCase()}:${headerValue}`);
    }

    const canonical = [
      method.toUpperCase(),
      path,
      sortedQuery,
      ...signedHeaders,
      timestamp,
      nonce,
      bodyHash
    ].join('\n');

    console.log('🔐 Canonical String:');
    console.log(canonical);
    console.log('---');

    // Sign with HMAC-SHA256
    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(canonical)
      .digest('base64');

    return signature;
  }

  // Compute body hash
  computeBodyHash(body) {
    if (!body || body === '') {
      return 'UNSIGNED-PAYLOAD';
    }
    return crypto.createHash('sha256').update(body).digest('hex');
  }

  // Make HMAC request
  async makeRequest(method, path, query = '', body = null, extraHeaders = {}) {
    console.log('Making request to:', path);
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID();
    const bodyHash = this.computeBodyHash(body);

    const url = new URL(path, this.baseUrl);
    if (query) url.search = query;

    const headers = {
      'host': url.host,
      'content-type': body ? 'application/json' : undefined,
      ...extraHeaders
    };

    const signature = await this.generateSignature(
      method, url.pathname, query, headers, timestamp, nonce, bodyHash
    );

    const requestHeaders = {
      'X-Key-Id': this.keyId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
      'X-Content-SHA256': bodyHash,
      'Host': headers.host
    };

    if (body) {
      requestHeaders['Content-Type'] = 'application/json';
    }

    console.log('📤 Making HMAC Request:');
    console.log(`${method} ${url.toString()}`);
    console.log('Headers:', requestHeaders);
    if (body) console.log('Body:', body);
    console.log('---');

    try {
      const response = await fetch(url.toString(), {
        method,
        headers: requestHeaders,
        body: body || undefined
      });

      const responseText = await response.text();
      console.log('📥 Response:');
      console.log(`Status: ${response.status}`);
      console.log(`Body: ${responseText}`);
      console.log('---');

      return { response, body: responseText };
    } catch (error) {
      console.error('❌ Request failed:', error);
      throw error;
    }
  }
}

// Test scenarios
async function runTests() {
  const tester = new HMACTester(
    'https://v2-cloudflare.bigscoots.dev', // Your Worker URL
    'live_org_test123',                     // Your test key ID
    'base64randomsecret'                    // Your test secret
  );

  console.log('🧪 Starting HMAC Tests...\n');

  try {
    // Test 1: Built-in test route (no auth required)
    console.log('Test 1: Built-in Test Route (No Auth)');
    await tester.makeRequest('GET', '/hi');

    // Test 2: Public route (no auth required)
    console.log('\nTest 2: Public Route - Sites List');
    await tester.makeRequest('GET', '/sites');

    // Test 3: Protected route - User Management (requires auth)
    console.log('\nTest 3: Protected Route - User Management');
    await tester.makeRequest('GET', '/user-mgmt/profile');

    // Test 4: Protected route - Get Site Details (requires auth)
    console.log('\nTest 4: Protected Route - Get Site Details');
    await tester.makeRequest('GET', '/sites/service-123/site-456');

    // Test 5: POST request - Create New Site (requires auth)
    console.log('\nTest 5: POST Request - Create New Site');
    await tester.makeRequest(
      'POST', 
      '/sites/service-123', 
      '',
      JSON.stringify({ domain: 'example.com', plan: 'basic' })
    );

    // Test 6: Invalid route (should return 404)
    console.log('\nTest 6: Invalid Route Test');
    await tester.makeRequest('GET', '/invalid/route');

    // Test 7: Invalid signature (wrong secret)
    console.log('\nTest 7: Invalid Signature Test');
    const badTester = new HMACTester(
      'https://v2-cloudflare.bigscoots.dev',
      'live_org_test123',
      'wrong-secret'
    );
    console.log('🔍 [TEST] Using wrong secret: "wrong-secret" vs stored: "base64randomsecret"');
    await badTester.makeRequest('GET', '/sites/service-123/site-456');

  } catch (error) {
    console.error('Test failed:', error);
  }
}

// Run the tests
runTests();
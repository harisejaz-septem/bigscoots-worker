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
      if (headers[name]) {
        signedHeaders.push(`${name.toLowerCase()}:${headers[name]}`);
      }
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
    // Test 1: GET request
    console.log('Test 1: GET Request');
    await tester.makeRequest('GET', '/hi');

    // Test 2: POST request with body
    console.log('\nTest 2: POST Request with Body');
    await tester.makeRequest(
      'POST', 
      '/api/test', 
      'param1=value1&param2=value2',
      JSON.stringify({ message: 'Hello HMAC' })
    );

    // Test 3: Invalid signature (wrong secret)
    console.log('\nTest 3: Invalid Signature Test');
    const badTester = new HMACTester(
      'https://v2-cloudflare.bigscoots.dev',
      'live_org_test123',
      'wrong-secret'
    );
    await badTester.makeRequest('GET', '/hi');

  } catch (error) {
    console.error('Test failed:', error);
  }
}

// Run the tests
runTests();
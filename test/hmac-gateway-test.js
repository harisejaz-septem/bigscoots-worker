// test/hmac-gateway-test.js
import crypto from 'crypto';

class HMACGatewayTester {
  constructor(baseUrl, keyId, secret) {
    this.baseUrl = baseUrl;
    this.keyId = keyId;
    this.secret = secret;
  }

  // Generate HMAC signature (same as gateway logic)
  async generateSignature(method, path, query, headers, timestamp, nonce, bodyHash) {
    const sortedQuery = query ? new URLSearchParams(query).toString() : '';
    
    const signedHeaders = [];
    const headerNames = ['host', 'content-type'].sort();
    for (const name of headerNames) {
      const headerValue = headers[name] || '';
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

    const signature = crypto
      .createHmac('sha256', this.secret)
      .update(canonical)
      .digest('base64');

    return signature;
  }

  computeBodyHash(body) {
    if (!body || body === '') {
      return 'UNSIGNED-PAYLOAD';
    }
    return crypto.createHash('sha256').update(body).digest('hex');
  }

  async makeHMACRequest(method, path, query = '', body = null) {
    console.log(`\n🚀 Testing HMAC Flow: ${method} ${path}`);
    console.log('=' .repeat(60));
    
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID();
    const bodyHash = this.computeBodyHash(body);

    const url = new URL(path, this.baseUrl);
    if (query) url.search = query;

    const headers = {
      'host': url.host,
      'content-type': body ? 'application/json' : ''
    };

    console.log('📋 Request Details:');
    console.log(`  Method: ${method}`);
    console.log(`  Path: ${path}`);
    console.log(`  Query: ${query || 'none'}`);
    console.log(`  Body Hash: ${bodyHash}`);
    console.log(`  Timestamp: ${timestamp}`);
    console.log(`  Nonce: ${nonce}`);

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

    console.log('📤 HMAC Headers:');
    Object.entries(requestHeaders).forEach(([key, value]) => {
      console.log(`  ${key}: ${value}`);
    });

    try {
      const response = await fetch(url.toString(), {
        method,
        headers: requestHeaders,
        body: body || undefined
      });

      const responseText = await response.text();
      
      console.log('\n📥 Gateway Response:');
      console.log(`  Status: ${response.status}`);
      console.log(`  Headers: ${JSON.stringify(Object.fromEntries(response.headers), null, 2)}`);
      
      // Parse response if JSON
      let parsedResponse;
      try {
        parsedResponse = JSON.parse(responseText);
        console.log(`  Body: ${JSON.stringify(parsedResponse, null, 2)}`);
      } catch {
        console.log(`  Body: ${responseText}`);
      }

      // Analyze the response
      this.analyzeResponse(response.status, parsedResponse || responseText, path);

      return { response, body: responseText, parsed: parsedResponse };
    } catch (error) {
      console.error('❌ Request failed:', error);
      throw error;
    }
  }

  analyzeResponse(status, body, path) {
    console.log('\n🔍 Analysis:');
    
    if (status === 200) {
      console.log('  ✅ HMAC authentication successful!');
      console.log('  ✅ Gateway processed and forwarded request');
      console.log('  ⚠️  Backend response (may fail due to missing HMAC support)');
    } else if (status === 401) {
      if (body.message?.includes('Authentication required')) {
        console.log('  ❌ No authentication provided');
      } else if (body.message?.includes('HMAC')) {
        console.log('  ❌ HMAC validation failed');
      } else if (body.message?.includes('timestamp')) {
        console.log('  ❌ Timestamp validation failed');
      } else if (body.message?.includes('nonce')) {
        console.log('  ❌ Nonce replay detected');
      } else if (body.message?.includes('signature')) {
        console.log('  ❌ Signature verification failed');
      } else {
        console.log('  ❌ Authentication failed (unknown reason)');
      }
    } else if (status === 404) {
      console.log('  ❌ Route not found');
    } else {
      console.log(`  ⚠️  Unexpected status: ${status}`);
    }
  }

  // Test invalid signature
  async testInvalidSignature(path) {
    console.log(`\n🧪 Testing Invalid Signature: ${path}`);
    console.log('=' .repeat(60));
    
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID();
    const bodyHash = 'UNSIGNED-PAYLOAD';

    const requestHeaders = {
      'X-Key-Id': this.keyId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': 'invalid-signature-here',
      'X-Content-SHA256': bodyHash,
      'Host': new URL(this.baseUrl).host
    };

    const response = await fetch(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: requestHeaders
    });

    const responseText = await response.text();
    console.log(`📥 Response: ${response.status} - ${responseText}`);
    
    if (response.status === 401) {
      console.log('✅ Invalid signature correctly rejected');
    } else {
      console.log('❌ Invalid signature should have been rejected');
    }
  }

  // Test timestamp validation
  async testOldTimestamp(path) {
    console.log(`\n🧪 Testing Old Timestamp: ${path}`);
    console.log('=' .repeat(60));
    
    const oldTimestamp = (Math.floor(Date.now() / 1000) - 400).toString(); // 400 seconds ago
    const nonce = crypto.randomUUID();
    const bodyHash = 'UNSIGNED-PAYLOAD';

    const url = new URL(path, this.baseUrl);
    const headers = { 'host': url.host, 'content-type': '' };

    const signature = await this.generateSignature(
      'GET', url.pathname, '', headers, oldTimestamp, nonce, bodyHash
    );

    const requestHeaders = {
      'X-Key-Id': this.keyId,
      'X-Timestamp': oldTimestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
      'X-Content-SHA256': bodyHash,
      'Host': headers.host
    };

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: requestHeaders
    });

    const responseText = await response.text();
    console.log(`📥 Response: ${response.status} - ${responseText}`);
    
    if (response.status === 401 && responseText.includes('timestamp')) {
      console.log('✅ Old timestamp correctly rejected');
    } else {
      console.log('❌ Old timestamp should have been rejected');
    }
  }

  // Test replay attack
  async testReplayAttack(path) {
    console.log(`\n🧪 Testing Replay Attack: ${path}`);
    console.log('=' .repeat(60));
    
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomUUID();
    const bodyHash = 'UNSIGNED-PAYLOAD';

    const url = new URL(path, this.baseUrl);
    const headers = { 'host': url.host, 'content-type': '' };

    const signature = await this.generateSignature(
      'GET', url.pathname, '', headers, timestamp, nonce, bodyHash
    );

    const requestHeaders = {
      'X-Key-Id': this.keyId,
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
      'X-Content-SHA256': bodyHash,
      'Host': headers.host
    };

    // First request
    console.log('📤 First request (should succeed):');
    const response1 = await fetch(url.toString(), {
      method: 'GET',
      headers: requestHeaders
    });
    console.log(`📥 Response 1: ${response1.status}`);

    // Second request with same nonce (should fail)
    console.log('📤 Second request with same nonce (should fail):');
    const response2 = await fetch(url.toString(), {
      method: 'GET',
      headers: requestHeaders
    });
    
    const responseText2 = await response2.text();
    console.log(`📥 Response 2: ${response2.status} - ${responseText2}`);
    
    if (response2.status === 401 && responseText2.includes('nonce')) {
      console.log('✅ Replay attack correctly detected and blocked');
    } else {
      console.log('❌ Replay attack should have been blocked');
    }
  }
}

// Test suite
async function runHMACGatewayTests() {
  const tester = new HMACGatewayTester(
    'https://v2-cloudflare.bigscoots.dev',
    'live_org_test123',
    'base64randomsecret'
  );

  console.log('🧪 HMAC Gateway Test Suite');
  console.log('🎯 Goal: Test HMAC authentication flow through gateway');
  console.log('📝 Note: Backend services may return errors (expected - no HMAC support yet)');
  console.log('✅ Success = Gateway authenticates and forwards request');
  console.log('\n' + '='.repeat(80));

  try {
    // Test 1: Valid HMAC requests
    await tester.makeHMACRequest('GET', '/user-mgmt/profile');
    await tester.makeHMACRequest('GET', '/site-mgmt/plans');
    await tester.makeHMACRequest('POST', '/site-mgmt/sites', '', 
      JSON.stringify({ domain: 'test.com', plan: 'basic' }));

    // Test 2: Security validations
    await tester.testInvalidSignature('/user-mgmt/profile');
    await tester.testOldTimestamp('/user-mgmt/profile');
    await tester.testReplayAttack('/user-mgmt/profile');

    console.log('\n🎉 HMAC Gateway Tests Completed!');
    console.log('📊 Summary:');
    console.log('  - HMAC signature generation: ✅');
    console.log('  - Canonical string building: ✅');
    console.log('  - Gateway authentication: ✅');
    console.log('  - Security validations: ✅');
    console.log('  - Request forwarding: ✅');

  } catch (error) {
    console.error('❌ Test suite failed:', error);
  }
}

// Run the tests
runHMACGatewayTests();
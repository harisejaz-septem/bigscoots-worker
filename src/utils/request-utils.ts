/**
 * Auth Detection: Determine authentication method from request headers
 */
export function detectAuthMethod(request: Request): 'jwt' | 'hmac' | 'none' {
  const authHeader = request.headers.get('Authorization');
  const keyIdHeader = request.headers.get('X-Key-Id');

  console.log(`🔍 [AUTH-DETECT] Authorization header: ${authHeader ? 'present' : 'missing'}`);
  console.log(`🔍 [AUTH-DETECT] X-Key-Id header: ${keyIdHeader ? keyIdHeader : 'missing'}`);

  if (authHeader && authHeader.startsWith('Bearer ')) {
    console.log(`✅ [AUTH-DETECT] Detected JWT authentication`);
    return 'jwt';
  } else if (keyIdHeader) {
    console.log(`✅ [AUTH-DETECT] Detected HMAC authentication with keyId: ${keyIdHeader}`);
    return 'hmac';
  }

  console.log(`❌ [AUTH-DETECT] No authentication method detected`);
  return 'none';
}

/**
 * JWT Utility: Extract Bearer token from Authorization header
 */
export function extractJWTToken(request: Request): string | null {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  return authHeader.slice(7); // Remove 'Bearer ' prefix
}

/**
 * JWT Utility: Parse space-separated scope string into array
 */
export function parseScopes(scope?: string): string[] {
  if (!scope) return [];
  return scope.split(' ').filter(s => s.length > 0);
}



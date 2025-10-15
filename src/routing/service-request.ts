/**
 * Routing Utility: Create request for backend service
 * 
 * Creates a new request object targeting the specified backend service while preserving
 * the original path, query parameters, headers, and body. Adds identity headers from authentication.
 * For JWT requests, keeps the Authorization header so backend can decode the token.
 * For HMAC requests, removes all authentication headers.
 * 
 * @param originalRequest - Original client request
 * @param serviceUrl - Backend service base URL
 * @param pathname - Request path to preserve
 * @param identityHeaders - Headers to add from authentication (X-Auth-Type, X-User-Id, etc.)
 * @returns New request object for backend service
 */
export function createServiceRequest(
  originalRequest: Request, 
  serviceUrl: string, 
  pathname: string,
  identityHeaders: Record<string, string>
): Request {
  const url = new URL(originalRequest.url);
  const targetUrl = `${serviceUrl}${pathname}${url.search}`;
  
  // Copy all original headers
  const newHeaders = new Headers(originalRequest.headers);
  
  // Remove HMAC authentication headers (they shouldn't reach backend services)
  newHeaders.delete('X-Key-Id');      // Remove HMAC headers
  newHeaders.delete('X-Timestamp');
  newHeaders.delete('X-Nonce');
  newHeaders.delete('X-Signature');
  newHeaders.delete('X-Content-SHA256');
  
  // Keep Authorization header for JWT requests, remove for HMAC requests
  if (identityHeaders['X-Auth-Type'] === 'hmac') {
    newHeaders.delete('Authorization'); // Remove for HMAC (no JWT to pass)
  }
  // For JWT requests, keep Authorization header so backend can decode token
  
  // Add identity headers from authentication
  Object.entries(identityHeaders).forEach(([key, value]) => {
    newHeaders.set(key, value);
  });
  
  // Update Host header to match target service
  const targetHost = new URL(serviceUrl).host;
  newHeaders.set('Host', targetHost);
  
  return new Request(targetUrl, {
    method: originalRequest.method,
    headers: newHeaders,
    body: originalRequest.body,
  });
}

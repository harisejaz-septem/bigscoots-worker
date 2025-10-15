import { PUBLIC_ROUTES, ROUTE_CONFIG } from "./route-config";

/**
 * Route Utility: Check if route bypasses authentication
 * 
 * Determines whether a request path should skip JWT/HMAC validation.
 * Useful for health checks, documentation, and public endpoints.
 * 
 * @param pathname - Request path from URL (e.g., "/health", "/api/docs")
 * @returns true if route is public, false if authentication required
 * 
 * @example
 * const isPublic = isPublicRoute("/health");
 * // Returns: true (if "/health" is in PUBLIC_ROUTES array)
 */
export function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTES.some(route => {
    // Exact match for root endpoints that shouldn't match sub-paths
    if (route === '/sites' || route === '/service') {
      return pathname === route;
    }
    // Prefix match for auth endpoints that should match sub-paths
    return pathname.startsWith(route);
  });
}

/**
 * Routing Utility: Determine target service for request path
 * 
 * Matches request path against configured route prefixes to determine which backend service
 * should handle the request. Supports multiple prefixes per service.
 * 
 * @param pathname - Request path from URL (e.g., "/sites/123", "/user-mgmt/profile")
 * @returns Route configuration object or null if no match found
 * 
 * @example
 * const route = getRouteForPath("/sites/abc-123");
 * // Returns: { prefixes: ["/sites/", ...], serviceUrl: "SITE_SERVICE_URL", serviceName: "Site Management" }
 */
export function getRouteForPath(pathname: string): typeof ROUTE_CONFIG[number] | null {
  // Normalize path - ensure it ends with / for prefix matching
  const normalizedPath = pathname.endsWith('/') ? pathname : pathname + '/';
  
  for (const route of ROUTE_CONFIG) {
    for (const prefix of route.prefixes) {
      if (normalizedPath.startsWith(prefix)) {
        return route;
      }
    }
  }
  
  return null;
}

// bigscoots-v2-gateway-test
// JWT Authentication Gateway for BigScoots API

import { Env, NonceReplayGuardStub, AuthError } from "./types/interfaces";
import { createErrorResponse } from "./utils/error-handlers";
import { detectAuthMethod, extractJWTToken, parseScopes } from "./utils/request-utils";
import { isPublicRoute, getRouteForPath } from "./routing/route-matcher";
import { createServiceRequest } from "./routing/service-request";
import { NonceReplayGuard, NONCE_TTL } from "./durable-objects/nonce-replay-guard";
import { validateJWT } from "./jwt/jwt-validator";
import { validateHMAC } from "./hmac/hmac-validator";

/**
 * Main Worker Handler: Dual authentication and request routing
 * 
 * Entry point for all requests. Handles both JWT and HMAC authentication on the same endpoints.
 * Routes authenticated requests to backend services with injected identity headers.
 * 
 * Flow: Detect auth method → Validate credentials → Inject headers → Forward to backend
 * 
 * @param request - Incoming HTTP request
 * @param env - Worker environment variables and bindings
 * @param ctx - Execution context for background tasks
 * @returns Promise resolving to HTTP response
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	  const { method, url } = request;
	  const parsedUrl = new URL(url);
  
    // Request logging
	  console.log(
		`🟢 [REQUEST] ${method} ${parsedUrl.pathname} @ ${new Date().toISOString()}`
	  );
  
    try {
      // Handle built-in test routes FIRST (no auth required)
      if (parsedUrl.pathname === "/hi") {
        console.log("🔓 [AUTH] Built-in test route - bypassing authentication");
        const response = new Response("👋 Hi from BigScoots Worker!");
        console.log(
          `🔵 [RESPONSE] ${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`
        );
        return response;
      }
      
      if (parsedUrl.pathname === "/json") {
        console.log("🔓 [AUTH] Built-in test route - bypassing authentication");
        const response = new Response(JSON.stringify({ message: "Hello JSON" }), {
		  headers: { "Content-Type": "application/json" },
		});
        console.log(
          `🔵 [RESPONSE] ${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`
        );
        return response;
      }

      // Check if route is public (bypass auth)
      if (isPublicRoute(parsedUrl.pathname)) {
        console.log("🔓 [AUTH] Public route - bypassing authentication");
        
        // Route public requests to appropriate service
        const route = getRouteForPath(parsedUrl.pathname);
        if (!route) {
          console.log(`❌ [ROUTING] No route found for path: ${parsedUrl.pathname}`);
          return createErrorResponse('Not Found', 'Route not found', 404);
        }
        
        const serviceUrl = env[route.serviceUrl as keyof Env] as string;
        console.log(`🌐 [ROUTING] Public route to ${route.serviceName}: ${serviceUrl}`);
        
        // Create request without identity headers for public routes
        const serviceRequest = createServiceRequest(request, serviceUrl, parsedUrl.pathname, {});
        const response = await fetch(serviceRequest);
        
        console.log(`📤 [${route.serviceName.toUpperCase()}] ${serviceUrl}${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`);
        return response;
        
	  } else {
        // Authentication required for all other routes
        const authMethod = detectAuthMethod(request);
        console.log(`🔍 [AUTH] Detected auth method: ${authMethod}`);

        if (authMethod === 'none') {
          return createErrorResponse(
            'Unauthorized',
            'Authentication required. Provide either Bearer token or API key.',
            401
          );
        }

        if (authMethod === 'jwt') {
          // Extract and validate JWT
          const token = extractJWTToken(request);
          if (!token) {
            return createErrorResponse(
              'Unauthorized',
              'Bearer token is required but not provided',
              401
            );
          }

          // Validate JWT
          const payload = await validateJWT(token, env);
          console.log("✅ [AUTH] JWT authentication successful");

          // Determine target service for this route
          const route = getRouteForPath(parsedUrl.pathname);
          if (!route) {
            console.log(`❌ [ROUTING] No route found for authenticated path: ${parsedUrl.pathname}`);
            return createErrorResponse('Not Found', 'Route not found', 404);
          }
          
          const serviceUrl = env[route.serviceUrl as keyof Env] as string;
          console.log(`🌐 [ROUTING] JWT authenticated request to ${route.serviceName}: ${serviceUrl}`);
          
          // Create identity headers for JWT authentication
          const scopes = parseScopes(payload.scope);
          const identityHeaders: Record<string, string> = {
            'X-Auth-Type': 'jwt',
            'X-User-Id': payload.sub,
            'X-Client-Id': payload.sub,
            'X-Org-Id': 'null', // Normal users don't have org_id
            'X-Scopes': JSON.stringify(scopes)
          };
          
          // Add custom claims if present
          if (payload["https://v2-bigscoots.com/role"]) {
            identityHeaders['X-Role'] = payload["https://v2-bigscoots.com/role"];
          }
          if (payload["https://v2-bigscoots.com/email"]) {
            identityHeaders['X-Email'] = payload["https://v2-bigscoots.com/email"];
          }
          
          // Create and forward authenticated request
          const serviceRequest = createServiceRequest(request, serviceUrl, parsedUrl.pathname, identityHeaders);
          const response = await fetch(serviceRequest);
          
          console.log(`📤 [${route.serviceName.toUpperCase()}] ${serviceUrl}${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`);
          return response;

        } else if (authMethod === 'hmac') {
          console.log("🚀 [AUTH] Starting HMAC authentication process");
          console.log(`🔑 [AUTH] Request URL: ${request.url}`);
          console.log(`🔑 [AUTH] Request method: ${request.method}`);
          
          // Validate HMAC signed request
          const payload = await validateHMAC(request, env);
          console.log("✅ [AUTH] HMAC authentication successful");
          console.log(`✅ [AUTH] Authenticated client: ${payload.keyId} (org: ${payload.orgId})`);

          // Determine target service for this route
          const route = getRouteForPath(parsedUrl.pathname);
          if (!route) {
            console.log(`❌ [ROUTING] No route found for authenticated path: ${parsedUrl.pathname}`);
            return createErrorResponse('Not Found', 'Route not found', 404);
          }
          
          const serviceUrl = env[route.serviceUrl as keyof Env] as string;
          console.log(`🌐 [ROUTING] HMAC authenticated request to ${route.serviceName}: ${serviceUrl}`);
          
          // Create identity headers for HMAC authentication
          const identityHeaders = {
            'X-Auth-Type': 'hmac',
            'X-Client-Id': payload.keyId,
            'X-Org-Id': payload.orgId,
            'X-Scopes': JSON.stringify(payload.scopes)
          };
          
          // Create and forward authenticated request
          const serviceRequest = createServiceRequest(request, serviceUrl, parsedUrl.pathname, identityHeaders);
          const response = await fetch(serviceRequest);
          
          console.log(`📤 [${route.serviceName.toUpperCase()}] ${serviceUrl}${parsedUrl.pathname} -> ${response.status} @ ${new Date().toISOString()}`);
          return response;
        }
      }

      // Fallback for unhandled cases
      return createErrorResponse('Internal Server Error', 'Unhandled request case', 500);

    } catch (error) {
      console.error("❌ [ERROR] Request processing failed:", error);
      
      console.error("❌ [ERROR] Request processing failed:", error);
      
      // Handle authentication errors
      if (error instanceof Error) {
        console.error(`❌ [ERROR] Error type: ${error.constructor.name}`);
        console.error(`❌ [ERROR] Error message: ${error.message}`);
        
        // JWT errors
        if (error.message.includes('expired')) {
          console.error(`❌ [ERROR] JWT token expired`);
          return createErrorResponse('Unauthorized', error.message, 401);
        }
        if (error.message.includes('Invalid')) {
          console.error(`❌ [ERROR] Invalid JWT token`);
          return createErrorResponse('Unauthorized', error.message, 401);
        }
        
        // HMAC errors
        if (error.message.includes('timestamp') || error.message.includes('replay')) {
          console.error(`❌ [ERROR] HMAC timestamp/replay error`);
          return createErrorResponse('Unauthorized', error.message, 401);
        }
        if (error.message.includes('HMAC') || error.message.includes('signature')) {
          console.error(`❌ [ERROR] HMAC signature verification failed`);
          return createErrorResponse('Unauthorized', error.message, 401);
        }
        if (error.message.includes('API key not found')) {
          console.error(`❌ [ERROR] API key not found in KV storage`);
          return createErrorResponse('Unauthorized', error.message, 401);
        }
      }

      // Generic server error
      return createErrorResponse(
        'Internal Server Error',
        'An unexpected error occurred',
        500
      );
    }
	},
  } satisfies ExportedHandler<Env>;

// Export Durable Object class for Cloudflare Workers
export { NonceReplayGuard };
import { PublicRoutes, ServiceRouteConfig } from "../types/routing-types";

/**
 * Public routes that bypass authentication
 */
export const PUBLIC_ROUTES: PublicRoutes = [
  // User Management public routes
  '/user-mgmt/auth/login',
  '/user-mgmt/auth/refresh', 
  '/user-mgmt/auth/verify-oob-code',
  '/user-mgmt/auth/social-login',
  '/authentication/get-token',
  
  // All site-mgmt routes removed - now require authentication
] as const;

/**
 * Service routing configuration
 */
export const ROUTE_CONFIG: ServiceRouteConfig = [
  {
    prefixes: ['/user-mgmt/'],
    serviceUrl: 'USER_SERVICE_URL',
    serviceName: 'User Management'
  },
  {
    prefixes: ['/site-mgmt/', '/sites/', '/authentication/', '/dashboard/', '/management/', '/service/', '/plans/'],
    serviceUrl: 'SITE_SERVICE_URL', 
    serviceName: 'Site Management'
  }
] as const;

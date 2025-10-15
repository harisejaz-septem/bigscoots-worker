/**
 * Route configuration interface
 */
export interface RouteConfig {
  prefixes: readonly string[];
  serviceUrl: string;
  serviceName: string;
}

/**
 * Service routing configuration type
 */
export type ServiceRouteConfig = readonly RouteConfig[];

/**
 * Public routes configuration
 */
export type PublicRoutes = readonly string[];

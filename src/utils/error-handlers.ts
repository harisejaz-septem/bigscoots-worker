import { AuthError } from "../types/interfaces";

/**
 * Auth Utility: Create standardized JSON error response
 *
 * Generates consistent error responses with proper HTTP status codes and JSON format.
 * Used for both JWT and HMAC authentication failures.
 */
export function createErrorResponse(error: string, description: string, status: number): Response {
  const errorBody: AuthError = {
    statusCode: status,
    message: description,
    data: error,
  };

  return new Response(JSON.stringify(errorBody), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}



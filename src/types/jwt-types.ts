/**
 * JWT Header interface
 */
export interface JWTHeader {
  alg: string;
  typ: string;
  kid: string;
}

/**
 * JWT Payload interface with custom BigScoots claims
 */
export interface JWTPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  scope?: string;
  "https://v2-bigscoots.com/role"?: string;
  "https://v2-bigscoots.com/email"?: string;
  "https://v2-bigscoots.com/email_verified"?: boolean;
}

/**
 * JSON Web Key interface for JWKS
 */
export interface JWKSKey {
  kty: string;
  use: string;
  kid: string;
  x5c: string[];
  n: string;
  e: string;
  alg: string;
}

/**
 * JSON Web Key Set interface
 */
export interface JWKS {
  keys: JWKSKey[];
}

/**
 * OAuth 2.0/2.1 Grant Types
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-1.3
 */
export type GrantType =
    | 'authorization_code'
    | 'refresh_token'
    | 'client_credentials'
    | 'urn:ietf:params:oauth:grant-type:device_code';

/**
 * OAuth 2.0 Response Types
 */
export type ResponseType = 'code' | 'token' | 'id_token' | 'code id_token' | 'code token';

/**
 * Token Endpoint Authentication Methods
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 */
export type TokenEndpointAuthMethod =
    | 'none'
    | 'client_secret_basic'
    | 'client_secret_post'
    | 'private_key_jwt';

/**
 * PKCE Code Challenge Methods
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 */
export type CodeChallengeMethod = 'S256' | 'plain';

/**
 * Standard OAuth 2.0 Scopes + OpenID Connect
 */
export const STANDARD_SCOPES = [
    'openid',
    'profile',
    'email',
    'address',
    'phone',
    'offline_access',
] as const;

export type StandardScope = (typeof STANDARD_SCOPES)[number];

/**
 * OAuth 2.0 Authorization Request
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
 */
export interface AuthorizationRequest {
    response_type: ResponseType;
    client_id: string;
    redirect_uri: string;
    scope?: string;
    state?: string;
    code_challenge?: string;
    code_challenge_method?: CodeChallengeMethod;
    nonce?: string;
    prompt?: 'none' | 'login' | 'consent' | 'select_account';
    max_age?: number;
    ui_locales?: string;
    login_hint?: string;
}

/**
 * OAuth 2.0 Authorization Response
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
 */
export interface AuthorizationResponse {
    code: string;
    state?: string;
}

/**
 * OAuth 2.0 Token Request - Authorization Code
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 */
export interface TokenRequestAuthorizationCode {
    grant_type: 'authorization_code';
    code: string;
    redirect_uri: string;
    client_id: string;
    client_secret?: string;
    code_verifier?: string;
}

/**
 * OAuth 2.0 Token Request - Refresh Token
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-6
 */
export interface TokenRequestRefreshToken {
    grant_type: 'refresh_token';
    refresh_token: string;
    client_id: string;
    client_secret?: string;
    scope?: string;
}

/**
 * OAuth 2.0 Token Request - Client Credentials
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
export interface TokenRequestClientCredentials {
    grant_type: 'client_credentials';
    client_id: string;
    client_secret: string;
    scope?: string;
}

export type TokenRequest =
    | TokenRequestAuthorizationCode
    | TokenRequestRefreshToken
    | TokenRequestClientCredentials;

/**
 * OAuth 2.0 Token Response
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
export interface TokenResponse {
    access_token: string;
    token_type: 'Bearer';
    expires_in: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
}

/**
 * OAuth 2.0 Error Response
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
 */
export interface TokenErrorResponse {
    error: OAuthErrorCode;
    error_description?: string;
    error_uri?: string;
}

/**
 * Standard OAuth 2.0 Error Codes
 */
export type OAuthErrorCode =
    | 'invalid_request'
    | 'invalid_client'
    | 'invalid_grant'
    | 'unauthorized_client'
    | 'unsupported_grant_type'
    | 'invalid_scope'
    | 'access_denied'
    | 'server_error'
    | 'temporarily_unavailable'
    | 'invalid_token'
    | 'insufficient_scope';

/**
 * Token Introspection Request
 * @see https://datatracker.ietf.org/doc/html/rfc7662
 */
export interface IntrospectionRequest {
    token: string;
    token_type_hint?: 'access_token' | 'refresh_token';
}

/**
 * Token Introspection Response
 * @see https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
 */
export interface IntrospectionResponse {
    active: boolean;
    scope?: string;
    client_id?: string;
    username?: string;
    token_type?: string;
    exp?: number;
    iat?: number;
    nbf?: number;
    sub?: string;
    aud?: string | string[];
    iss?: string;
    jti?: string;
}

/**
 * Token Revocation Request
 * @see https://datatracker.ietf.org/doc/html/rfc7009
 */
export interface RevocationRequest {
    token: string;
    token_type_hint?: 'access_token' | 'refresh_token';
}

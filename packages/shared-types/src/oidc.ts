/**
 * OpenID Connect Discovery Document
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export interface OpenIDConfiguration {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint?: string;
    jwks_uri: string;
    registration_endpoint?: string;
    scopes_supported: string[];
    response_types_supported: string[];
    response_modes_supported?: string[];
    grant_types_supported: string[];
    acr_values_supported?: string[];
    subject_types_supported: string[];
    id_token_signing_alg_values_supported: string[];
    id_token_encryption_alg_values_supported?: string[];
    id_token_encryption_enc_values_supported?: string[];
    userinfo_signing_alg_values_supported?: string[];
    userinfo_encryption_alg_values_supported?: string[];
    userinfo_encryption_enc_values_supported?: string[];
    request_object_signing_alg_values_supported?: string[];
    request_object_encryption_alg_values_supported?: string[];
    request_object_encryption_enc_values_supported?: string[];
    token_endpoint_auth_methods_supported: string[];
    token_endpoint_auth_signing_alg_values_supported?: string[];
    display_values_supported?: string[];
    claim_types_supported?: string[];
    claims_supported?: string[];
    service_documentation?: string;
    claims_locales_supported?: string[];
    ui_locales_supported?: string[];
    claims_parameter_supported?: boolean;
    request_parameter_supported?: boolean;
    request_uri_parameter_supported?: boolean;
    require_request_uri_registration?: boolean;
    op_policy_uri?: string;
    op_tos_uri?: string;
    revocation_endpoint?: string;
    revocation_endpoint_auth_methods_supported?: string[];
    introspection_endpoint?: string;
    introspection_endpoint_auth_methods_supported?: string[];
    code_challenge_methods_supported?: string[];
    end_session_endpoint?: string;
}

/**
 * OpenID Connect Standard Claims
 * @see https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
 */
export interface StandardClaims {
    sub: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    middle_name?: string;
    nickname?: string;
    preferred_username?: string;
    profile?: string;
    picture?: string;
    website?: string;
    email?: string;
    email_verified?: boolean;
    gender?: string;
    birthdate?: string;
    zoneinfo?: string;
    locale?: string;
    phone_number?: string;
    phone_number_verified?: boolean;
    address?: AddressClaim;
    updated_at?: number;
}

/**
 * OpenID Connect Address Claim
 */
export interface AddressClaim {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
}

/**
 * ID Token Claims
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
 */
export interface IDTokenClaims extends StandardClaims {
    iss: string;
    aud: string | string[];
    exp: number;
    iat: number;
    auth_time?: number;
    nonce?: string;
    acr?: string;
    amr?: string[];
    azp?: string;
    at_hash?: string;
    c_hash?: string;
}

/**
 * Access Token Claims (JWT)
 */
export interface AccessTokenClaims {
    iss: string;
    sub: string;
    aud: string | string[];
    exp: number;
    iat: number;
    nbf?: number;
    jti: string;
    client_id: string;
    scope: string;
}

/**
 * UserInfo Response
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
 */
export type UserInfoResponse = StandardClaims;

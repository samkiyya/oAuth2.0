/**
 * OpenID Connect Discovery Document
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export interface OpenIDConfiguration {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    userinfo_endpoint?: string | undefined;
    jwks_uri: string;
    registration_endpoint?: string | undefined;
    scopes_supported: string[];
    response_types_supported: string[];
    response_modes_supported?: string[] | undefined;
    grant_types_supported: string[];
    acr_values_supported?: string[] | undefined;
    subject_types_supported: string[];
    id_token_signing_alg_values_supported: string[];
    id_token_encryption_alg_values_supported?: string[] | undefined;
    id_token_encryption_enc_values_supported?: string[] | undefined;
    userinfo_signing_alg_values_supported?: string[] | undefined;
    userinfo_encryption_alg_values_supported?: string[] | undefined;
    userinfo_encryption_enc_values_supported?: string[] | undefined;
    request_object_signing_alg_values_supported?: string[] | undefined;
    request_object_encryption_alg_values_supported?: string[] | undefined;
    request_object_encryption_enc_values_supported?: string[] | undefined;
    token_endpoint_auth_methods_supported: string[];
    token_endpoint_auth_signing_alg_values_supported?: string[] | undefined;
    display_values_supported?: string[] | undefined;
    claim_types_supported?: string[] | undefined;
    claims_supported?: string[] | undefined;
    service_documentation?: string | undefined;
    claims_locales_supported?: string[] | undefined;
    ui_locales_supported?: string[] | undefined;
    claims_parameter_supported?: boolean | undefined;
    request_parameter_supported?: boolean | undefined;
    request_uri_parameter_supported?: boolean | undefined;
    require_request_uri_registration?: boolean | undefined;
    op_policy_uri?: string | undefined;
    op_tos_uri?: string | undefined;
    revocation_endpoint?: string | undefined;
    revocation_endpoint_auth_methods_supported?: string[] | undefined;
    introspection_endpoint?: string | undefined;
    introspection_endpoint_auth_methods_supported?: string[] | undefined;
    code_challenge_methods_supported?: string[] | undefined;
    end_session_endpoint?: string | undefined;
}

/**
 * OpenID Connect Standard Claims
 * @see https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
 */
export interface StandardClaims {
    sub: string;
    name?: string | undefined;
    given_name?: string | undefined;
    family_name?: string | undefined;
    middle_name?: string | undefined;
    nickname?: string | undefined;
    preferred_username?: string | undefined;
    profile?: string | undefined;
    picture?: string | undefined;
    website?: string | undefined;
    email?: string | undefined;
    email_verified?: boolean | undefined;
    gender?: string | undefined;
    birthdate?: string | undefined;
    zoneinfo?: string | undefined;
    locale?: string | undefined;
    phone_number?: string | undefined;
    phone_number_verified?: boolean | undefined;
    address?: AddressClaim | undefined;
    updated_at?: number | undefined;
}

/**
 * OpenID Connect Address Claim
 */
export interface AddressClaim {
    formatted?: string | undefined;
    street_address?: string | undefined;
    locality?: string | undefined;
    region?: string | undefined;
    postal_code?: string | undefined;
    country?: string | undefined;
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
    auth_time?: number | undefined;
    nonce?: string | undefined;
    acr?: string | undefined;
    amr?: string[] | undefined;
    azp?: string | undefined;
    at_hash?: string | undefined;
    c_hash?: string | undefined;
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
    nbf?: number | undefined;
    jti: string;
    client_id: string;
    scope: string;
}

/**
 * UserInfo Response
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
 */
export type UserInfoResponse = StandardClaims;

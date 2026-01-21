import type { Request, Response, NextFunction } from 'express';
import type { OpenIDConfiguration } from '@oauth2/shared-types';
import { keyService } from '../services/key.service.js';
import config from '../config/index.js';

/**
 * OpenID Connect Discovery Document
 * GET /.well-known/openid-configuration
 */
export async function getOpenIDConfiguration(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const issuer = config.server.issuer;

        const configuration: OpenIDConfiguration = {
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            userinfo_endpoint: `${issuer}/userinfo`,
            jwks_uri: `${issuer}/.well-known/jwks.json`,
            registration_endpoint: `${issuer}/register`,
            revocation_endpoint: `${issuer}/revoke`,
            introspection_endpoint: `${issuer}/introspect`,
            end_session_endpoint: `${issuer}/logout`,

            scopes_supported: config.oauth.supportedScopes,
            response_types_supported: config.oauth.supportedResponseTypes,
            response_modes_supported: ['query'],
            grant_types_supported: config.oauth.supportedGrantTypes,

            subject_types_supported: ['public'],

            id_token_signing_alg_values_supported: ['RS256'],
            token_endpoint_auth_methods_supported: [
                'client_secret_basic',
                'client_secret_post',
                'none',
            ],

            claims_supported: [
                'sub',
                'iss',
                'aud',
                'exp',
                'iat',
                'auth_time',
                'nonce',
                'name',
                'email',
                'email_verified',
                'picture',
            ],

            code_challenge_methods_supported: config.oauth.supportedCodeChallengeMethods,

            // Additional metadata
            claims_parameter_supported: false,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
        };

        res.json(configuration);
    } catch (error) {
        next(error);
    }
}

/**
 * JSON Web Key Set
 * GET /.well-known/jwks.json
 */
export async function getJWKS(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
        const jwks = await keyService.getJWKS();
        res.json(jwks);
    } catch (error) {
        next(error);
    }
}

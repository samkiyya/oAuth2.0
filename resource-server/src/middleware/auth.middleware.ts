import type { Request, Response, NextFunction } from 'express';
import * as jose from 'jose';
import { createLogger, OAuthErrors } from '@oauth2/shared-utils';
import config from '../config/index.js';

const logger = createLogger({ name: 'auth-middleware' });

// Extend Express Request
declare global {
    namespace Express {
        interface Request {
            user?: {
                sub: string;
                scope: string;
                clientId: string;
                email?: string;
                name?: string;
                iat?: number;
                exp?: number;
            };
        }
    }
}

// JWKS cache
let jwks: jose.JWTVerifyGetKey | null = null;
let jwksLastFetch = 0;

/**
 * Get JWKS (cached)
 */
async function getJWKS(): Promise<jose.JWTVerifyGetKey> {
    const now = Date.now();

    if (!jwks || now - jwksLastFetch > config.cache.jwksTtl) {
        logger.debug({ uri: config.auth.jwksUri }, 'Fetching JWKS');
        jwks = jose.createRemoteJWKSet(new URL(config.auth.jwksUri));
        jwksLastFetch = now;
    }

    return jwks;
}

/**
 * JWT Bearer token authentication middleware
 */
export async function requireAuth(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            res.status(401).json({
                error: 'invalid_token',
                error_description: 'Authorization header is required',
            });
            return;
        }

        if (!authHeader.startsWith('Bearer ')) {
            res.status(401).json({
                error: 'invalid_token',
                error_description: 'Authorization header must use Bearer scheme',
            });
            return;
        }

        const token = authHeader.slice(7);

        if (!token) {
            res.status(401).json({
                error: 'invalid_token',
                error_description: 'Access token is required',
            });
            return;
        }

        // Verify JWT
        const JWKS = await getJWKS();

        const { payload } = await jose.jwtVerify(token, JWKS, {
            issuer: config.auth.issuer,
            audience: config.auth.audience,
        });

        // Populate user info on request
        req.user = {
            sub: payload.sub ?? '',
            scope: (payload.scope as string) ?? '',
            clientId: (payload.client_id as string) ?? (payload.aud as string),
            email: payload.email as string | undefined,
            name: payload.name as string | undefined,
            iat: payload.iat,
            exp: payload.exp,
        };

        logger.debug({ sub: req.user.sub, scope: req.user.scope }, 'Token validated');
        next();
    } catch (error) {
        if (error instanceof jose.errors.JWTExpired) {
            logger.debug('Token expired');
            res.status(401).json({
                error: 'invalid_token',
                error_description: 'Access token has expired',
            });
            return;
        }

        if (error instanceof jose.errors.JWTClaimValidationFailed) {
            logger.debug({ error }, 'Token claim validation failed');
            res.status(401).json({
                error: 'invalid_token',
                error_description: `Token validation failed: ${error.message}`,
            });
            return;
        }

        if (error instanceof jose.errors.JWSSignatureVerificationFailed) {
            logger.warn('Token signature verification failed');
            res.status(401).json({
                error: 'invalid_token',
                error_description: 'Invalid token signature',
            });
            return;
        }

        logger.error({ error }, 'Token validation error');
        res.status(401).json({
            error: 'invalid_token',
            error_description: 'Token validation failed',
        });
    }
}

/**
 * Scope validation middleware factory
 */
export function requireScope(...requiredScopes: string[]) {
    return (req: Request, res: Response, next: NextFunction): void => {
        if (!req.user) {
            res.status(401).json({
                error: 'invalid_token',
                error_description: 'Authentication required',
            });
            return;
        }

        const tokenScopes = req.user.scope.split(' ').filter(Boolean);
        const missingScopes = requiredScopes.filter((scope) => !tokenScopes.includes(scope));

        if (missingScopes.length > 0) {
            logger.debug(
                { required: requiredScopes, actual: tokenScopes, missing: missingScopes },
                'Insufficient scope'
            );
            res.status(403).json({
                error: 'insufficient_scope',
                error_description: `Missing required scopes: ${missingScopes.join(', ')}`,
                scope: requiredScopes.join(' '),
            });
            return;
        }

        next();
    };
}

/**
 * Optional authentication - doesn't fail if no token
 */
export async function optionalAuth(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
        next();
        return;
    }

    // Try to validate, but don't fail if invalid
    await requireAuth(req, res, (err) => {
        if (err) {
            // Clear any partial user data
            req.user = undefined;
        }
        next();
    });
}

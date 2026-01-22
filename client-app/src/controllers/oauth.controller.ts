import type { Request, Response, NextFunction } from 'express';
import { oauthService, type TokenData, type UserData } from '../services/oauth.service.js';
import { createLogger } from '@oauth2/shared-utils';
import config from '../config/index.js';

const logger = createLogger({ name: 'oauth-controller' });

// Extend session data
declare module 'express-session' {
    interface SessionData {
        codeVerifier?: string | undefined;
        state?: string | undefined;
        nonce?: string | undefined;
        tokens?: TokenData | undefined;
        user?: UserData | undefined;
    }
}

/**
 * Home page
 */
export function home(req: Request, res: Response): void {
    res.render('home', {
        user: req.session.user,
        isAuthenticated: !!req.session.tokens,
    });
}

/**
 * Start OAuth login flow
 */
export function login(req: Request, res: Response): void {
    const { url, codeVerifier, state, nonce } = oauthService.generateAuthorizationRequest();

    // Store PKCE and state in session
    req.session.codeVerifier = codeVerifier;
    req.session.state = state;
    req.session.nonce = nonce;

    logger.info('Redirecting to authorization server');
    res.redirect(url);
}

/**
 * OAuth callback handler
 */
export async function callback(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
        const { code, state, error, error_description } = req.query as Record<string, string>;

        // Handle error response from auth server
        if (error) {
            logger.warn({ error, error_description }, 'Authorization error');
            res.render('error', {
                error,
                errorDescription: error_description ?? 'Authorization was denied',
            });
            return;
        }

        // Validate state parameter
        if (!state || state !== req.session.state) {
            logger.warn({ expected: req.session.state, received: state }, 'State mismatch');
            res.render('error', {
                error: 'invalid_state',
                errorDescription: 'State parameter mismatch. This may indicate a CSRF attack.',
            });
            return;
        }

        // Validate authorization code
        if (!code) {
            res.render('error', {
                error: 'missing_code',
                errorDescription: 'Authorization code was not received',
            });
            return;
        }

        // Get code verifier from session
        const codeVerifier = req.session.codeVerifier;
        if (!codeVerifier) {
            res.render('error', {
                error: 'missing_verifier',
                errorDescription: 'PKCE code verifier not found. Please try logging in again.',
            });
            return;
        }

        // Exchange code for tokens
        const tokens = await oauthService.exchangeCodeForTokens(code, codeVerifier);

        // Clear temporary PKCE values
        delete req.session.codeVerifier;
        delete req.session.state;
        delete req.session.nonce;

        // Store tokens in session
        req.session.tokens = {
            accessToken: tokens.access_token,
            refreshToken: tokens.refresh_token,
            idToken: tokens.id_token,
            expiresAt: Date.now() + tokens.expires_in * 1000,
            scope: tokens.scope ?? '',
        };

        // Get user info from ID token or userinfo endpoint
        try {
            if (tokens.id_token) {
                const claims = oauthService.parseIdToken(tokens.id_token);
                req.session.user = {
                    sub: claims.sub as string,
                    email: claims.email as string | undefined,
                    name: claims.name as string | undefined,
                    picture: claims.picture as string | undefined,
                };
            } else {
                const userInfo = await oauthService.getUserInfo(tokens.access_token);
                req.session.user = {
                    sub: userInfo.sub,
                    email: userInfo.email,
                    name: userInfo.name,
                    picture: userInfo.picture,
                };
            }
        } catch (err) {
            logger.warn({ error: err }, 'Failed to fetch user info');
        }

        logger.info({ userId: req.session.user?.sub }, 'User authenticated successfully');
        res.redirect('/dashboard');
    } catch (error) {
        logger.error({ error }, 'Callback error');
        next(error);
    }
}

/**
 * Dashboard (authenticated users only)
 */
export async function dashboard(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
        if (!req.session.tokens) {
            res.redirect('/login');
            return;
        }

        // Check if token needs refresh
        if (
            req.session.tokens.refreshToken &&
            oauthService.isTokenExpired(req.session.tokens.expiresAt)
        ) {
            try {
                logger.info('Refreshing expired access token');
                const newTokens = await oauthService.refreshAccessToken(req.session.tokens.refreshToken);

                req.session.tokens = {
                    accessToken: newTokens.access_token,
                    refreshToken: newTokens.refresh_token ?? req.session.tokens.refreshToken,
                    idToken: newTokens.id_token ?? req.session.tokens.idToken,
                    expiresAt: Date.now() + newTokens.expires_in * 1000,
                    scope: newTokens.scope ?? req.session.tokens.scope,
                };
            } catch (err) {
                logger.warn({ error: err }, 'Token refresh failed, redirecting to login');
                delete req.session.tokens;
                delete req.session.user;
                res.redirect('/login');
                return;
            }
        }

        const tokens = req.session.tokens!;
        res.render('dashboard', {
            user: req.session.user,
            tokens: {
                accessToken: `${tokens.accessToken.substring(0, 50)}...`,
                refreshToken: tokens.refreshToken
                    ? `${tokens.refreshToken.substring(0, 20)}...`
                    : null,
                expiresIn: Math.max(0, Math.floor((tokens.expiresAt - Date.now()) / 1000)),
                scope: tokens.scope,
            },
        });
    } catch (error) {
        next(error);
    }
}

/**
 * Call protected API
 */
export async function callApi(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
        if (!req.session.tokens) {
            res.redirect('/login');
            return;
        }

        const data = await oauthService.callProtectedApi(
            req.session.tokens.accessToken,
            '/api/v1/profile'
        );

        res.render('api-result', {
            user: req.session.user,
            data,
        });
    } catch (error) {
        logger.error({ error }, 'API call failed');
        next(error);
    }
}

/**
 * Logout - revoke tokens and clear session
 */
export async function logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
        // Revoke tokens if present
        if (req.session.tokens) {
            if (req.session.tokens.refreshToken) {
                await oauthService.revokeToken(req.session.tokens.refreshToken, 'refresh_token');
            }
            await oauthService.revokeToken(req.session.tokens.accessToken, 'access_token');
        }

        // Destroy session
        req.session.destroy((err) => {
            if (err) {
                logger.error({ error: err }, 'Session destruction failed');
            }
            res.clearCookie(config.session.name);
            res.redirect('/');
        });
    } catch (error) {
        next(error);
    }
}

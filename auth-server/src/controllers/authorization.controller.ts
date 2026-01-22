import type { Request, Response, NextFunction } from 'express';
import type { ResponseType, CodeChallengeMethod } from '@oauth2/shared-types';
import { clientService } from '../services/client.service.js';
import { authorizationService } from '../services/authorization.service.js';
import { OAuthErrors } from '@oauth2/shared-utils';

/**
 * Authorization endpoint
 * GET /authorize
 */
export async function authorize(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        // Get parameters from query or pending auth
        const pendingAuth = req.session.pendingAuth;
        const params = {
            responseType: ((req.query.response_type as string) ?? pendingAuth?.clientId ? 'code' : '') as ResponseType,
            clientId: (req.query.client_id as string) ?? pendingAuth?.clientId ?? '',
            redirectUri: (req.query.redirect_uri as string) ?? pendingAuth?.redirectUri ?? '',
            scope: (req.query.scope as string) ?? pendingAuth?.scope ?? '',
            state: (req.query.state as string) ?? pendingAuth?.state,
            codeChallenge: (req.query.code_challenge as string) ?? pendingAuth?.codeChallenge,
            codeChallengeMethod: ((req.query.code_challenge_method as string) ?? pendingAuth?.codeChallengeMethod) as CodeChallengeMethod | undefined,
            nonce: (req.query.nonce as string) ?? pendingAuth?.nonce,
            prompt: req.query.prompt as string | undefined,
        };

        // Clear pending auth from session
        delete req.session.pendingAuth;

        // Validate basic request parameters
        if (!params.clientId) {
            throw OAuthErrors.invalidRequest('client_id is required');
        }

        if (!params.redirectUri) {
            throw OAuthErrors.invalidRequest('redirect_uri is required');
        }

        // Validate authorization request
        authorizationService.validateAuthorizationRequest(params);

        // Validate client and redirect URI
        const client = await clientService.validateClientForAuthorization(params.clientId);
        clientService.validateRedirectUri(client, params.redirectUri);

        // Parse and validate scopes
        const scopes = clientService.validateScope(client, params.scope);

        // User must be logged in
        if (!req.session.userId || !(req as any).user) {
            // Store pending auth and redirect to login
            req.session.pendingAuth = {
                clientId: params.clientId,
                redirectUri: params.redirectUri,
                scope: params.scope,
                state: params.state,
                codeChallenge: params.codeChallenge,
                codeChallengeMethod: params.codeChallengeMethod,
                nonce: params.nonce,
            };
            res.redirect('/login');
            return;
        }

        const user = (req as any).user;

        // Check if prompt=none
        if (params.prompt === 'none') {
            // User must already have consent
            const hasConsent = await authorizationService.hasConsent(
                user._id,
                client.clientId,
                scopes
            );

            if (!hasConsent) {
                const errorUrl = new URL(params.redirectUri);
                errorUrl.searchParams.set('error', 'consent_required');
                if (params.state) {
                    errorUrl.searchParams.set('state', params.state);
                }
                res.redirect(errorUrl.toString());
                return;
            }

            // Generate code immediately
            const code = await authorizationService.generateAuthorizationCode(user, client, params);
            const redirectUrl = new URL(params.redirectUri);
            redirectUrl.searchParams.set('code', code);
            if (params.state) {
                redirectUrl.searchParams.set('state', params.state);
            }
            res.redirect(redirectUrl.toString());
            return;
        }

        // Check for existing consent (skip consent screen if already consented)
        const hasConsent = await authorizationService.hasConsent(
            user._id,
            client.clientId,
            scopes
        );

        if (hasConsent && params.prompt !== 'consent') {
            // Generate authorization code directly
            const code = await authorizationService.generateAuthorizationCode(user, client, params);

            const redirectUrl = new URL(params.redirectUri);
            redirectUrl.searchParams.set('code', code);
            if (params.state) {
                redirectUrl.searchParams.set('state', params.state);
            }

            res.redirect(redirectUrl.toString());
            return;
        }

        // Show consent screen
        res.render('consent', {
            client: {
                name: client.clientName,
                logoUri: client.logoUri,
                policyUri: client.policyUri,
                tosUri: client.tosUri,
            },
            scopes: scopes.map((scope) => ({
                name: scope,
                description: getScopeDescription(scope),
            })),
            user: {
                email: user.email,
                name: user.profile.name,
            },
            params: {
                clientId: params.clientId,
                redirectUri: params.redirectUri,
                scope: params.scope,
                state: params.state,
                codeChallenge: params.codeChallenge,
                codeChallengeMethod: params.codeChallengeMethod,
                nonce: params.nonce,
            },
            csrfToken: req.session.id,
        });
    } catch (error) {
        // For OAuth errors, redirect back to client with error
        if (error instanceof Error && 'error' in error) {
            const oauthError = error as { error: string; errorDescription?: string };
            const redirectUri = req.query.redirect_uri as string;
            const state = req.query.state as string | undefined;

            if (redirectUri && isValidRedirectUri(redirectUri)) {
                const errorUrl = new URL(redirectUri);
                errorUrl.searchParams.set('error', oauthError.error);
                if (oauthError.errorDescription) {
                    errorUrl.searchParams.set('error_description', oauthError.errorDescription);
                }
                if (state) {
                    errorUrl.searchParams.set('state', state);
                }
                res.redirect(errorUrl.toString());
                return;
            }
        }

        next(error);
    }
}

/**
 * Handle consent form submission
 * POST /authorize
 */
export async function handleConsent(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        const { action, clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, nonce } = req.body;

        if (!(req as any).user) {
            res.redirect('/login');
            return;
        }

        const user = (req as any).user;
        const client = await clientService.validateClientForAuthorization(clientId);
        clientService.validateRedirectUri(client, redirectUri);
        const scopes = clientService.validateScope(client, scope);

        const params = {
            responseType: 'code' as ResponseType,
            clientId,
            redirectUri,
            scope,
            state,
            codeChallenge,
            codeChallengeMethod: codeChallengeMethod as CodeChallengeMethod | undefined,
            nonce,
        };

        if (action === 'deny') {
            // User denied consent
            const errorUrl = new URL(redirectUri);
            errorUrl.searchParams.set('error', 'access_denied');
            errorUrl.searchParams.set('error_description', 'User denied the authorization request');
            if (state) {
                errorUrl.searchParams.set('state', state);
            }
            res.redirect(errorUrl.toString());
            return;
        }

        // Record consent
        await authorizationService.recordConsent(user._id, client.clientId, scopes);

        // Generate authorization code
        const code = await authorizationService.generateAuthorizationCode(user, client, params);

        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (state) {
            redirectUrl.searchParams.set('state', state);
        }

        res.redirect(redirectUrl.toString());
    } catch (error) {
        next(error);
    }
}

/**
 * Get human-readable scope description
 */
function getScopeDescription(scope: string): string {
    const descriptions: Record<string, string> = {
        openid: 'Authenticate you using your account',
        profile: 'Access your profile information (name, picture)',
        email: 'Access your email address',
        offline_access: 'Access your data when you are not using the application',
    };

    return descriptions[scope] ?? `Access to ${scope}`;
}

/**
 * Basic validation that redirect URI is a valid URL
 */
function isValidRedirectUri(uri: string): boolean {
    try {
        const url = new URL(uri);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
}

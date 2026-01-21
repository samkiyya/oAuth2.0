import * as authService from '../services/auth.service.js';
import logger from '../utils/logger.js';

async function authorize(req, res, next) {
    const { response_type, client_id, redirect_uri, scope = '', state, code_challenge, code_challenge_method } = req.query;

    try {
        if (response_type !== 'code') {
            throw new Error('Only response_type code is supported');
        }
        if (!code_challenge || code_challenge_method !== 'S256') {
            throw new Error('Invalid or missing PKCE parameters');
        }

        const client = await authService.validateClient(client_id, redirect_uri);
        const code = await authService.generateAuthorizationCode(client, redirect_uri, code_challenge, scope);

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.append('code', code);
        if (state) {
            redirectUrl.searchParams.append('state', state);
        }
        res.redirect(redirectUrl.toString());
    } catch (error) {
        logger.error(error.message);
        next(error);
    }
}

async function token(req, res, next) {
    const { grant_type } = req.body;

    try {
        if (grant_type === 'authorization_code') {
            const { code, redirect_uri, client_id, code_verifier } = req.body;
            const tokenResponse = await authService.exchangeCodeForToken(code, redirect_uri, client_id, code_verifier);
            return res.json(tokenResponse);
        }

        if (grant_type === 'refresh_token') {
            const { refresh_token, client_id } = req.body;
            const tokenResponse = await authService.refreshToken(refresh_token, client_id);
            return res.json(tokenResponse);
        }

        throw new Error('unsupported_grant_type');
    } catch (error) {
        logger.error(error.message);
        next(error);
    }
}

async function jwks(req, res, next) {
    try {
        const jwks = await authService.getJWKS();
        res.json(jwks);
    } catch (error) {
        logger.error(error.message);
        next(error);
    }
}

export { authorize, token, jwks };

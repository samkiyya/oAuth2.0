import { jwtVerify, createRemoteJWKSet } from 'jose';
import config from '../../config.js';

const JWKS_URL = new URL(`${config.authServerUrl}/.well-known/jwks.json`);
const JWKS = createRemoteJWKSet(JWKS_URL);

async function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'invalid_request', error_description: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.slice('Bearer '.length);
    try {
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: config.authServerUrl,
            audience: config.audience,
        });
        req.user = payload;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'invalid_token', error_description: 'Invalid or expired token' });
    }
}

function requireScope(scope) {
    return (req, res, next) => {
        const scopes = String(req.user?.scope || '').split(' ').filter(Boolean);
        if (!scopes.includes(scope)) {
            return res.status(403).json({ error: 'insufficient_scope', error_description: `Required scope: ${scope}` });
        }
        next();
    };
}

export { requireAuth, requireScope };

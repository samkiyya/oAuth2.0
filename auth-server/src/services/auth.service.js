import { randomBytes, createHash } from 'crypto';
import { signJWT, exportJWK, importPKCS8 } from 'jose';
import config from '../../config.js';
import db from '../db/index.js';

const KEY_ID = 'test-key-1';

function base64url(input) {
    return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function sha256Base64url(str) {
    const hash = createHash('sha256').update(str).digest();
    return base64url(hash);
}

function generateCode() {
    return base64url(randomBytes(32));
}

function getDemoUser() {
    return {
        sub: 'user123',
        name: 'Demo User',
        email: 'demo@example.com'
    };
}

async function validateClient(client_id, redirect_uri) {
    const client = db.data.clients.find(c => c.client_id === client_id);
    if (!client) {
        throw new Error('Invalid client_id');
    }
    if (!client.redirect_uris.includes(redirect_uri)) {
        throw new Error('Invalid redirect_uri');
    }
    return client;
}

async function generateAuthorizationCode(client, redirect_uri, code_challenge, scope) {
    const user = getDemoUser();
    const code = generateCode();
    db.data.authCodes.push({
        code,
        clientId: client.client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        scope,
        user,
        expiresAt: Date.now() + 5 * 60 * 1000 // 5 minutes
    });
    await db.write();
    return code;
}

async function exchangeCodeForToken(code, redirect_uri, client_id, code_verifier) {
    const authRecord = db.data.authCodes.find(c => c.code === code);
    if (!authRecord) {
        throw new Error('Authorization code not found');
    }
    if (authRecord.expiresAt < Date.now()) {
        db.data.authCodes = db.data.authCodes.filter(c => c.code !== code);
        await db.write();
        throw new Error('Authorization code expired');
    }
    if (authRecord.clientId !== client_id || authRecord.redirectUri !== redirect_uri) {
        throw new Error('Mismatched client_id or redirect_uri');
    }

    const computedChallenge = sha256Base64url(code_verifier);
    if (computedChallenge !== authRecord.codeChallenge) {
        throw new Error('PKCE verification failed');
    }
    db.data.authCodes = db.data.authCodes.filter(c => c.code !== code); // single use
    await db.write();

    const privateKey = await importPKCS8(config.privateKey, 'RS256');

    const accessToken = await new signJWT({
        scope: authRecord.scope,
        name: authRecord.user.name,
        email: authRecord.user.email
    })
        .setProtectedHeader({ alg: 'RS256', kid: KEY_ID })
        .setIssuer(config.issuer)
        .setAudience(client_id)
        .setSubject(authRecord.user.sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(privateKey);

    const refresh_token = generateCode();
    db.data.refreshTokens.push({
        token: refresh_token,
        sub: authRecord.user.sub,
        scope: authRecord.scope,
        clientId: client_id,
    });
    await db.write();

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 900,
        refresh_token,
        scope: authRecord.scope
    };
}

async function refreshToken(refresh_token, client_id) {
    const tokenRecord = db.data.refreshTokens.find(t => t.token === refresh_token);
    if (!tokenRecord) {
        throw new Error('Refresh token not found');
    }
    if (tokenRecord.clientId !== client_id) {
        throw new Error('Mismatched client_id');
    }

    const privateKey = await importPKCS8(config.privateKey, 'RS256');

    const accessToken = await new signJWT({
        scope: tokenRecord.scope,
    })
        .setProtectedHeader({ alg: 'RS256', kid: KEY_ID })
        .setIssuer(config.issuer)
        .setAudience(client_id)
        .setSubject(tokenRecord.sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(privateKey);

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 900
    };
}

async function getJWKS() {
    const privateKey = await importPKCS8(config.privateKey, 'RS256');
    const jwk = await exportJWK(privateKey);
    jwk.use = 'sig';
    jwk.alg = 'RS256';
    jwk.kid = KEY_ID;
    return { keys: [jwk] };
}

export {
    validateClient,
    generateAuthorizationCode,
    exchangeCodeForToken,
    refreshToken,
    getJWKS,
};

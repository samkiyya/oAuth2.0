import axios from 'axios';
import { randomBytes, createHash } from 'crypto';
import { URLSearchParams } from 'url';
import config from '../../config.js';

function base64url(input) {
    return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function generateCodeVerifier() {
    return base64url(randomBytes(32));
}

function generateCodeChallenge(codeVerifier) {
    const hash = createHash('sha256').update(codeVerifier).digest();
    return base64url(hash);
}

function generateState() {
    return base64url(randomBytes(16));
}

function getAuthorizeUrl(code_challenge, state) {
    const authorizeUrl = new URL(`${config.authServerUrl}/authorize`);
    authorizeUrl.searchParams.append('response_type', 'code');
    authorizeUrl.searchParams.append('client_id', config.clientId);
    authorizeUrl.searchParams.append('redirect_uri', config.redirectUri);
    authorizeUrl.searchParams.append('scope', config.scope);
    authorizeUrl.searchParams.append('state', state);
    authorizeUrl.searchParams.append('code_challenge', code_challenge);
    authorizeUrl.searchParams.append('code_challenge_method', 'S256');
    return authorizeUrl.toString();
}

async function exchangeCodeForToken(code, code_verifier) {
    const tokenResponse = await axios.post(
        `${config.authServerUrl}/token`,
        new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: config.redirectUri,
            client_id: config.clientId,
            client_secret: config.clientSecret,
            code_verifier: code_verifier,
        }).toString(),
        {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }
    );
    return tokenResponse.data;
}

async function refreshAccessToken(refresh_token) {
    const tokenResponse = await axios.post(
        `${config.authServerUrl}/token`,
        new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refresh_token,
            client_id: config.clientId,
            client_secret: config.clientSecret,
        }).toString(),
        {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }
    );
    return tokenResponse.data;
}

async function getProfile(access_token) {
    const apiResponse = await axios.get(`${config.resourceServerUrl}/profile`, {
        headers: {
            Authorization: `Bearer ${access_token}`,
        },
    });
    return apiResponse.data;
}

export {
    generateCodeVerifier,
    generateCodeChallenge,
    generateState,
    getAuthorizeUrl,
    exchangeCodeForToken,
    refreshAccessToken,
    getProfile,
};

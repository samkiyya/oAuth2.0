import * as clientService from '../services/client.service.js';

function home(req, res) {
    res.send(`<html>
        <body>
        <h2>Client App</h2>
        <p>This app uses OAuth2 Authorization Code Flow with PKCE to access a protected resource.</p>
        <a href="/login">Login with Authorization Server</a>
        </body>
        </html>`);
}

function login(req, res) {
    const code_verifier = clientService.generateCodeVerifier();
    const state = clientService.generateState();
    
    req.session.code_verifier = code_verifier;
    req.session.state = state;

    const code_challenge = clientService.generateCodeChallenge(code_verifier);
    const authorizeUrl = clientService.getAuthorizeUrl(code_challenge, state);

    res.redirect(authorizeUrl);
}

async function callback(req, res) {
    const { code, state } = req.query;
    const { state: storedState, code_verifier } = req.session;

    if (!code) {
        return res.status(400).send('Authorization code not found');
    }
    if (!state || state !== storedState) {
        return res.status(400).send('Invalid state, state mismatch');
    }

    try {
        const tokenData = await clientService.exchangeCodeForToken(code, code_verifier);
        req.session.access_token = tokenData.access_token;
        req.session.refresh_token = tokenData.refresh_token;

        res.send(`<html>
            <body>
            <h2>Logged in Successfully</h2>
            <p>Access Token Expires In: ${tokenData.expires_in} seconds</p>
            <p>Access Token: ${tokenData.access_token}</p>
            <p>Refresh Token: ${tokenData.refresh_token}</p>
            <a href="/profile">Call Protected API</a><br/><br/>
            <a href="/refresh">Refresh access token</a>
            </body>
            </html>`);
    } catch (error) {
        const message = error?.response?.data ? JSON.stringify(error.response.data) : error.message;
        return res.status(500).send(`Error exchanging code for token: ${message}`);
    }
}

async function profile(req, res) {
    const { access_token } = req.session;
    if (!access_token) {
        return res.redirect('/');
    }

    try {
        const profileData = await clientService.getProfile(access_token);
        res.send(`<pre>${JSON.stringify(profileData, null, 2)}</pre>`);
    } catch (error) {
        const message = error?.response?.data ? JSON.stringify(error.response.data) : error.message;
        return res.status(500).send(`Error fetching protected resource: ${message}`);
    }
}

async function refresh(req, res) {
    const { refresh_token } = req.session;
    if (!refresh_token) {
        return res.redirect('/');
    }

    try {
        const tokenData = await clientService.refreshAccessToken(refresh_token);
        req.session.access_token = tokenData.access_token;

        res.send(`<h3>Refreshed Access token</h3>
            <a href="/profile">Call protected API again</a>`);
    } catch (error) {
        const message = error?.response?.data ? JSON.stringify(error.response.data) : error.message;
        return res.status(500).send(`Error refreshing token: ${message}`);
    }
}

export { home, login, callback, profile, refresh };

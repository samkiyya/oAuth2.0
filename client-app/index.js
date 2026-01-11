import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import axios from 'axios';
import {randomBytes, createHash} from 'crypto';
import { URLSearchParams } from 'url';

dotenv.config();

const app = express();
app.use(cookieParser());
const PORT = process.env.PORT || 4040;
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'http://localhost:5000';
const RESOURCE_SERVER = process.env.RESOURCE_SERVER || 'http://localhost:4000';
const CLIENT_ID = process.env.CLIENT_ID || 'test-client';
const REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/callback`;

//helpers
function base64url(input){
    return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateCodeVerifier(){
    return base64url(randomBytes(32));
}

function generateCodeChallenges256(codeVerifier){
    const hash = createHash('sha256').update(codeVerifier).digest();
    return base64url(hash);
}

function generateState(){
    return base64url(randomBytes(16));
}

app.get('/login', (req, res) => {
    res.send(`<html>
        <body>
        <h2>Client App</h2>
        <p> this app uses OAuth2 Authorization Code Flow with PKCE to access a protected resource.</p>
        <a href="/login">Login with Authorization Server</a>
        </body>
        </html>`);
});

app.get('/login', (req, res) => {
    const code_verifier = generateCodeVerifier();
    const code_challenge = generateCodeChallenges256(code_verifier);
    const state = generateState();
    // Store code_verifier and state in cookies for later verification in production, use server-side session store
res.cookie('code_verifier', code_verifier, {httpOnly: true, secure: true});
res.cookie('auth_state', state, {httpOnly: true, secure: true});
const authorizeUrl = new URL(`${AUTH_SERVER_URL}/authorize`);

authorizeUrl.searchParams.append('response_type', 'code');
authorizeUrl.searchParams.append('client_id', CLIENT_ID);
authorizeUrl.searchParams.append('redirect_uri', REDIRECT_URI);
authorizeUrl.searchParams.append('scope', 'api.read openid profile email');
authorizeUrl.searchParams.append('state', state);
authorizeUrl.searchParams.append('code_challenge', code_challenge);
authorizeUrl.searchParams.append('code_challenge_method', 'S256');
    res.redirect(authorizeUrl.toString());
});

app.get('/callback', async (req, res) => {
    const {code, state} = req.query;
    const storedState = req.cookies['auth_state'];
    const code_verifier = req.cookies['code_verifier'];

    if (!code) return res.status(400).send('Authorization code not found');
    if(!state || state !== storedState){
        return res.status(400).send('Invalid state, state mismatch');
    }

    // Exchange authorization code for tokens
    const tokenResponse = await axios.post(`${AUTH_SERVER_URL}/token`, new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: code_verifier
    }).toString,
    {
        headers:{'Content-Type': 'application/x-www-form-urlencoded'}
    });
    const {access_token, refresh_token, expires_in} = tokenResponse.data;
    res.cookie('access_token', access_token, {httpOnly: true, secure: true});
    res.cookie('refresh_token', refresh_token, {httpOnly: true, secure: true});
    res.send(`<html>
        <body>
        <h2>Logged in Successfully</h2>
        <p>Access Token Expires In: ${expires_in} seconds</p>
        <p>Access Token: ${access_token}</p>
        <p>Refresh Token: ${refresh_token}</p>
        <a href="/profile">call Protected API</a><br/> </br/>
        <a href="/refresh">Refresh access token</a>
        </body>
        </html>`);
});

app.get('/profile',async (req, res)=>{
    const accessToken = req.cookies.access_token;
    if(!accessToken){
        return res.redirect('/');
    }
    try{
const apiResponse = await axios.get(`${RESOURCE_SERVER}/profile`, {
    headers: {
        'Authorization': `Bearer ${accessToken}`    
    }});
    res.send(`
        <pre>
        ${JSON.stringify(apiResponse.data,null,2)}
        </pre>
        `);
}
    catch(error){
        const message=error?.response.data?JSON.stringify(error.response.data):error.message;
        return res.status(500).send(`Error fetching protected resource: ${message}`);
    }
});

app.get('/refresh',async(req, res)=>{
    const refreshToken = req.cookies.refresh_token;
    if(!refreshToken) return res.redirect('/');

    const tokenResponse = await axios.post(`${AUTH_SERVER_URL}/token`,new URLSearchParams(
        {
            grant_type:"refresh_token",
            refresh_token:refreshToken,
            client_id:CLIENT_ID
        }
    ).toString(),
    {
headers:{"Content-Type":"application/x-www-form-urlencoded"}
    });
    res.cookie("access_token",tokenResponse.data.access_token,{httpOnly:true});
    res.send(`
        <h3>
        Refreshed Access token
        </h3>
        <a href="/profile"> call protected API again</a>
        `);
})

app.listen(PORT, () => {
    console.log(`Client App running on http://localhost:${PORT}`);
});
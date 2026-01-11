import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import {randomBytes, createHash} from 'crypto';
import {signJWT, exportJWK, importPKCS8} from 'jose';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
app.use(cookieParser())

const clients = new Map();
const authCodes=new Map();
const refreshTokens=new Map();

clients.set('test-client',{
    client_id:'test-client',
    redirect_uris:['http://localhost:4040/callback'],
});

const PRIVATE_KEY_PEM=`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDO6k1b0p6l6T6uU
...
-----END PRIVATE KEY-----`;

const ISSUER='http://localhost:5000';
const KEY_ID='test-key-1';

function base64url(input){
    return input.toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
}

function sha256Base64url(str){
    const hash= createHash('sha256').update(str).digest();
    return base64url(hash);
}

function generateCode(){
    return base64url(randomBytes(32));
}

function getDemoUser(){
    return {
        sub:'user123',
        name:'Demo User',
        email:'demo@example.com'
    };}

app.get('/authorize',(req,res)=>{
    const {response_type, client_id, redirect_uri, scope='',state,code_challenge,code_challenge_method} = req.query;

    const client =clients.get(client_id);
    if(!client){
        return res.status(400).send('Invalid client_id');
    }
    if(!client.redirect_uris.includes(redirect_uri)){
        return res.status(400).send('Invalid redirect_uri');
    }
    if(response_type !=='code'){
        return res.status(400).send('Only response_type code is supported');
    }
    if(!code_challenge || code_challenge_method !=='S256'){
        return res.status(400).send('Invalid or missing PKCE parameters');
    }

    // Normally: show login and consent UI here
    //for test simplicity: auth login and consent are skipped

    const user = getDemoUser();
    const code = generateCode();
    authCodes.set(code,{
        clientId:client_id,
        redirectUri:redirect_uri,
        codeChallenge:code_challenge,
        scope,
        user,
        expiresAt:Date.now()+5*60*1000 // 5 minutes
    });

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.append('code',code);
    if(state){
        redirectUrl.searchParams.append('state',state);
    }
    res.redirect(redirectUrl.toString());

});

/**
 * POST /token
 * supports:
 * - grant_type=authorization_code with PKCE
 * - grant_type=refresh_token
 */
app.post('/token',async (req,res)=>{
    const {grant_type}=req.body;
    if(grant_type==='authorization_code'){
        const {code,redirect_uri,client_id,code_verifier}=req.body;
        const authRecord=authCodes.get(code);
        if(!authRecord){
            return res.status(400).json({error:'invalid_grant', error_description:'Authorization code not found',error_code:'code_not_found' });
        }
        if(authRecord.expiresAt < Date.now()){
            authCodes.delete(code);
            return res.status(400).json({error:'invalid_grant', error_description:'Authorization code expired',error_code:'code_expired' });
        }
        if(authRecord.clientId !== client_id || authRecord.redirectUri !== redirect_uri){
            return res.status(400).json({error:'invalid_grant', error_description:'Mismatched client_id or redirect_uri', error_code:'mismatched_client_or_redirect' });
        }

        // pkce Validation
        const computedChallenge=sha256Base64url(code_verifier);
        if(computedChallenge !== authRecord.codeChallenge){
            return res.status(400).json({error:'invalid_grant', error_description:'PKCE verification failed', error_code:'pkce_verification_failed' });
        }
        authCodes.delete(code); // single use

        //create jwt access token
        const privateKey = await importPKCS8(PRIVATE_KEY_PEM,'RS256');
        
        const accessToken= await new signJWT({
            scope:authRecord.scope,
            name:authRecord.user.name,
            email:authRecord.user.email
        })
        .setProtectedHeader({alg:'RS256', kid:KEY_ID})
        .setIssuer(ISSUER)
        .setAudience(client_id)
        .setSubject(authRecord.user.sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(privateKey);

        //create refresh token
        const refresh_token=generateCode();
        refreshTokens.set(refresh_token,{
            sub:authRecord.user.sub,
            scope:authRecord.scope,
            clientId:client_id,
        });
        return res.json({
            access_token:accessToken,
            token_type:'Bearer',
            expires_in:900,
            refresh_token,
            scope:authRecord.scope
        })
    }
    if(grant_type==='refresh_token'){
        const {refresh_token,client_id}=req.body;
        const tokenRecord=refreshTokens.get(refresh_token);
        if(!tokenRecord){
            return res.status(400).json({error:'invalid_grant', error_description:'Refresh token not found', error_code:'refresh_token_not_found' });
        }
        if(tokenRecord.clientId !== client_id){
            return res.status(400).json({error:'invalid_grant', error_description:'Mismatched client_id', error_code:'mismatched_client' });
        }

        const privateKey = await importPKCS8(PRIVATE_KEY_PEM,'RS256');

        //create new jwt access token
        const accessToken= await new signJWT({
            scope:tokenRecord.scope,
        })
        .setProtectedHeader({alg:'RS256', kid:KEY_ID})
        .setIssuer(ISSUER)
        .setAudience(client_id)
        .setSubject(tokenRecord.sub)
        .setIssuedAt()
        .setExpirationTime('15m')
        .sign(privateKey);

        return res.json({
            access_token:accessToken,
            token_type:'Bearer',
            expires_in:900
        });
    }
    return res.status(400).json({error:'unsupported_grant_type', error_description:'Only authorization_code and refresh_token grant types are supported', error_code:'unsupported_grant_type' });
});

/**
 *  JWKS endpoint:
 * Resource servers fetch public keys here to validate JWT signed by the auth server
 */
app.get('/.well-known/jwks.json',async (req,res)=>{
    const privateKey = await importPKCS8(PRIVATE_KEY_PEM,'RS256');

    // jose exports jwk from a key object, but we need public jwk
    // for test simplicity, jose can export from private key too (it includes public key parts)

    const jwk = await exportJWK(privateKey);
    jwk.use='sig';
    jwk.alg='RS256';
    jwk.kid=KEY_ID;
    res.json({keys:[jwk]});
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Authorization server running on http://localhost:${PORT}`);
});
import express from 'express';
import { jwtVerify, createRemoteJWKSet } from 'jose';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
const PORT= process.env.PORT || 4000;

app.use(express.json());

const ISSUER = 'http://localhost:5000';
const AUDIENCE = 'test-client';
const JWKS_URL = new URL(`${ISSUER}/.well-known/jwks.json`);

const JWKS = createRemoteJWKSet(JWKS_URL);

async function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'invalid_request', error_description: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.slice('Bearer '.length);
    try{
const { payload } = await jwtVerify(token, JWKS, {
        issuer: ISSUER,
        audience: AUDIENCE, 
    });
    req.user = payload;
    next();
}
    catch (err) {
return res.status(401).json({ error: 'invalid_token', error_description: 'Invalid or expired token' });
    }
}

function requireScope(scope) {
    return (req, res, next) => {
        const scopes = String(req.user?.scope||'').split(' ').filter(Boolean);
        if (!scopes.includes(scope)) {
            return res.status(403).json({ error: 'insufficient_scope', error_description: `Required scope: ${scope}` });
        }
        next();
    };
}

app.get('/api/profile',requireAuth, requireScope('profile'), (req, res) => {
    res.json({
        message: 'This is the protected profile information.',
        user:{
            sub: req.user.sub,
            name:req.user.name,
            email:req.user.email,
            scope:req.user.scope
        }
    });
});

app.listen(PORT, () => {
  console.log(`Resource Server running on port ${PORT}`);
});
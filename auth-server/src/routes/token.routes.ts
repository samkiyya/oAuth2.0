import { Router } from 'express';
import { token, revoke, introspect } from '../controllers/token.controller.js';
import { tokenRateLimiter } from '../middleware/rateLimit.middleware.js';
import { noCacheMiddleware } from '../middleware/security.middleware.js';

const router: Router = Router();

// Token endpoint
router.post('/token', noCacheMiddleware, tokenRateLimiter, token);

// Token revocation endpoint (RFC 7009)
router.post('/revoke', noCacheMiddleware, revoke);

// Token introspection endpoint (RFC 7662)
router.post('/introspect', noCacheMiddleware, introspect);

export default router;

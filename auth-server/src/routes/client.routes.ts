import { Router } from 'express';
import {
    registerClient,
    getClientConfiguration,
    rotateClientSecret,
} from '../controllers/client.controller.js';
import { registrationRateLimiter } from '../middleware/rateLimit.middleware.js';
import { noCacheMiddleware } from '../middleware/security.middleware.js';

const router: Router = Router();

// Dynamic Client Registration (RFC 7591)
router.post('/register', noCacheMiddleware, registrationRateLimiter, registerClient);
router.get('/register/:clientId', noCacheMiddleware, getClientConfiguration);
router.post('/register/:clientId/rotate', noCacheMiddleware, rotateClientSecret);

export default router;

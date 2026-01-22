import { Router } from 'express';
import {
    getMFASetup,
    enableMFA,
    getMFAVerify,
    verifyMFA,
    getMFAManage,
    disableMFA,
} from '../controllers/mfa.controller.js';
import { requireSession } from '../middleware/session.middleware.js';
import { noCacheMiddleware } from '../middleware/security.middleware.js';

const router: Router = Router();

// MFA setup (requires auth)
router.get('/mfa/setup', noCacheMiddleware, requireSession, getMFASetup);
router.post('/mfa/setup', noCacheMiddleware, requireSession, enableMFA);

// MFA verification during login
router.get('/mfa/verify', noCacheMiddleware, getMFAVerify);
router.post('/mfa/verify', noCacheMiddleware, verifyMFA);

// MFA management
router.get('/mfa/manage', noCacheMiddleware, requireSession, getMFAManage);
router.post('/mfa/disable', noCacheMiddleware, requireSession, disableMFA);

export default router;

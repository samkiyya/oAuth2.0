import { Router } from 'express';
import { authorize, handleConsent } from '../controllers/authorization.controller.js';
import { loadUser } from '../middleware/session.middleware.js';
import { noCacheMiddleware } from '../middleware/security.middleware.js';

const router: Router = Router();

// Authorization endpoint
router.get('/authorize', noCacheMiddleware, loadUser, authorize);
router.post('/authorize', noCacheMiddleware, loadUser, handleConsent);

export default router;

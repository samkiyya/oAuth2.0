import { Router } from 'express';
import { requireAuth, requireScope } from '../../middleware/auth.middleware.js';
import { getProfile, getUser, getResources } from '../../controllers/resource.controller.js';

const router: Router = Router();

// Protected endpoints - require valid access token and specific scopes
router.get('/profile', requireAuth, requireScope('profile'), getProfile);
router.get('/user', requireAuth, requireScope('email'), getUser);
router.get('/resources', requireAuth, requireScope('read'), getResources);

export default router;

import { Router } from 'express';
import {
    getLogin,
    postLogin,
    getRegister,
    postRegister,
    logout,
    getUserInfo,
} from '../controllers/user.controller.js';
import { authRateLimiter, registrationRateLimiter } from '../middleware/rateLimit.middleware.js';
import { requireNoSession, loadUser } from '../middleware/session.middleware.js';
import { noCacheMiddleware } from '../middleware/security.middleware.js';

const router = Router();

// Login
router.get('/login', noCacheMiddleware, requireNoSession, getLogin);
router.post('/login', noCacheMiddleware, authRateLimiter, postLogin);

// Registration
router.get('/register', noCacheMiddleware, requireNoSession, getRegister);
router.post('/register', noCacheMiddleware, registrationRateLimiter, postRegister);

// Logout
router.get('/logout', noCacheMiddleware, logout);
router.post('/logout', noCacheMiddleware, logout);

// UserInfo endpoint (OIDC)
router.get('/userinfo', loadUser, getUserInfo);

export default router;

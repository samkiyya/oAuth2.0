import { Router } from 'express';
import {
    home,
    login,
    callback,
    dashboard,
    callApi,
    logout,
} from '../controllers/oauth.controller.js';

const router: Router = Router();

// Public routes
router.get('/', home);
router.get('/login', login);
router.get('/callback', callback);

// Protected routes  
router.get('/dashboard', dashboard);
router.get('/api', callApi);

// Logout
router.get('/logout', logout);
router.post('/logout', logout);

export default router;

import { Router } from 'express';
import { home, login, callback, profile, refresh } from '../controllers/client.controller.js';

const router = Router();

router.get('/', home);
router.get('/login', login);
router.get('/callback', callback);
router.get('/profile', profile);
router.get('/refresh', refresh);

export default router;

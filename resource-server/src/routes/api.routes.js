import { Router } from 'express';
import { requireAuth, requireScope } from '../middleware/auth.middleware.js';

const router = Router();

function getProfile(req, res) {
    res.json({
        message: 'This is the protected profile information.',
        user: {
            sub: req.user.sub,
            name: req.user.name,
            email: req.user.email,
            scope: req.user.scope,
        },
    });
}

router.get('/profile', requireAuth, requireScope('profile'), getProfile);

export default router;

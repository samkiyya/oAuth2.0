import { Router } from 'express';
import { authorize, token, jwks } from '../controllers/auth.controller.js';

const router = Router();

router.get('/authorize', authorize);
router.post('/token', token);
router.get('/.well-known/jwks.json', jwks);

export default router;

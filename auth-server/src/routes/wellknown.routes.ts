import { Router } from 'express';
import { getOpenIDConfiguration, getJWKS } from '../controllers/wellknown.controller.js';
import { noCacheMiddleware } from '../middleware/security.middleware.js';

const router: Router = Router();

// OpenID Connect Discovery
router.get('/.well-known/openid-configuration', noCacheMiddleware, getOpenIDConfiguration);

// JSON Web Key Set
router.get('/.well-known/jwks.json', getJWKS);

export default router;

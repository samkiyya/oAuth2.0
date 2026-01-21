import { Router } from 'express';
import {
    deviceAuthorization,
    deviceVerificationPage,
    verifyDeviceCode,
    authorizeDevice,
} from '../controllers/device.controller.js';
import { loadUser } from '../middleware/session.middleware.js';
import { noCacheMiddleware } from '../middleware/security.middleware.js';

const router = Router();

// Device authorization initiation (for devices)
router.post('/device/code', deviceAuthorization);

// User verification endpoints
router.get('/device', noCacheMiddleware, deviceVerificationPage);
router.post('/device/verify', noCacheMiddleware, loadUser, verifyDeviceCode);
router.post('/device/authorize', noCacheMiddleware, loadUser, authorizeDevice);

export default router;

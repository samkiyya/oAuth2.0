import { Router } from 'express';
import wellknownRoutes from './wellknown.routes.js';
import userRoutes from './user.routes.js';
import authRoutes from './auth.routes.js';
import tokenRoutes from './token.routes.js';
import clientRoutes from './client.routes.js';
import healthRoutes from './health.routes.js';
import deviceRoutes from './device.routes.js';
import mfaRoutes from './mfa.routes.js';

const router = Router();

// Health checks (no rate limiting)
router.use('/', healthRoutes);

// Well-known endpoints
router.use('/', wellknownRoutes);

// User authentication routes
router.use('/', userRoutes);

// MFA routes
router.use('/', mfaRoutes);

// Device flow routes
router.use('/', deviceRoutes);

// OAuth authorization routes
router.use('/', authRoutes);

// OAuth token routes
router.use('/', tokenRoutes);

// Client registration routes
router.use('/', clientRoutes);

export default router;

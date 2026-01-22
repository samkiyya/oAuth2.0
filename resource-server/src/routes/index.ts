import { Router } from 'express';
import v1Routes from './v1/index.js';
import { healthCheck, livenessProbe, readinessProbe } from '../controllers/resource.controller.js';

const router: Router = Router();

// Health checks (no auth required)
router.get('/health', healthCheck);
router.get('/health/live', livenessProbe);
router.get('/health/ready', readinessProbe);

// API v1
router.use('/api/v1', v1Routes);

// Legacy route (redirect to v1) - for backwards compatibility
router.use('/api', v1Routes);

export default router;

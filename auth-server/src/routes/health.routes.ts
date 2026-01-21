import { Router } from 'express';
import { healthCheck, livenessProbe, readinessProbe } from '../controllers/health.controller.js';

const router = Router();

// Health check endpoints
router.get('/health', healthCheck);
router.get('/health/live', livenessProbe);
router.get('/health/ready', readinessProbe);

export default router;

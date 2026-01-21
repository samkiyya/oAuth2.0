import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import pinoHttp from 'pino-http';
import { createLogger } from '@oauth2/shared-utils';
import config from './config/index.js';
import routes from './routes/index.js';

const logger = createLogger({ name: 'resource-server', level: config.logging.level });

export function createApp(): express.Application {
    const app = express();

    // Trust proxy
    app.set('trust proxy', 1);

    // Security headers
    app.use(helmet());

    // CORS configuration
    app.use(
        cors({
            origin: config.server.corsOrigins,
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
            exposedHeaders: ['X-Request-ID'],
            maxAge: 86400, // 24 hours
        })
    );

    // Request logging
    app.use(
        pinoHttp({
            logger,
            genReqId: (req) => req.headers['x-request-id'] as string ?? crypto.randomUUID(),
            autoLogging: {
                ignore: (req) => req.url === '/health' || req.url === '/health/live',
            },
        })
    );

    // Body parsing
    app.use(express.json({ limit: '10kb' }));

    // Add request ID to response
    app.use((req, res, next) => {
        res.setHeader('X-Request-ID', req.id ?? '');
        next();
    });

    // Routes
    app.use('/', routes);

    // 404 handler
    app.use((req, res) => {
        res.status(404).json({
            error: 'not_found',
            message: `Endpoint ${req.method} ${req.path} not found`,
            path: req.path,
            timestamp: new Date().toISOString(),
        });
    });

    // Error handler
    app.use((err: Error & { statusCode?: number }, req: express.Request, res: express.Response, _next: express.NextFunction) => {
        logger.error({ error: err, path: req.path, requestId: req.id }, 'Request error');

        const statusCode = err.statusCode ?? 500;
        res.status(statusCode).json({
            error: statusCode >= 500 ? 'server_error' : 'request_error',
            message: config.isProduction ? 'An error occurred' : err.message,
            requestId: req.id,
            timestamp: new Date().toISOString(),
        });
    });

    return app;
}

export default createApp;

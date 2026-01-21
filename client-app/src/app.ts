import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import helmet from 'helmet';
import { createClient } from 'redis';
import RedisStore from 'connect-redis';
import path from 'path';
import { fileURLToPath } from 'url';
import pinoHttp from 'pino-http';
import { createLogger } from '@oauth2/shared-utils';
import config from './config/index.js';
import routes from './routes/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = createLogger({ name: 'client-app', level: config.logging.level });

export async function createApp() {
    const app = express();

    // Trust proxy for rate limiting behind load balancer
    app.set('trust proxy', 1);

    // View engine
    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));

    // Security headers
    app.use(
        helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'"],
                    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
                    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
                    imgSrc: ["'self'", 'data:', 'https:'],
                    connectSrc: ["'self'", config.oauth.authServerUrl],
                },
            },
        })
    );

    // Request logging
    app.use(
        pinoHttp({
            logger,
            autoLogging: {
                ignore: (req) => req.url === '/health',
            },
        })
    );

    // Body parsing
    app.use(express.urlencoded({ extended: false }));
    app.use(express.json());
    app.use(cookieParser());

    // Session configuration
    let sessionStore: session.Store | undefined;

    if (config.redis.url) {
        try {
            const redisClient = createClient({ url: config.redis.url });
            await redisClient.connect();
            sessionStore = new RedisStore({ client: redisClient, prefix: 'client:sess:' });
            logger.info('Redis session store connected');
        } catch (error) {
            logger.warn({ error }, 'Failed to connect Redis, using memory store');
        }
    }

    app.use(
        session({
            name: config.session.name,
            secret: config.session.secret,
            resave: false,
            saveUninitialized: false,
            store: sessionStore,
            cookie: {
                secure: config.isProduction,
                httpOnly: true,
                maxAge: config.session.maxAge,
                sameSite: 'lax',
            },
        })
    );

    // Static files
    app.use('/static', express.static(path.join(__dirname, 'public')));

    // Routes
    app.use('/', routes);

    // Health check
    app.get('/health', (req, res) => {
        res.json({ status: 'healthy', service: 'client-app', timestamp: new Date().toISOString() });
    });

    // Error handler
    app.use((err: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => {
        logger.error({ error: err, path: req.path }, 'Request error');
        res.status(500).render('error', {
            error: 'server_error',
            errorDescription: config.isProduction ? 'An unexpected error occurred' : err.message,
        });
    });

    return app;
}

export default createApp;

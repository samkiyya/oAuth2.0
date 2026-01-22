import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import { pinoHttp } from 'pino-http';
import config from './config/index.js';
import routes from './routes/index.js';
import { logger } from './utils/logger.js';
import {
    helmetMiddleware,
    corsMiddleware,
    correlationMiddleware,
} from './middleware/security.middleware.js';
import { generalRateLimiter } from './middleware/rateLimit.middleware.js';
import { errorMiddleware, notFoundHandler } from './middleware/error.middleware.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app: Express = express();

// Trust proxy (for rate limiting behind load balancer)
app.set('trust proxy', 1);

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Security middleware
app.use(helmetMiddleware);
app.use(corsMiddleware);

// Request logging
app.use(
    pinoHttp({
        logger,
        autoLogging: {
            ignore: (req) => req.url === '/health' || req.url === '/health/live' || req.url === '/health/ready',
        },
    })
);

// Correlation ID
app.use(correlationMiddleware);

// Body parsing
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Cookie parsing
app.use(cookieParser());

// Session management
app.use(
    session({
        name: config.session.name,
        secret: config.session.secret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: config.isProduction,
            httpOnly: true,
            maxAge: config.session.maxAge,
            sameSite: 'lax',
        },
        // In production, use Redis store
        // store: new RedisStore({ client: getRedis() }),
    })
);

// Rate limiting
app.use(generalRateLimiter);

// Static files (for CSS, JS, images)
app.use('/static', express.static(path.join(__dirname, 'public')));

// Home page
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.render('home', { user: { id: req.session.userId } });
    } else {
        res.redirect('/login');
    }
});

// API routes
app.use('/', routes);

// 404 handler
app.use(notFoundHandler);

// Error handler
app.use(errorMiddleware);

export default app;

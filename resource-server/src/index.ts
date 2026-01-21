import 'dotenv/config';
import { createApp } from './app.js';
import config from './config/index.js';
import { createLogger } from '@oauth2/shared-utils';

const logger = createLogger({ name: 'resource-server', level: config.logging.level });

const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];

async function gracefulShutdown(signal: string, server: ReturnType<typeof createApp>['listen'] extends (...args: any[]) => infer R ? R : never): Promise<void> {
    logger.info({ signal }, 'Received shutdown signal, starting graceful shutdown...');

    server.close(() => {
        logger.info('HTTP server closed');
        process.exit(0);
    });

    // Force shutdown after 30 seconds
    setTimeout(() => {
        logger.warn('Forceful shutdown due to timeout');
        process.exit(1);
    }, 30000);
}

async function bootstrap(): Promise<void> {
    try {
        logger.info('Starting Resource Server...');

        const app = createApp();

        const server = app.listen(config.server.port, () => {
            logger.info(
                {
                    port: config.server.port,
                    env: config.env,
                    authServer: config.auth.authServerUrl,
                },
                `Resource Server is running on http://localhost:${config.server.port}`
            );
        });

        // Handle graceful shutdown
        signals.forEach((signal) => {
            process.on(signal, () => gracefulShutdown(signal, server));
        });

        // Handle uncaught errors
        process.on('uncaughtException', (error) => {
            logger.fatal({ error }, 'Uncaught exception');
            process.exit(1);
        });

        process.on('unhandledRejection', (reason) => {
            logger.fatal({ reason }, 'Unhandled rejection');
            process.exit(1);
        });
    } catch (error) {
        logger.fatal({ error }, 'Failed to start Resource Server');
        process.exit(1);
    }
}

bootstrap();

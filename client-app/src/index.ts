import 'dotenv/config';
import { createApp } from './app.js';
import config from './config/index.js';
import { createLogger } from '@oauth2/shared-utils';

const logger = createLogger({ name: 'client-app', level: config.logging.level });

const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];

async function gracefulShutdown(signal: string): Promise<void> {
    logger.info({ signal }, 'Received shutdown signal, starting graceful shutdown...');

    // Give existing requests time to complete
    setTimeout(() => {
        logger.warn('Forceful shutdown due to timeout');
        process.exit(1);
    }, 30000);

    process.exit(0);
}

async function bootstrap(): Promise<void> {
    try {
        logger.info('Starting Client App...');

        const app = await createApp();

        const server = app.listen(config.server.port, () => {
            logger.info(
                {
                    port: config.server.port,
                    env: config.env,
                    authServer: config.oauth.authServerUrl,
                },
                `Client App is running on http://localhost:${config.server.port}`
            );
        });

        // Handle graceful shutdown
        signals.forEach((signal) => {
            process.on(signal, () => {
                logger.info({ signal }, 'Shutdown signal received');
                server.close(() => {
                    gracefulShutdown(signal);
                });
            });
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
        logger.fatal({ error }, 'Failed to start Client App');
        process.exit(1);
    }
}

bootstrap();

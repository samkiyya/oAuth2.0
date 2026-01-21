import 'dotenv/config';
import app from './app.js';
import config from './config/index.js';
import { connectDatabase, createIndexes } from './config/database.js';
import { connectRedis } from './config/redis.js';
import { logger } from './utils/logger.js';

const signals = ['SIGINT', 'SIGTERM'];

async function gracefulShutdown(signal: string): Promise<void> {
    logger.info({ signal }, 'Received shutdown signal, starting graceful shutdown...');

    // Give existing requests time to complete
    setTimeout(() => {
        logger.warn('Forceful shutdown due to timeout');
        process.exit(1);
    }, 30000);

    try {
        // Close database connections
        const { disconnectDatabase } = await import('./config/database.js');
        const { disconnectRedis } = await import('./config/redis.js');

        await Promise.all([disconnectDatabase(), disconnectRedis()]);

        logger.info('Graceful shutdown completed');
        process.exit(0);
    } catch (error) {
        logger.error({ error }, 'Error during graceful shutdown');
        process.exit(1);
    }
}

async function bootstrap(): Promise<void> {
    try {
        logger.info('Starting Auth Server...');

        // Connect to databases
        await connectDatabase();
        await createIndexes();
        await connectRedis();

        // Start HTTP server
        const server = app.listen(config.server.port, () => {
            logger.info(
                {
                    port: config.server.port,
                    env: config.env,
                    issuer: config.server.issuer,
                },
                `Auth Server is running on http://localhost:${config.server.port}`
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

        process.on('unhandledRejection', (reason, promise) => {
            logger.fatal({ reason, promise }, 'Unhandled rejection');
            process.exit(1);
        });
    } catch (error) {
        logger.fatal({ error }, 'Failed to start Auth Server');
        process.exit(1);
    }
}

bootstrap();

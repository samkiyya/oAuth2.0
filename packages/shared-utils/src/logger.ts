import pino, { type Logger as PinoLogger } from 'pino';
import { randomUUID } from 'crypto';

export interface LoggerOptions {
    name: string;
    level?: string;
    prettyPrint?: boolean;
}

export interface LogContext {
    correlationId?: string | undefined;
    userId?: string | undefined;
    clientId?: string | undefined;
    requestId?: string | undefined;
    [key: string]: unknown;
}

export type Logger = PinoLogger;

/**
 * Create a structured logger with correlation ID support
 */
export function createLogger(options: LoggerOptions): Logger {
    const { name, level = 'info', prettyPrint = process.env['NODE_ENV'] !== 'production' } = options;

    const transport = prettyPrint
        ? {
            target: 'pino-pretty',
            options: {
                colorize: true,
                translateTime: 'SYS:standard',
                ignore: 'pid,hostname',
            },
        }
        : undefined;

    const pinoOptions: any = {
        name,
        level,
        formatters: {
            level: (label: string) => ({ level: label }),
        },
        timestamp: pino.stdTimeFunctions.isoTime,
        base: {
            env: process.env['NODE_ENV'] ?? 'development',
        },
        redact: {
            paths: [
                'password',
                'passwordHash',
                'secret',
                'clientSecret',
                'accessToken',
                'refreshToken',
                'authorization',
                'cookie',
                '*.password',
                '*.secret',
                '*.accessToken',
                '*.refreshToken',
            ],
            censor: '[REDACTED]',
        },
    };

    if (transport) {
        pinoOptions.transport = transport;
    }

    return pino(pinoOptions);
}

/**
 * Generate a new correlation ID
 */
export function generateCorrelationId(): string {
    return randomUUID();
}

/**
 * Create a child logger with correlation context
 */
export function withCorrelation(logger: Logger, correlationId?: string): Logger {
    return logger.child({
        correlationId: correlationId ?? generateCorrelationId(),
    });
}

/**
 * Security event logger for audit trails
 */
export interface SecurityEvent {
    event: string;
    success: boolean;
    userId?: string | undefined;
    clientId?: string | undefined;
    ipAddress?: string | undefined;
    userAgent?: string | undefined;
    details?: Record<string, unknown> | undefined;
}

export function logSecurityEvent(logger: Logger, event: SecurityEvent): void {
    const logFn = event.success ? logger.info.bind(logger) : logger.warn.bind(logger);
    logFn(
        {
            type: 'security',
            ...event,
        },
        `Security: ${event.event}`
    );
}

import type { Request, Response, NextFunction } from 'express';
import type { ZodSchema } from 'zod';
import { ValidationError } from '@oauth2/shared-utils';

type RequestPart = 'body' | 'query' | 'params';

/**
 * Validation middleware factory
 */
export function validate(schema: ZodSchema, source: RequestPart = 'body') {
    return (req: Request, res: Response, next: NextFunction): void => {
        const data = req[source];
        const result = schema.safeParse(data);

        if (!result.success) {
            const errors = result.error.errors.map((e) => ({
                field: e.path.join('.'),
                message: e.message,
                code: e.code,
            }));

            next(new ValidationError(errors));
            return;
        }

        // Replace request data with parsed/transformed data
        req[source] = result.data;
        next();
    };
}

/**
 * Validate multiple sources
 */
export function validateMultiple(schemas: { [K in RequestPart]?: ZodSchema }) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const allErrors: { field: string; message: string; code: string }[] = [];

        for (const [source, schema] of Object.entries(schemas) as [RequestPart, ZodSchema][]) {
            const data = req[source];
            const result = schema.safeParse(data);

            if (!result.success) {
                const errors = result.error.errors.map((e) => ({
                    field: `${source}.${e.path.join('.')}`,
                    message: e.message,
                    code: e.code,
                }));
                allErrors.push(...errors);
            } else {
                req[source] = result.data;
            }
        }

        if (allErrors.length > 0) {
            next(new ValidationError(allErrors));
            return;
        }

        next();
    };
}

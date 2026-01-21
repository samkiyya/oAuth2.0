import logger from '../utils/logger.js';

function errorMiddleware(err, req, res, next) {
    logger.error(err.stack);
    res.status(500).send('Something broke!');
}

export default errorMiddleware;

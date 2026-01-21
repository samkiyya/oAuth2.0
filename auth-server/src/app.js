import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import config from '../config.js';
import authRoutes from './routes/auth.routes.js';
import logger from './utils/logger.js';
import errorMiddleware from './middleware/error.middleware.js';

const app = express();
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
app.use(cookieParser());

app.use((req, res, next) => {
    logger.info(`${req.method} ${req.url}`);
    next();
});

app.use('/', authRoutes);

app.use(errorMiddleware);

export default app;

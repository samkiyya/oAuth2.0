import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import config from '../config.js';
import clientRoutes from './routes/client.routes.js';

const app = express();

app.use(cookieParser());
app.use(session({
    secret: 'supersecret', // in production, use a real secret from config
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // in production, set to true if using https
}));


app.use('/', clientRoutes);

export default app;

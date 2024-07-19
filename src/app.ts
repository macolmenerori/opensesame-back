import compression from 'compression';
import cookieParser from 'cookie-parser';
import express from 'express';
import mongoSanitize from 'express-mongo-sanitize';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';

import userRouter from './routes/userRouter';

const app = express();

// Add security HTTP headers
app.use(helmet({ contentSecurityPolicy: false }));

// Rate limit. Default is 100 requests per hour
const limiter = rateLimit({
  max: parseInt(
    process.env.RATELIMIT_MAXCONNECTIONS ? process.env.RATELIMIT_MAXCONNECTIONS : '100'
  ),
  windowMs: parseInt(process.env.RATELIMIT_WINDOWMS ? process.env.RATELIMIT_WINDOWMS : '3600000'),
  message: 'Too many requests from this IP, please try again after an hour'
});
app.use('/api', limiter);

// Middleware, modifies incoming data. For parsing JSON bodies on POST requests
app.use(express.json({ limit: '10kb' })); // Do not accept bodies bigger than 10 kilobytes

// Middleware, modifies incoming data. For parsing URL encoded forms
app.use(express.urlencoded({ extended: true, limit: '10kb' })); // Do not accept bodies bigger than 10 kilobytes

app.use(cookieParser()); // Parse cookies

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Compress responses
app.use(compression());

app.get('/healthcheck', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Server is running'
  });
});

app.use('/api/v1/users', userRouter);

// Middleware for handling unhandled routes
app.all('*', (req, res) => {
  return res.status(404).json({
    status: 'fail',
    message: `Can't find ${req.originalUrl} on this server`
  });
});

export default app;

import cookieParser from 'cookie-parser';
import express from 'express';

import userRouter from './routes/userRouter';

const app = express();

// Middleware, modifies incoming data. For parsing JSON bodies on POST requests
app.use(express.json({ limit: '10kb' })); // Do not accept bodies bigger than 10 kilobytes

// Middleware, modifies incoming data. For parsing URL encoded forms
app.use(express.urlencoded({ extended: true, limit: '10kb' })); // Do not accept bodies bigger than 10 kilobytes

app.use(cookieParser()); // Parse cookies

// TODO: Delete this
app.get('/', (req, res) => {
  res.send('Hello from opensesame!');
});

app.use('/api/v1/users', userRouter);

export default app;

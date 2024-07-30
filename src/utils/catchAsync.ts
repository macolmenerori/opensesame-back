/* eslint-disable @typescript-eslint/no-explicit-any */
import type { NextFunction, Request, Response } from 'express';

const catchAsync =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) =>
  (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch(() => {
      return res.status(500).json({
        status: 'fail',
        message: 'Internal server error.'
      });
    });
  };

export default catchAsync;

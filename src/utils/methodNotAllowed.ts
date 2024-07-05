import { NextFunction, Request, Response } from 'express';

import { HTTPMethod } from './consts';

export const methodNotAllowed =
  (allowedMethods: HTTPMethod[]) => (req: Request, res: Response, next: NextFunction) => {
    if (!allowedMethods.includes(req.method as HTTPMethod)) {
      res.setHeader('Allow', allowedMethods.join(', '));
      return res.status(405).json({ status: 'fail', message: 'Method not allowed' });
    }
    next();
  };

import type { NextFunction, Request as RequestExpress, Response } from 'express';
import { JwtPayload, sign, verify, VerifyOptions } from 'jsonwebtoken';
import { promisify } from 'util';

import User from '../models/userModel';
import { UserRoles, UserSchemaType, UserType } from '../models/userTypes';
import catchAsync from '../utils/catchAsync';

type Request = RequestExpress & {
  user?: UserType;
};

type CookieOptionsType = {
  expires: Date;
  httpOnly: boolean;
  secure?: boolean;
};

type DecodedJwt = JwtPayload & {
  id: string;
};

const signToken = (id: string): string => {
  return sign({ id: id }, process.env.JWT_SECRET!, {
    expiresIn: process.env.JWT_EXPIRES_IN,
    algorithm: 'HS256'
  });
};

const verifyAsync = promisify<string, string | Buffer, VerifyOptions | undefined, DecodedJwt>(
  verify
);

const verifyToken = async (token: string): Promise<DecodedJwt | null> => {
  try {
    const decoded = (await verifyAsync(token, process.env.JWT_SECRET as string, {})) as DecodedJwt;
    return decoded;
  } catch (err) {
    return null;
  }
};

const signAndSendToken = (
  user: UserType,
  statusCode: number,
  tokenType: 'cookie' | 'bearer',
  req: Request,
  res: Response
) => {
  const token = signToken(user._id as string);

  switch (tokenType) {
    case 'cookie': {
      // Set cookie for browser
      const cookieOptions: CookieOptionsType = {
        expires: new Date(
          Date.now() + parseInt(process.env.JWT_COOKIE_EXPIRES_IN!) * 24 * 60 * 60 * 1000
        ),
        httpOnly: true
      };

      if (req.secure || req.headers['x-forwarded-proto'] === 'https') cookieOptions.secure = true;

      res.cookie('jwt', token, cookieOptions);

      res.status(statusCode).json({
        status: 'success',
        token,
        data: {
          user
        }
      });
    }
    case 'bearer': {
      res.status(statusCode).json({
        status: 'success',
        token,
        data: {
          user
        }
      });
    }
  }
};

export const signUp = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  // Create user
  const newUser = await User.create(req.body);

  // Sign and send back the token
  //signAndSendToken(newUser, 201, 'cookie', req, res);

  return res.status(201).json({
    status: 'success',
    message: 'User created',
    data: {
      user: newUser
    }
  });
});

export const logIn = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { email, password } = req.body;

  // 1) Check if email and password exist
  if (!email || !password) {
    return res.status(401).json({
      status: 'fail',
      message: 'Please provide email and password!'
    });
  }

  // 2) Check if user exists && password is correct
  const user = (await User.findOne({ email }).select('+password')) as UserSchemaType;

  if (!user || !(await user.correctPassword(password, user.password))) {
    return res.status(401).json({
      status: 'fail',
      message: 'Incorrect email or password'
    });
  }

  // 3) If everything ok, send token to client
  if (req.headers.authorizationtype && req.headers.authorizationtype === 'bearer') {
    signAndSendToken(user, 200, 'bearer', req, res);
  } else {
    signAndSendToken(user, 200, 'cookie', req, res);
  }
});

export const logOut = (req: Request, res: Response) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000), // 10 seconds
    httpOnly: true
  });

  return res.status(200).json({ status: 'success', message: 'Successfully logged out.' });
};

// TODO: remove this
export const testEnd = (req: Request, res: Response) => {
  res.status(200).json({
    status: 'success',
    message: 'You are tested'
  });
};

// Restrict access to authenticated users, no matter the role
export const protect = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  // 1) Getting token and check if it's there
  // The token can be sent in the headers or in the cookies
  let token: string | undefined;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return res.status(401).json({
      status: 'fail',
      message: 'You are not logged in! Please log in to get access.'
    });
  }

  // 2) Verification token
  const decoded = await verifyToken(token);
  if (!decoded) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token provided.'
    });
  }

  // 3) Check if user still exists
  const currentUser = (await User.findById(decoded.id)) as UserSchemaType;
  if (!currentUser) {
    return res.status(401).json({
      status: 'fail',
      message: 'The user belonging to this token does no longer exist.'
    });
  }

  // 4) Check if user changed password after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat!.toString())) {
    return res.status(401).json({
      status: 'fail',
      message: 'Password changed recently. Please log in again.'
    });
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});

// Restrict access to certain roles. This middleware should be called AFTER the protect middleware
export const restrictTo =
  (grantedRoles: UserRoles[]) => (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }
    if (!grantedRoles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'fail',
        message: 'You do not have permission to perform this action'
      });
    }

    next();
  };

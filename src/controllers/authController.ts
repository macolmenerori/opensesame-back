import type { NextFunction, Request as RequestExpress, Response } from 'express';
import { validationResult } from 'express-validator';
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

/**
 * Securely signs a token
 *
 * @param {string} id - The user ID
 * @returns {string} - The signed token
 */
const signToken = (id: string): string => {
  return sign({ id: id }, process.env.JWT_SECRET!, {
    expiresIn: process.env.JWT_EXPIRES_IN,
    algorithm: 'HS256'
  });
};

const verifyAsync = promisify<string, string | Buffer, VerifyOptions | undefined, DecodedJwt>(
  verify
);

/**
 * Verifies and decodes a token
 *
 * @param {string} token - The token to verify
 * @returns {Promise<DecodedJwt | null>} - The decoded token, or null if the token is invalid
 */
const verifyToken = async (token: string): Promise<DecodedJwt | null> => {
  try {
    const decoded = (await verifyAsync(token, process.env.JWT_SECRET as string, {})) as DecodedJwt;
    return decoded;
  } catch (err) {
    return null;
  }
};

/**
 * Signs a token and sends it back to the client
 *
 * @param {UserType} user - The user object to sign the token for
 * @param {number} statusCode - The status code to return
 * @param {'cookie' | 'bearer'} tokenType - The type of token to send, bearer or cookie
 * @param {Request} req - The request object
 * @param {Response} res - The response object
 */
const signAndSendToken = (
  user: UserType,
  statusCode: number,
  tokenType: 'cookie' | 'bearer',
  req: Request,
  res: Response
) => {
  const token = signToken(user._id as string);

  if (tokenType === 'cookie') {
    // Set cookie for browser
    const cookieOptions: CookieOptionsType = {
      expires: new Date(
        Date.now() + parseInt(process.env.JWT_COOKIE_EXPIRES_IN!) * 24 * 60 * 60 * 1000
      ),
      httpOnly: true
    };

    if (req.secure || req.headers['x-forwarded-proto'] === 'https') cookieOptions.secure = true;

    res.cookie('jwt', token, cookieOptions);
  }

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      }
    }
  });
  return;
};

/**
 * Retrieves from the database a user by its email or ID
 *
 * @param {string} type - The type of search, email or ID
 * @param {string} email - The email to search for
 * @param {string} id - The ID to search for
 * @param {Response} res - The response object
 * @returns {Promise<UserSchemaType | Response>} - The user object, or a response object if the user is not found
 */
const getUserByEmailOrId = async (
  type: 'email' | 'id',
  email: string,
  id: string,
  res: Response
): Promise<UserSchemaType | Response> => {
  switch (type) {
    case 'email': {
      const user = (await User.findOne({ email })) as UserSchemaType;
      if (!user) {
        return res.status(404).json({
          status: 'fail',
          message: 'User not found with that email.'
        });
      } else {
        return user;
      }
    }
    case 'id': {
      const user = (await User.findOne({ id })) as UserSchemaType;
      if (!user) {
        return res.status(404).json({
          status: 'fail',
          message: 'User not found with that id.'
        });
      } else {
        return user;
      }
    }
  }
};

/**
 * Checks if the validation has errors and sends a response if it does
 *
 * @param {Request} req - The request object
 * @param {Response} res - The response object
 */
const checkValidation = (req: Request, res: Response) => {
  const validationRes = validationResult(req);
  if (!validationRes.isEmpty()) {
    return res.status(400).json({
      status: 'fail',
      message: 'Invalid input data',
      errors: validationRes.array()
    });
  }
};

export const signUp = catchAsync(async (req: Request, res: Response) => {
  checkValidation(req, res);

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

export const logIn = catchAsync(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  checkValidation(req, res);

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
  const cookieOptions: CookieOptionsType = {
    expires: new Date(Date.now() + 10 * 1000), // 10 seconds
    httpOnly: true
  };

  if (req.secure || req.headers['x-forwarded-proto'] === 'https') cookieOptions.secure = true;

  res.cookie('jwt', 'loggedout', cookieOptions);

  return res.status(200).json({ status: 'success', message: 'Successfully logged out.' });
};

export const isLoggedIn = catchAsync(async (req: Request, res: Response) => {
  const { user } = req;

  return res.status(200).json({ status: 'success', message: 'User is logged in', data: { user } });
});

export const getRoles = catchAsync(async (req: Request, res: Response) => {
  const { email, id } = req.body;

  checkValidation(req, res);

  // Check that at least one exists
  if (!email && !id) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide an email or an id'
    });
  }

  // Search by email or id
  const user = (await getUserByEmailOrId(
    !email ? 'id' : 'email',
    email,
    id,
    res
  )) as UserSchemaType;
  const role = user?.role;

  if (!role) {
    return res.status(404).json({
      status: 'fail',
      message: 'Role not found for that user.'
    });
  }

  return res.status(200).json({
    status: 'success',
    message: 'Roles retrieved',
    data: {
      role
    }
  });
});

export const updatePermissions = catchAsync(async (req: Request, res: Response) => {
  const { email, id, permissions } = req.body;

  checkValidation(req, res);

  // Check that at least one exists
  if (!email && !id) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide an email or an id'
    });
  }

  if (!permissions) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide permissions'
    });
  }

  // Search by email or id
  const user = (await getUserByEmailOrId(
    !email ? 'id' : 'email',
    email,
    id,
    res
  )) as UserSchemaType;

  const updatedUser = await User.findByIdAndUpdate(user.id, req.body, {
    new: true,
    runValidators: true
  });

  if (!updatedUser) {
    return res.status(500).json({
      status: 'fail',
      message: 'Could not update user'
    });
  }

  return res.status(200).json({
    status: 'success',
    message: 'Permissions updated',
    data: {
      user: updatedUser
    }
  });
});

export const getPermissions = catchAsync(async (req: Request, res: Response) => {
  const { email, id } = req.body;

  checkValidation(req, res);

  // Check that at least one exists
  if (!email && !id) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide an email or an id'
    });
  }

  // Search by email or id
  const user = (await getUserByEmailOrId(
    !email ? 'id' : 'email',
    email,
    id,
    res
  )) as UserSchemaType;
  const permissions = user?.permissions;

  if (!permissions || permissions.length === 0) {
    return res.status(200).json({
      status: 'success',
      message: 'This user does not have permissions.',
      data: {
        permissions: []
      }
    });
  }

  return res.status(200).json({
    status: 'success',
    message: 'Permissions retrieved',
    data: {
      permissions
    }
  });
});

export const updateRoles = catchAsync(async (req: Request, res: Response) => {
  const { email, id, role } = req.body;

  checkValidation(req, res);

  // Check that at least one exists
  if (!email && !id) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide an email or an id'
    });
  }

  // Check that the role is provided
  if (!role) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide a role'
    });
  }

  // Check that the role is valid
  if (role !== 'admin' && role !== 'user') {
    return res.status(400).json({
      status: 'fail',
      message: 'Role must be either "admin" or "user"'
    });
  }

  // Search by email or id
  const user = (await getUserByEmailOrId(
    !email ? 'id' : 'email',
    email,
    id,
    res
  )) as UserSchemaType;

  const updatedUser = await User.findByIdAndUpdate(user.id, req.body, {
    new: true,
    runValidators: true
  });

  if (!updatedUser) {
    return res.status(500).json({
      status: 'fail',
      message: 'Could not update user'
    });
  }

  return res.status(200).json({
    status: 'success',
    message: 'Roles updated',
    data: {
      user: updatedUser
    }
  });
});

export const removeUser = catchAsync(async (req: Request, res: Response) => {
  const { email, id } = req.body;

  checkValidation(req, res);

  // Check that at least one exists
  if (!email && !id) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide an email or an id'
    });
  }

  // Search by email or id
  const user = (await getUserByEmailOrId(
    !email ? 'id' : 'email',
    email,
    id,
    res
  )) as UserSchemaType;

  // Remove user
  const removed = await User.findByIdAndDelete(user.id);

  if (!removed) {
    return res.status(500).json({
      status: 'fail',
      message: 'Could not remove user'
    });
  }

  return res.status(204).json({
    status: 'success',
    message: 'User removed'
  });
});

export const changePassword = catchAsync(async (req: Request, res: Response) => {
  checkValidation(req, res);

  // Get the logged in user
  const user = (await User.findById(req.user?.id).select('+password')) as UserSchemaType;

  // Check if the current password is correct
  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return res.status(401).json({
      status: 'fail',
      message: 'Your current password is wrong'
    });
  }

  // Check if password and passwordConfirm are the same
  if (req.body.newPassword !== req.body.newPasswordConfirm) {
    return res.status(400).json({
      status: 'fail',
      message: 'Passwords are not the same'
    });
  }

  // Update password
  user.password = req.body.newPassword;
  user.passwordConfirm = req.body.newPasswordConfirm;
  await user.save();

  // Update user JWT
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    signAndSendToken(user, 200, 'bearer', req, res);
  } else {
    signAndSendToken(user, 200, 'cookie', req, res);
  }
});

export const changeUserPassword = catchAsync(async (req: Request, res: Response) => {
  const { email, id } = req.body;

  checkValidation(req, res);

  // Check that at least one exists
  if (!email && !id) {
    return res.status(400).json({
      status: 'fail',
      message: 'Please provide an email or an id'
    });
  }

  // Search by email or id
  const user = (await getUserByEmailOrId(
    !email ? 'id' : 'email',
    email,
    id,
    res
  )) as UserSchemaType;

  // Check if password and passwordConfirm are the same
  if (req.body.newPassword !== req.body.newPasswordConfirm) {
    return res.status(400).json({
      status: 'fail',
      message: 'Passwords are not the same'
    });
  }

  // Update password
  user.password = req.body.newPassword;
  user.passwordConfirm = req.body.newPasswordConfirm;
  await user.save();

  return res.status(200).json({
    status: 'success',
    message: 'Password updated'
  });
});

export const getAllUsers = catchAsync(async (req: Request, res: Response) => {
  const page = Number(req.query.page) || 1;
  const perpage = Number(req.query.perpage) || 10;

  // Calculate the number of users to skip
  const skip = (page - 1) * perpage;

  const users = await User.find().select('name email role permissions').skip(skip).limit(perpage);

  // Count the total number of users for metadata information
  const totalCount = await User.countDocuments();

  return res.status(200).json({
    status: 'success',
    results: users.length,
    data: {
      users
    },
    pagination: {
      totalCount,
      currentPage: page,
      totalPages: Math.ceil(totalCount / perpage)
    }
  });
});

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

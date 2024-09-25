import { body, ValidationChain } from 'express-validator';

export const signUpValidation: ValidationChain[] = [
  body('name')
    .exists({ checkFalsy: true })
    .withMessage('Name cannot be empty')
    .bail()
    .isString()
    .withMessage('Name must be a string')
    .bail()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .exists({ checkFalsy: true })
    .withMessage('Email cannot be empty')
    .bail()
    .isEmail()
    .withMessage('Email must be valid'),
  body('password')
    .exists({ checkFalsy: true })
    .withMessage('Password cannot be empty')
    .bail()
    .isString()
    .withMessage('Password must be a string')
    .bail()
    .isLength({ min: 8, max: 100 })
    .withMessage('Password must be at least 8 characters'),
  body('passwordConfirm')
    .exists({ checkFalsy: true })
    .withMessage('Password cannot be empty')
    .bail()
    .isString()
    .withMessage('Password must be a string')
    .bail()
    .isLength({ min: 8, max: 100 })
    .withMessage('Password must be at least 8 characters'),
  body('role')
    .exists({ checkFalsy: true })
    .withMessage('Role cannot be empty')
    .bail()
    .isString()
    .withMessage('Role must be a string')
    .bail()
    .isLength({ min: 2, max: 50 })
    .withMessage('Role must be between 2 and 50 characters'),
  body('permissions')
    .optional()
    .isString()
    .withMessage('Permissions is optional, but if declared it must be a string')
];

export const logInValidation: ValidationChain[] = [
  body('email')
    .exists({ checkFalsy: true })
    .withMessage('Email cannot be empty')
    .bail()
    .isEmail()
    .withMessage('Email must be valid'),
  body('password')
    .exists({ checkFalsy: true })
    .withMessage('Password cannot be empty')
    .bail()
    .isString()
    .withMessage('Password must be a string')
];

export const changePasswordValidation: ValidationChain[] = [
  body('currentPassword')
    .exists({ checkFalsy: true })
    .withMessage('Current password cannot be empty')
    .bail()
    .isString()
    .withMessage('Current password must be a string')
    .bail()
    .isLength({ min: 8, max: 100 })
    .withMessage('Current password must be at least 8 characters'),
  body('newPassword')
    .exists({ checkFalsy: true })
    .withMessage('New password cannot be empty')
    .bail()
    .isString()
    .withMessage('New password must be a string')
    .bail()
    .isLength({ min: 8, max: 100 })
    .withMessage('New password must be at least 8 characters'),
  body('newPasswordConfirm')
    .exists({ checkFalsy: true })
    .withMessage('New password confirm cannot be empty')
    .bail()
    .isString()
    .withMessage('New password confirm must be a string')
    .bail()
    .isLength({ min: 8, max: 100 })
    .withMessage('New password confirm must be at least 8 characters')
];

export const changeUserPasswordValidation: ValidationChain[] = [
  body('email')
    .exists({ checkFalsy: true })
    .withMessage('Email cannot be empty')
    .bail()
    .isEmail()
    .withMessage('Email must be valid'),
  body('newPassword')
    .exists({ checkFalsy: true })
    .withMessage('New password cannot be empty')
    .bail()
    .isString()
    .withMessage('New password must be a string')
    .bail()
    .isLength({ min: 8, max: 100 })
    .withMessage('New password must be at least 8 characters'),
  body('newPasswordConfirm')
    .exists({ checkFalsy: true })
    .withMessage('New password confirm cannot be empty')
    .bail()
    .isString()
    .withMessage('New password confirm must be a string')
    .bail()
    .isLength({ min: 8, max: 100 })
    .withMessage('New password confirm must be at least 8 characters')
];

export const validateEmailOrId: ValidationChain[] = [
  body('email').optional().isEmail().withMessage('Email must be valid'),
  body('id').optional().isString().withMessage('ID must be a string')
];

export const validateName: ValidationChain[] = [
  body('name')
    .optional()
    .isString()
    .withMessage('Name must be a string')
    .bail()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters')
];

export const updateRolesValidation: ValidationChain[] = [
  body('email').optional().isEmail().withMessage('Email must be valid'),
  body('id').optional().isString().withMessage('ID must be a string'),
  body('role')
    .exists({ checkFalsy: true })
    .withMessage('Role cannot be empty')
    .bail()
    .isString()
    .withMessage('Role must be a string')
    .bail()
    .isLength({ min: 2, max: 50 })
    .withMessage('Role must be between 2 and 50 characters')
];

export const updatePermissionsValidation: ValidationChain[] = [
  body('email').optional().isEmail().withMessage('Email must be valid'),
  body('id').optional().isString().withMessage('ID must be a string'),
  body('permissions')
    .exists({ checkFalsy: true })
    .withMessage('Permissions cannot be empty')
    .bail()
    .isString()
    .withMessage('Permissions must be a string')
    .isLength({ min: 2, max: 50 })
    .withMessage('Role must be between 2 and 50 characters')
];

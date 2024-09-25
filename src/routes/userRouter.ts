import express from 'express';

import {
  changePassword,
  changeUserPassword,
  getAllUsers,
  getPermissions,
  getRoles,
  getUserByName,
  getUserDetails,
  isLoggedIn,
  logIn,
  logOut,
  protect,
  removeUser,
  restrictTo,
  signUp,
  updatePermissions,
  updateRoles
} from '../controllers/authController';
import { methodNotAllowed } from '../utils/methodNotAllowed';
import {
  changePasswordValidation,
  changeUserPasswordValidation,
  logInValidation,
  signUpValidation,
  updatePermissionsValidation,
  updateRolesValidation,
  validateEmailOrId,
  validateName
} from '../validations/userValidation';

const router = express.Router();

router
  .route('/signup')
  .post(protect, restrictTo(['admin']), signUpValidation, signUp)
  .all(methodNotAllowed(['POST']));
router
  .route('/login')
  .post(logInValidation, logIn)
  .all(methodNotAllowed(['POST']));
router
  .route('/logout')
  .delete(logOut)
  .all(methodNotAllowed(['DELETE']));
router
  .route('/isloggedin')
  .get(protect, isLoggedIn)
  .all(methodNotAllowed(['GET']));
router
  .route('/changePassword')
  .post(protect, changePasswordValidation, changePassword)
  .all(methodNotAllowed(['POST']));
router
  .route('/changeUserPassword')
  .post(protect, restrictTo(['admin']), changeUserPasswordValidation, changeUserPassword)
  .all(methodNotAllowed(['POST']));
router
  .route('/roles')
  .get(protect, validateEmailOrId, getRoles)
  .put(protect, restrictTo(['admin']), updateRolesValidation, updateRoles)
  .all(methodNotAllowed(['GET', 'PUT']));
router
  .route('/permissions')
  .get(protect, validateEmailOrId, getPermissions)
  .put(protect, restrictTo(['admin']), updatePermissionsValidation, updatePermissions)
  .all(methodNotAllowed(['GET', 'PUT']));
router
  .route('/allusers')
  .get(protect, getAllUsers)
  .all(methodNotAllowed(['GET']));
router
  .route('/userdetails')
  .get(protect, validateEmailOrId, getUserDetails)
  .all(methodNotAllowed(['GET']));
router
  .route('/searchbyname')
  .get(protect, validateName, getUserByName)
  .all(methodNotAllowed(['GET']));
router
  .route('/delete')
  .delete(protect, restrictTo(['admin']), validateEmailOrId, removeUser)
  .all(methodNotAllowed(['DELETE']));

export default router;

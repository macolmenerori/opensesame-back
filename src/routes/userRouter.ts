import express from 'express';

import {
  changePassword,
  changeUserPassword,
  getPermissions,
  getRoles,
  logIn,
  logOut,
  protect,
  removeUser,
  restrictTo,
  signUp,
  testEnd,
  updatePermissions,
  updateRoles
} from '../controllers/authController';
import {
  changePasswordValidation,
  changeUserPasswordValidation,
  logInValidation,
  signUpValidation,
  updatePermissionsValidation,
  updateRolesValidation,
  validateEmailOrId
} from '../validations/userValidation';

const router = express.Router();

router.route('/signup').post(protect, restrictTo(['admin']), signUpValidation, signUp);
router.route('/test').get(protect, restrictTo(['admin']), testEnd); // TODO: remove
router.route('/login').post(logInValidation, logIn);
router.route('/logout').delete(logOut);
router.route('/changePassword').post(protect, changePasswordValidation, changePassword);
router
  .route('/changeUserPassword')
  .post(protect, restrictTo(['admin']), changeUserPasswordValidation, changeUserPassword);
router
  .route('/roles')
  .get(protect, validateEmailOrId, getRoles)
  .put(protect, restrictTo(['admin']), updateRolesValidation, updateRoles);
router
  .route('/permissions')
  .get(protect, validateEmailOrId, getPermissions)
  .put(protect, restrictTo(['admin']), updatePermissionsValidation, updatePermissions);
router.route('/delete').delete(protect, restrictTo(['admin']), validateEmailOrId, removeUser);

export default router;

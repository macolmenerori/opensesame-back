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
import { signUpValidation } from '../validations/userValidation';

const router = express.Router();

router.route('/signup').post(protect, restrictTo(['admin']), signUpValidation, signUp);
router.route('/test').get(protect, restrictTo(['admin']), testEnd); // TODO: remove
router.route('/login').post(logIn);
router.route('/logout').delete(logOut);
router.route('/changePassword').post(protect, changePassword);
router.route('/changeUserPassword').post(protect, restrictTo(['admin']), changeUserPassword);
router
  .route('/roles')
  .get(protect, getRoles)
  .put(protect, restrictTo(['admin']), updateRoles);
router
  .route('/permissions')
  .get(protect, getPermissions)
  .put(protect, restrictTo(['admin']), updatePermissions);
router.route('/delete').delete(protect, restrictTo(['admin']), removeUser);

export default router;

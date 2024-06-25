import express from 'express';

import {
  getPermissions,
  getRoles,
  logIn,
  logOut,
  protect,
  restrictTo,
  signUp,
  testEnd,
  updatePermissions,
  updateRoles
} from '../controllers/authController';

const router = express.Router();

router.route('/signup').post(protect, restrictTo(['admin']), signUp);
router.route('/test').get(protect, restrictTo(['admin']), testEnd); // TODO: remove
router.route('/login').post(logIn);
router.route('/logout').delete(logOut);
router
  .route('/roles')
  .get(protect, getRoles)
  .put(protect, restrictTo(['admin']), updateRoles);
router
  .route('/permissions')
  .get(protect, getPermissions)
  .put(protect, restrictTo(['admin']), updatePermissions);

export default router;

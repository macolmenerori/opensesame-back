import express from 'express';

import {
  getRoles,
  logIn,
  logOut,
  protect,
  restrictTo,
  signUp,
  testEnd,
  updatePermissions
} from '../controllers/authController';

const router = express.Router();

router.route('/signup').post(signUp);
router.route('/test').get(protect, restrictTo(['admin']), testEnd); // TODO: remove
router.route('/login').post(logIn);
router.route('/logout').delete(logOut);
router.route('/roles').get(protect, restrictTo(['admin']), getRoles);
router.route('/permissions').put(protect, restrictTo(['admin']), updatePermissions);

export default router;

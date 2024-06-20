import express from 'express';

import { logIn, logOut, protect, restrictTo, signUp, testEnd } from '../controllers/authController';

const router = express.Router();

router.route('/signup').post(signUp);
router.route('/test').get(protect, restrictTo(['admin']), testEnd); // TODO: remove
router.route('/login').post(logIn);
router.route('/logout').delete(logOut);

export default router;

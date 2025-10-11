const express = require('express');
const router = express.Router();
const {
  signup,
  login,
  logout,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  changePassword,
  getMe
} = require('../controllers/authController');
const { protect } = require('../middleware/auth');
const { validateSignup, validateLogin, validateChangePassword } = require('../middleware/validation');

// Public routes
router.post('/signup', validateSignup, signup);
router.post('/login', validateLogin, login);
router.post('/refresh-token', refreshToken);
router.get('/verify-email/:token', verifyEmail);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password/:token', resetPassword);

// Protected routes (require authentication)
router.use(protect); // All routes below this are protected

router.get('/me', getMe);
router.post('/logout', logout);
router.post('/change-password', validateChangePassword, changePassword);

module.exports = router;
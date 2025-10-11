const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError } = require('../utils/appError');
const { sendEmail, emailTemplates } = require('../utils/email');
const { createSendToken } = require('../utils/auth');

// @desc    Register new user
// @route   POST /api/auth/signup
// @access  Public
exports.signup = async (req, res, next) => {
  try {
    const { firstName, lastName, email, password, role } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new AppError('Email already registered', 400));
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;
    if (!passwordRegex.test(password)) {
      return next(new AppError('Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character', 400));
    }

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      role: role || 'student'
    });

    // Generate email verification token
    const verificationToken = user.generateEmailVerificationToken();
    await user.save({ validateBeforeSave: false });

    // Send verification email
    const verificationUrl = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
    
    try {
      const emailContent = emailTemplates.verification(verificationUrl, user.firstName);
      await sendEmail({
        email: user.email,
        subject: emailContent.subject,
        html: emailContent.html
      });

      res.status(201).json({
        success: true,
        message: 'User registered successfully. Please check your email to verify your account.',
        data: {
          user: {
            id: user._id,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            role: user.role
          }
        }
      });
    } catch (emailError) {
      user.emailVerificationToken = undefined;
      user.emailVerificationExpire = undefined;
      await user.save({ validateBeforeSave: false });
      
      return next(new AppError('Email could not be sent. Please try again later.', 500));
    }

  } catch (error) {
    next(error);
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res, next) => {
  try {
    const { email, password, rememberMe } = req.body;

    if (!email || !password) {
      return next(new AppError('Please provide email and password', 400));
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user) {
      return next(new AppError('Invalid credentials', 401));
    }

    if (user.isLocked) {
      return next(new AppError('Account is temporarily locked due to multiple failed login attempts. Please try again later.', 423));
    }

    const isPasswordCorrect = await user.comparePassword(password);

    if (!isPasswordCorrect) {
      await user.incrementLoginAttempts();
      return next(new AppError('Invalid credentials', 401));
    }

    if (user.loginAttempts > 0 || user.lockUntil) {
      await user.resetLoginAttempts();
    }

    user.lastLogin = Date.now();
    await user.save({ validateBeforeSave: false });

    // Create and send token
    createSendToken(user, 200, res, rememberMe);

  } catch (error) {
    next(error);
  }
};

// @desc    Logout user
// @route   POST /api/auth/logout
// @access  Private
exports.logout = async (req, res, next) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken && req.user) {
      await req.user.removeRefreshToken(refreshToken);
    }

    res.cookie('accessToken', 'none', {
      expires: new Date(Date.now() + 1 * 1000),
      httpOnly: true
    });

    res.cookie('refreshToken', 'none', {
      expires: new Date(Date.now() + 1 * 1000),
      httpOnly: true
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Refresh access token
// @route   POST /api/auth/refresh-token
// @access  Public
exports.refreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return next(new AppError('No refresh token provided', 401));
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Get user and check if refresh token exists in DB
    const user = await User.findById(decoded.id);

    if (!user) {
      return next(new AppError('User not found', 404));
    }

    const tokenExists = user.refreshTokens.some(rt => rt.token === refreshToken);

    if (!tokenExists) {
      return next(new AppError('Invalid refresh token', 401));
    }

    // Generate new access token
    const newAccessToken = user.generateAccessToken();

    res.cookie('accessToken', newAccessToken, {
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      success: true,
      token: newAccessToken
    });

  } catch (error) {
    next(new AppError('Invalid or expired refresh token', 401));
  }
};

// @desc    Verify email
// @route   GET /api/auth/verify-email/:token
// @access  Public
exports.verifyEmail = async (req, res, next) => {
  try {
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpire: { $gt: Date.now() }
    });

    if (!user) {
      return next(new AppError('Invalid or expired verification token', 400));
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpire = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });

  } catch (error) {
    next(error);
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgot-password
// @access  Public
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      // Don't reveal if user exists or not
      return res.status(200).json({
        success: true,
        message: 'If an account exists with that email, a password reset link has been sent.'
      });
    }

    // Generate reset token
    const resetToken = user.generatePasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // Send email
    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    try {
      const emailContent = emailTemplates.passwordReset(resetUrl, user.firstName);
      await sendEmail({
        email: user.email,
        subject: emailContent.subject,
        html: emailContent.html
      });

      res.status(200).json({
        success: true,
        message: 'Password reset email sent'
      });

    } catch (emailError) {
      user.passwordResetToken = undefined;
      user.passwordResetExpire = undefined;
      await user.save({ validateBeforeSave: false });

      return next(new AppError('Email could not be sent', 500));
    }

  } catch (error) {
    next(error);
  }
};

// @desc    Reset password
// @route   POST /api/auth/reset-password/:token
// @access  Public
exports.resetPassword = async (req, res, next) => {
  try {
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpire: { $gt: Date.now() }
    });

    if (!user) {
      return next(new AppError('Invalid or expired reset token', 400));
    }

    // Validate new password
    const { password } = req.body;
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;
    
    if (!passwordRegex.test(password)) {
      return next(new AppError('Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character', 400));
    }

    // Set new password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpire = undefined;
    user.passwordChangedAt = Date.now();
    
    // Clear all refresh tokens (logout from all devices)
    user.refreshTokens = [];
    
    await user.save();

    // Send confirmation email
    try {
      const emailContent = emailTemplates.passwordChanged(user.firstName);
      await sendEmail({
        email: user.email,
        subject: emailContent.subject,
        html: emailContent.html
      });
    } catch (emailError) {
      console.error('Password changed email failed:', emailError);
    }

    res.status(200).json({
      success: true,
      message: 'Password reset successful. Please login with your new password.'
    });

  } catch (error) {
    next(error);
  }
};

// @desc    Change password (for logged in users)
// @route   POST /api/auth/change-password
// @access  Private
exports.changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password
    const user = await User.findById(req.user.id).select('+password');

    // Verify current password
    const isPasswordCorrect = await user.comparePassword(currentPassword);

    if (!isPasswordCorrect) {
      return next(new AppError('Current password is incorrect', 401));
    }

    // Validate new password
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/;
    
    if (!passwordRegex.test(newPassword)) {
      return next(new AppError('Password must contain at least 8 characters, one uppercase, one lowercase, one number and one special character', 400));
    }

    // Check if new password is same as old
    if (currentPassword === newPassword) {
      return next(new AppError('New password must be different from current password', 400));
    }

    // Update password
    user.password = newPassword;
    user.passwordChangedAt = Date.now();
    await user.save();

    // Send confirmation email
    try {
      const emailContent = emailTemplates.passwordChanged(user.firstName);
      await sendEmail({
        email: user.email,
        subject: emailContent.subject,
        html: emailContent.html
      });
    } catch (emailError) {
      console.error('Password changed email failed:', emailError);
    }

    res.status(200).json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    next(error);
  }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    res.status(200).json({
      success: true,
      data: {
        user: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt
        }
      }
    });
  } catch (error) {
    next(error);
  }
};
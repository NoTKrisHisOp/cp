const { body, validationResult } = require('express-validator');
const { AppError } = require('../utils/appError');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(err => err.msg);
    return next(new AppError(errorMessages.join(', '), 400));
  }
  next();
};

// Signup validation
exports.validateSignup = [
  body('firstName')
    .trim()
    .notEmpty().withMessage('First name is required')
    .isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]+$/).withMessage('First name can only contain letters'),
  
  body('lastName')
    .trim()
    .notEmpty().withMessage('Last name is required')
    .isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]+$/).withMessage('Last name can only contain letters'),
  
  body('email')
    .trim()
    .toLowerCase()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email')
    .matches(/^[a-zA-Z0-9._%+-]+@gmail\.com$/).withMessage('Only Gmail addresses are allowed'),
  
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  body('role')
    .optional()
    .isIn(['student', 'graduate', 'professional', 'recruiter'])
    .withMessage('Invalid role selected'),
  
  handleValidationErrors
];

// Login validation
exports.validateLogin = [
  body('email')
    .trim()
    .toLowerCase()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email'),
  
  body('password')
    .notEmpty().withMessage('Password is required'),
  
  handleValidationErrors
];

// Change password validation
exports.validateChangePassword = [
  body('currentPassword')
    .notEmpty().withMessage('Current password is required'),
  
  body('newPassword')
    .notEmpty().withMessage('New password is required')
    .isLength({ min: 8 }).withMessage('New password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  body('newPassword').custom((value, { req }) => {
    if (value === req.body.currentPassword) {
      throw new Error('New password must be different from current password');
    }
    return true;
  }),
  
  handleValidationErrors
];

// Email validation
exports.validateEmail = [
  body('email')
    .trim()
    .toLowerCase()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email')
    .matches(/^[a-zA-Z0-9._%+-]+@gmail\.com$/).withMessage('Only Gmail addresses are allowed'),
  
  handleValidationErrors
];

// Password reset validation
exports.validatePasswordReset = [
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{8,}$/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  handleValidationErrors
];
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { AppError } = require('../utils/appError');

exports.protect = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return next(new AppError('You are not logged in. Please log in to access this resource.', 401));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);

    if (!user) {
      return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    if (user.isLocked) {
      return next(new AppError('Account is temporarily locked. Please try again later.', 423));
    }

    if (user.changedPasswordAfter(decoded.iat)) {
      return next(new AppError('Password was recently changed. Please log in again.', 401));
    }

    req.user = user;
    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return next(new AppError('Invalid token. Please log in again.', 401));
    }
    if (error.name === 'TokenExpiredError') {
      return next(new AppError('Your session has expired. Please log in again.', 401));
    }
    next(error);
  }
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    next();
  };
};

exports.optionalAuth = async (req, res, next) => {
  try {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      return next();
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (user && !user.isLocked && !user.changedPasswordAfter(decoded.iat)) {
      req.user = user;
    }

    next();
  } catch (error) {
    next();
  }
};

exports.requireEmailVerification = (req, res, next) => {
  if (!req.user.isEmailVerified) {
    return next(new AppError('Please verify your email address to access this resource', 403));
  }
  next();
};
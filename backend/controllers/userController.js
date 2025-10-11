const User = require('../models/User');
const { AppError } = require('../utils/appError');

// Filter allowed fields
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
exports.getAllUsers = async (req, res, next) => {
  try {
    const users = await User.find().select('-password -refreshTokens');

    res.status(200).json({
      success: true,
      results: users.length,
      data: { users }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Get single user
// @route   GET /api/users/:id
// @access  Private/Admin
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-password -refreshTokens');

    if (!user) {
      return next(new AppError('User not found', 404));
    }

    res.status(200).json({
      success: true,
      data: { user }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Update user (admin)
// @route   PATCH /api/users/:id
// @access  Private/Admin
exports.updateUser = async (req, res, next) => {
  try {
    // Don't allow password update through this route
    if (req.body.password) {
      return next(new AppError('This route is not for password updates', 400));
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true
      }
    ).select('-password -refreshTokens');

    if (!user) {
      return next(new AppError('User not found', 404));
    }

    res.status(200).json({
      success: true,
      data: { user }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Delete user (admin)
// @route   DELETE /api/users/:id
// @access  Private/Admin
exports.deleteUser = async (req, res, next) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return next(new AppError('User not found', 404));
    }

    res.status(204).json({
      success: true,
      data: null
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Update current user
// @route   PATCH /api/users/update-me
// @access  Private
exports.updateMe = async (req, res, next) => {
  try {
    // Don't allow password update through this route
    if (req.body.password || req.body.passwordConfirm) {
      return next(new AppError('This route is not for password updates. Please use /change-password', 400));
    }

    // Filter allowed fields
    const filteredBody = filterObj(req.body, 'firstName', 'lastName', 'email');

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      filteredBody,
      {
        new: true,
        runValidators: true
      }
    ).select('-password -refreshTokens');

    res.status(200).json({
      success: true,
      data: { user: updatedUser }
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Deactivate current user
// @route   DELETE /api/users/delete-me
// @access  Private
exports.deleteMe = async (req, res, next) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { active: false });

    res.status(204).json({
      success: true,
      data: null
    });
  } catch (error) {
    next(error);
  }
};
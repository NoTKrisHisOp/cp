const express = require('express');
const router = express.Router();
const { protect, restrictTo } = require('../middleware/auth');
const {
  getAllUsers,
  getUser,
  updateUser,
  deleteUser,
  updateMe,
  deleteMe
} = require('../controllers/userController');

// Protect all routes
router.use(protect);

// User self-management
router.patch('/update-me', updateMe);
router.delete('/delete-me', deleteMe);

// Admin only routes
router.use(restrictTo('admin'));

router.route('/')
  .get(getAllUsers);

router.route('/:id')
  .get(getUser)
  .patch(updateUser)
  .delete(deleteUser);

module.exports = router;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please provide first name'],
    trim: true,
    maxlength: [50, 'First name cannot be more than 50 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Please provide last name'],
    trim: true,
    maxlength: [50, 'Last name cannot be more than 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Please provide email address'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^[a-zA-Z0-9._%+-]+@gmail\.com$/,
      'Please provide a valid Gmail address'
    ]
  },
  password: {
    type: String,
    required: [true, 'Please provide password'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false // Don't return password by default
  },
  role: {
    type: String,
    enum: ['student', 'graduate', 'professional', 'recruiter', 'admin'],
    default: 'student'
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpire: Date,
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpire: Date,
  refreshTokens: [{
    token: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 2592000 // 30 days in seconds
    }
  }],
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,
  lastLogin: Date,
  active: {
    type: Boolean,
    default: true,
    select: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Virtual for account lock status
UserSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Indexes for performance
UserSchema.index({ email: 1 });
UserSchema.index({ passwordResetToken: 1 });
UserSchema.index({ emailVerificationToken: 1 });

// Hash password before saving
UserSchema.pre('save', async function(next) {
  // Only hash if password is modified
  if (!this.isModified('password')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
    this.password = await bcrypt.hash(this.password, salt);
    
    // Set passwordChangedAt (but not on new user creation)
    if (!this.isNew) {
      this.passwordChangedAt = Date.now() - 1000; // Subtract 1s to account for processing time
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Update the updatedAt timestamp
UserSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Compare password method
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Generate JWT Access Token
UserSchema.methods.generateAccessToken = function() {
  return jwt.sign(
    { 
      id: this._id,
      email: this.email,
      role: this.role
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// Generate JWT Refresh Token
UserSchema.methods.generateRefreshToken = function() {
  const refreshToken = jwt.sign(
    { id: this._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRE || '30d' }
  );
  
  // Store refresh token in database
  this.refreshTokens.push({ token: refreshToken });
  
  // Keep only last 5 refresh tokens
  if (this.refreshTokens.length > 5) {
    this.refreshTokens = this.refreshTokens.slice(-5);
  }
  
  return refreshToken;
};

// Generate password reset token
UserSchema.methods.generatePasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  // Hash and set to passwordResetToken
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  // Set expire time (10 minutes)
  this.passwordResetExpire = Date.now() + (parseInt(process.env.RESET_PASSWORD_EXPIRE) || 10) * 60 * 1000;
  
  return resetToken;
};

// Generate email verification token
UserSchema.methods.generateEmailVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  
  this.emailVerificationExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  
  return verificationToken;
};

// Increment login attempts
UserSchema.methods.incrementLoginAttempts = async function() {
  // Reset attempts if lock has expired
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return await this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
  const lockTime = (parseInt(process.env.LOCK_TIME) || 15) * 60 * 1000;
  
  // Lock account after max attempts
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
  }
  
  return await this.updateOne(updates);
};

// Reset login attempts
UserSchema.methods.resetLoginAttempts = async function() {
  return await this.updateOne({
    $set: { loginAttempts: 0 },
    $unset: { lockUntil: 1 }
  });
};

// Check if password was changed after token was issued
UserSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Remove refresh token
UserSchema.methods.removeRefreshToken = async function(token) {
  this.refreshTokens = this.refreshTokens.filter(rt => rt.token !== token);
  return await this.save();
};

module.exports = mongoose.model('User', UserSchema);
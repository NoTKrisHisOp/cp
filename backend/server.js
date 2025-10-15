require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const cors = require('cors');

const app = express();
app.use(cors()); // Allow all origins for now 
//app.use(cors({ origin: 'https://your-frontend-domain.com' }));   for connecting with frontend
app.use(express.json());



// --- Configuration ---
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_db';
const PORT = process.env.PORT || 3000;

// --- Database Connection ---
mongoose.connect(MONGODB_URI)
.then(() => console.log('MongoDB connected successfully.'))
.catch(err => {
  console.error('MongoDB connection error:', err.message);
  process.exit(1);
});

// --- Mongoose Schema ---
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: function() { return this.provider === 'local'; }
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  provider: {
    type: String,
    enum: ['local', 'google', 'github'],
    default: 'local',
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true,
  },
  githubId: {
    type: String,
    unique: true,
    sparse: true,
  },
  resetToken: String,
  resetTokenExpiry: Date,
}, {
  timestamps: true // Automatically handles createdAt and updatedAt
});

userSchema.index({ email: 1 });
userSchema.index({ googleId: 1 });
userSchema.index({ githubId: 1 });

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.pre('save', async function(next) {
  if (this.isModified('password') && this.password) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model('User', userSchema);

// --- Middleware & Helpers ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const generateToken = (userId, email) => {
  return jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '7d' });
};

// --- Passport Configuration ---
app.use(passport.initialize());

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        if (!profile.emails || !profile.emails.length) {
          return done(new Error('No email found in Google profile'));
        }
        const email = profile.emails[0].value;
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = await User.findOne({ email });
          if (user) {
            user.googleId = profile.id;
            user.provider = 'google';
            await user.save();
          } else {
            user = await User.create({
              email: email,
              name: profile.displayName,
              googleId: profile.id,
              provider: 'google'
            });
          }
        }
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  ));
  console.log('Google OAuth strategy configured.');
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/github/callback'
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ githubId: profile.id });

        if (!user) {
          const email = profile.emails?.[0]?.value || `${profile.username}@github.com`;
          user = await User.findOne({ email });
          if (user) {
            user.githubId = profile.id;
            user.provider = 'github';
            await user.save();
          } else {
            user = await User.create({
              email,
              name: profile.displayName || profile.username,
              githubId: profile.id,
              provider: 'github'
            });
          }
        }
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  ));
  console.log('GitHub OAuth strategy configured.');
}

// --- API Routes ---
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Auth server is running' });
});

// Traditional Auth Routes
app.post('/api/auth/signup', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('name').trim().notEmpty()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password, name } = req.body;
    if (await User.findOne({ email })) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const user = await User.create({ email, password, name, provider: 'local' });
    const token = generateToken(user._id, user.email);

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user._id, email: user.email, name: user.name }
    });
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email, provider: 'local' });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user._id, user.email);
    res.json({
      message: 'Login successful',
      token,
      user: { id: user._id, email: user.email, name: user.name }
    });
  } catch (error) {
    next(error);
  }
});

// OAuth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'], session: false }));

app.get('/auth/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/auth/failure' }),
  (req, res) => {
    const token = generateToken(req.user._id, req.user.email);
    res.json({
      success: true,
      message: 'Google authentication successful',
      token,
      user: { id: req.user._id, email: req.user.email, name: req.user.name, provider: req.user.provider }
    });
  }
);

app.get('/auth/github/callback',
  passport.authenticate('github', { session: false, failureRedirect: '/auth/failure' }),
  (req, res) => {
    const token = generateToken(req.user._id, req.user.email);
    res.json({
      success: true,
      message: 'GitHub authentication successful',
      token,
      user: { id: req.user._id, email: req.user.email, name: req.user.name, provider: req.user.provider }
    });
  }
);

// Password Management Routes
app.post('/api/auth/change-password', authenticateToken, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 })
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user.userId);

    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.provider !== 'local') return res.status(400).json({ error: 'Cannot change password for OAuth accounts' });
    if (!(await user.comparePassword(currentPassword))) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    user.password = newPassword;
    await user.save();
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    next(error);
  }
});

// User Info Routes
app.get('/api/auth/me', authenticateToken, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    next(error);
  }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logout successful' });
});

app.get('/api/users', async (req, res, next) => { // For debugging
  try {
    const users = await User.find().select('-password');
    res.json({ count: users.length, users });
  } catch (error) {
    next(error);
  }
});

// --- Error Handlers ---
app.get('/auth/failure', (req, res) => {
  res.status(401).json({ error: 'Authentication failed' });
});

app.use((req, res) => { // 404 Handler
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => { // Global Error Handler
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// --- Server Startup ---
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('MongoDB connection closed. Server shutting down.');
  process.exit(0);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
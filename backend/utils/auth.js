const jwt = require('jsonwebtoken');

exports.createSendToken = (user, statusCode, res, rememberMe = false) => {
  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  user.save({ validateBeforeSave: false });

  const accessTokenExpire = rememberMe ? 30 : 7; 
  const refreshTokenExpire = 30;

  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('accessToken', accessToken, {
    ...cookieOptions,
    expires: new Date(Date.now() + accessTokenExpire * 24 * 60 * 60 * 1000)
  });

  res.cookie('refreshToken', refreshToken, {
    ...cookieOptions,
    expires: new Date(Date.now() + refreshTokenExpire * 24 * 60 * 60 * 1000)
  });

  user.password = undefined;

  res.status(statusCode).json({
    success: true,
    token: accessToken,
    refreshToken: refreshToken,
    data: {
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        lastLogin: user.lastLogin
      }
    }
  });
};

exports.verifyToken = (token, secret) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
};
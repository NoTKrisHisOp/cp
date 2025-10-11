
const nodemailer = require('nodemailer');

exports.sendEmail = async (options) => {
  const transporter = nodemailer.createTransporter({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD 
    }
  });

  const mailOptions = {
    from: `Campus Hire <${process.env.EMAIL_FROM || process.env.EMAIL_USERNAME}>`,
    to: options.email,
    subject: options.subject,
    text: options.message,
    html: options.html || `<p>${options.message}</p>`
  };

  await transporter.sendMail(mailOptions);
};

exports.emailTemplates = {
  verification: (verificationUrl, firstName) => ({
    subject: 'Campus Hire - Email Verification',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(90deg, #4f46e5, #3b82f6); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 15px 30px; background: linear-gradient(90deg, #4f46e5, #3b82f6); color: white; text-decoration: none; border-radius: 8px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎓 Campus Hire</h1>
          </div>
          <div class="content">
            <h2>Welcome, ${firstName}!</h2>
            <p>Thank you for signing up with Campus Hire. Please verify your email address to complete your registration.</p>
            <p>Click the button below to verify your email:</p>
            <a href="${verificationUrl}" class="button">Verify Email</a>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #4f46e5;">${verificationUrl}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account with Campus Hire, please ignore this email.</p>
          </div>
          <div class="footer">
            <p>© 2025 Campus Hire. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `
  }),

  passwordReset: (resetUrl, firstName) => ({
    subject: 'Campus Hire - Password Reset Request',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(90deg, #4f46e5, #3b82f6); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .button { display: inline-block; padding: 15px 30px; background: linear-gradient(90deg, #ef4444, #dc2626); color: white; text-decoration: none; border-radius: 8px; margin: 20px 0; }
          .warning { background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎓 Campus Hire</h1>
          </div>
          <div class="content">
            <h2>Password Reset Request</h2>
            <p>Hi ${firstName},</p>
            <p>We received a request to reset your password. Click the button below to set a new password:</p>
            <a href="${resetUrl}" class="button">Reset Password</a>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #4f46e5;">${resetUrl}</p>
            <div class="warning">
              <strong>⚠️ Important:</strong>
              <ul>
                <li>This link will expire in 10 minutes</li>
                <li>If you didn't request a password reset, please ignore this email</li>
                <li>Your password will remain unchanged until you create a new one</li>
              </ul>
            </div>
          </div>
          <div class="footer">
            <p>© 2025 Campus Hire. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `
  }),

  passwordChanged: (firstName) => ({
    subject: 'Campus Hire - Password Changed Successfully',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(90deg, #10b981, #059669); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .success { background: #f0fdf4; border-left: 4px solid #10b981; padding: 15px; margin: 20px 0; }
          .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎓 Campus Hire</h1>
          </div>
          <div class="content">
            <h2>Password Changed Successfully</h2>
            <p>Hi ${firstName},</p>
            <div class="success">
              <p>✓ Your password has been changed successfully.</p>
            </div>
            <p>If you didn't make this change, please contact our support team immediately.</p>
            <p>For security reasons, you have been logged out of all devices. Please log in again with your new password.</p>
          </div>
          <div class="footer">
            <p>© 2025 Campus Hire. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `
  })
};
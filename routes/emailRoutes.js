const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// =======================
// Utilities
// =======================
const CatchAsyncErrors = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

class ErrorHandler extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode || 500;
  }
}

// =======================
// Authentication Middleware
// =======================
const isAuthenticated = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Please login to access this resource" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.id = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: "Authentication failed" });
  }
};

// =======================
// Nodemailer Setup
// =======================
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const sendMailUtility = async (email, url) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Password Reset Request - PapaPet',
    html: `
      <h1>Password Reset Request</h1>
      <p>Please click the link to reset your password:</p>
      <a href="${url}">${url}</a>
      <p>This link will expire in 5 minutes.</p>
    `
  };
  await transporter.sendMail(mailOptions);
};

// =======================
// JWT Token Generator
// =======================
const sendToken = (user, statusCode, res) => {
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_TIME
  });

  res.status(statusCode).json({
    success: true,
    token,
    user
  });
};

// =======================
// Routes
// =======================

// 1️⃣ Send Password Reset Email
router.post('/sendmail', CatchAsyncErrors(async (req, res, next) => {
  const db = mongoose.connection.db;
  const user = await db.collection('users').findOne({ email: req.body.email });
  if (!user) return next(new ErrorHandler("User with this email does not exist", 404));

  const resetToken = crypto.randomBytes(20).toString('hex');
  const resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  await db.collection('users').updateOne(
    { _id: user._id },
    { $set: { resetPasswordToken, resetPasswordExpire: new Date(Date.now() + 5*60*1000) } }
  );

  const url = `http://papapet.in/papapet/auth/forgotpassword/${resetToken}`;
  await sendMailUtility(req.body.email, url);

  res.status(200).json({ message: "Password reset link sent", resetUrl: url });
}));

// 2️⃣ Change Password via Token
router.post('/forgetlink/:token', CatchAsyncErrors(async (req, res, next) => {
  const db = mongoose.connection.db;
  const resetPasswordToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

  const user = await db.collection('users').findOne({
    resetPasswordToken,
    resetPasswordExpire: { $gt: new Date() }
  });

  if (!user) return next(new ErrorHandler("Link expired or invalid", 400));

  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  await db.collection('users').updateOne(
    { _id: user._id },
    { 
      $set: { password: hashedPassword },
      $unset: { resetPasswordToken: "", resetPasswordExpire: "" }
    }
  );

  res.status(200).json({ message: "Password changed successfully" });
}));

// 3️⃣ Reset Password (Logged-in User)
router.post('/reset/password', isAuthenticated, CatchAsyncErrors(async (req, res, next) => {
  const db = mongoose.connection.db;
  const user = await db.collection('users').findOne({ _id: new mongoose.Types.ObjectId(req.id) });
  if (!user) return next(new ErrorHandler("User not found", 404));

  const isMatch = await bcrypt.compare(req.body.oldpassword, user.password);
  if (!isMatch) return next(new ErrorHandler("Wrong password", 400));

  const hashedPassword = await bcrypt.hash(req.body.newpassword, 10);
  await db.collection('users').updateOne(
    { _id: user._id },
    { $set: { password: hashedPassword } }
  );

  sendToken(user, 200, res);
}));

// 4️⃣ Test Email Route
router.post('/test-email', CatchAsyncErrors(async (req, res) => {
  const { email } = req.body;
  await sendMailUtility(email, 'https://papapet.in/');
  res.status(200).json({ success: true, message: "Test email sent successfully" });
}));

module.exports = router;

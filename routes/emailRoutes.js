const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// Error Handler Utility
const CatchAsyncErrors = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Custom error handler
class errorHandler extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
    }
}

// Authentication middleware
const isAuthenticated = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: "Please login to access this resource" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.id = decoded.id;
        next();
    } catch (error) {
        res.status(401).json({ message: "Authentication failed" });
    }
};

// Create nodemailer transporter
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Send email utility function
const sendmail = async (req, res, next, url) => {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: req.body.email,
            subject: 'Password Reset Request - PapaPet',
            html: `
                <h1>Password Reset Request</h1>
                <p>Please click on the following link to reset your password:</p>
                <a href="${url}">${url}</a>
                <p>If you did not request this, please ignore this email.</p>
                <p>This link will expire in 5 minutes.</p>
            `
        };

        await transporter.sendMail(mailOptions);
    } catch (error) {
        return next(new errorHandler("Email could not be sent", 500));
    }
};

// Generate JWT Token
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

// Route handlers
const sendMail = CatchAsyncErrors(async (req, res, next) => {
    const db = mongoose.connection.db;
    const studentData = await db.collection('users').findOne({ email: req.body.email });
    
    if (!studentData) {
        return next(new errorHandler("User with this email does not exist", 404));
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetPasswordToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    // Update user with reset token
    await db.collection('users').updateOne(
        { _id: studentData._id },
        {
            $set: {
                resetPasswordToken: resetPasswordToken,
                resetPasswordExpire: new Date(Date.now() + 300000) // 5 minutes
            }
        }
    );

    // Construct frontend URL with plain token
    const url = `http://papapet.in/papapet/auth/forgotpassword/${resetToken}`;

    // Send email with reset link
    await sendmail(req, res, next, url);

    res.status(200).json({ message: "Password reset link sent", resetUrl: url });
});

const changePassword = CatchAsyncErrors(async (req, res, next) => {
    // Hash token from params to match DB
    const resetPasswordToken = crypto
        .createHash("sha256")
        .update(req.params.token)
        .digest("hex");

    const db = mongoose.connection.db;
    // Find user with valid token and expiry
    const studentData = await db.collection('users').findOne({
        resetPasswordToken: resetPasswordToken,
        resetPasswordExpire: { $gt: new Date() }
    });

    if (!studentData) {
        return res.status(400).json({ message: "Link Expired or Invalid" });
    }

    // Hash new password
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    // Update password and clear token/expiry
    await db.collection('users').updateOne(
        { _id: studentData._id },
        {
            $set: { password: hashedPassword },
            $unset: { 
                resetPasswordToken: "",
                resetPasswordExpire: ""
            }
        }
    );

    res.status(200).json({ message: "Password changed successfully" });
});

const resetPassword = CatchAsyncErrors(async (req, res, next) => {
    console.log(req.body);
    const db = mongoose.connection.db;
    const studentData = await db.collection('users').findOne({ _id: new mongoose.Types.ObjectId(req.id) });

    if (!studentData) {
        return next(new errorHandler("User not found", 404));
    }

    // Compare passwords
    const bcrypt = require('bcryptjs');
    const isMatch = await bcrypt.compare(req.body.oldpassword, studentData.password);

    console.log(studentData);
    if (!isMatch) return next(new errorHandler("Wrong password", 500));

    if (isMatch) {
        // Hash new password
        const hashedPassword = await bcrypt.hash(req.body.newpassword, 10);
        
        // Update password
        await db.collection('users').updateOne(
            { _id: studentData._id },
            { $set: { password: hashedPassword } }
        );

        sendToken(studentData, 201, res);
    }
});

// Test route to verify email functionality
router.post('/test-email', async (req, res) => {
    try {
        const { email } = req.body;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Test Email',
            html: `
                <h1>Test Email</h1>
                <p>This is a test email to verify the email service is working correctly.</p>
            `
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ 
            success: true, 
            message: 'Test email sent successfully' 
        });

    } catch (error) {
        console.error('Test email error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error sending test email' 
        });
    }
});

// Routes
router.post("/sendmail", sendMail);
router.post("/forgetlink/:token", changePassword);
router.post("/reset/password", isAuthenticated, resetPassword);

module.exports = router;
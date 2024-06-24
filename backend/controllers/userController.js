const User = require('../models/User.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const otpGenerator=require('otp-generator')
const nodemailer = require('nodemailer');
require('dotenv').config();
// const transporter = nodemailer.createTransport({
//     host: 'smtp.office365.com',
//     port: 587,
//     secure: false, // true for 465, false for other ports
//     auth: {
//         user: process.env.EMAIL,
//         pass: process.env.EMAIL_PASSWORD
//     }
// });


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD
    }
});

function generateNumericOTP(length) {
    const characters = '0123456789';
    let otp = '';

    for (let i = 0; i < length; i++) {
        otp += characters.charAt(Math.floor(Math.random() * characters.length));
    }

    return otp;
}


const sendOtpEmail = (email, otp) => {
    const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: 'Your OTP Code',
        text: `Your one-time password (OTP) for verifying your account is ${otp}. This code is valid for the next 10  minutes.`
    };
    console.log(`Sending OTP to: ${email}`);

    return transporter.sendMail(mailOptions);
};


exports.registerUser = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Please provide all the information' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password.toString(), 10);
        // const otp = otpGenerator.generate(6, { upperCase: false, specialChars: false });
        // const otp = otpGenerator.generate(6, { digits: true, upperCase: false, specialChars: false });
        // console.log(otp);
        // const otp = otpGenerator.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });
        const otp = generateNumericOTP(6); 
        console.log(otp);


        const otpExpiration = new Date(new Date().getTime() + 2* 60000); // OTP valid for 30 minutes

        const newUser = new User({ name, email, password: hashedPassword, otp, otpExpiration });
        await newUser.save();

        const mailOptions = {
            from: process.env.EMAIL, // Sender address
            to: email, // Recipient address (user's email)
            subject: 'Your OTP Code',
            text: `Your one-time password (OTP) for verifying your account on EduConnect is ${otp}. This code is valid for the next 30 minutes.`
        };

        console.log(`Sending OTP to: ${email}`); // Log the recipient's email

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.error('Error sending email:', error);
                return res.status(500).json({ error: 'Failed to send OTP email' });
            } else {
                console.log('Email sent: ' + info.response);
                res.status(201).json({ message: 'User registered successfully. Please verify your email using the OTP sent.' });
            }
        });
    } catch (error) {
        console.error('Error registering user: ', error);
        res.status(500).json({ error: error.message || 'An error occurred while registering user' });
    }
};

// Controller function to handle user login 
exports.loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (user.otp || user.otpExpiration) {
            return res.status(400).json({ error: 'Please verify your email using the OTP sent' });
        }
        // Compare passwords
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Ensure that the JWT_SECRET is provided and valid
        if (!process.env.JWT_SECRET) {
            return res.status(500).json({ error: 'JWT secret is missing or invalid' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '10h' });
        res.status(200).json({ token });
    } catch (error) {
        console.error('Error logging in user: ', error);
        res.status(500).json({ error: 'An error occurred while logging in user' });
    }
};

// Controller function to get user details
exports.getUserDetails = async (req, res) => {
    try {
        const userId = req.userId;
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ error: 'An error occurred while fetching user details' });
    }
};

// Controller function to update user details
exports.updateUserDetails = async (req, res) => {
    try {
        const userId = req.userId;
        const { name, email } = req.body;
        const updatedUser = await User.findByIdAndUpdate(userId, { name, email }, { new: true });
        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json(updatedUser);
    } catch (error) {
        console.error('Error updating user details: ', error);
        res.status(500).json({ error: 'An error occurred while updating user details ' });
    }
};

// Controller function to delete user account
exports.deleteUserAccount = async (req, res) => {
    try {
        const userId = req.userId;
        const deletedUser = await User.findByIdAndDelete(userId);
        if (!deletedUser) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ message: 'User account deleted successfully' });
    } catch (error) {
        console.error('Error deleting user account:', error);
        res.status(500).json({ error: 'An error occurred while deleting user account' });
    }
};

exports.logoutUser = async (req, res) => {
    try {
        //clear the JWT token on the client-side
        res.clearCookie('token');
        res.status(200).json({ message: 'User logged out successfully' });
    } catch (error) {
        console.error('Error logging out user: ', error);
        res.status(500).json({ error: 'An error occurred while logging out user' });
    }
};

exports.verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        if (user.otpExpiration < new Date()) {
            return res.status(400).json({ error: 'OTP expired' });
        }

        user.otp = undefined;
        user.otpExpiration = undefined;
        await user.save();

        res.status(200).json({ message: 'OTP verified successfully. You can now log in.' });
    } catch (error) {
        console.error('Error verifying OTP: ', error);
        res.status(500).json({ error: error.message || 'An error occurred while verifying OTP' });
    }
};

exports.resendOtp = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Please provide an email address' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const otp = generateNumericOTP(6);
        const otpExpiration = new Date(new Date().getTime() + 2 * 60000); // OTP valid for 2 minutes

        user.otp = otp;
        user.otpExpiration = otpExpiration;
        await user.save();

        await sendOtpEmail(email, otp);
        console.log(`ReSending OTP to: ${email}`);
        console.log(otp);
        res.status(200).json({ message: 'OTP resent successfully. Please check your email.' });
    } catch (error) {
        console.error('Error resending OTP: ', error);
        res.status(500).json({ error: error.message || 'An error occurred while resending OTP' });
    }
};

exports.initiatePasswordReset = async (req, res) => {
    try {
        const { oldPassword, newPassword, confirmNewPassword } = req.body;
        const userId = req.userId;  // Assuming authenticateUser middleware sets req.userId
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify old password
        const isPasswordValid = await bcrypt.compare(oldPassword, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid old password' });
        }

        // Check if new password and confirm new password match
        if (newPassword !== confirmNewPassword) {
            return res.status(400).json({ error: 'New passwords do not match' });
        }

        // Generate OTP
        // const otp = otpGenerator.generate(6, { upperCase: false, specialChars: false });
        const otp = generateNumericOTP(6); 
        console.log(otp);
        const otpExpiration = new Date(new Date().getTime() + 2 * 60000); // OTP valid for 30 minutes

        // Update user with OTP and expiration
        user.otp = otp;
        user.otpExpiration = otpExpiration;
        await user.save();

        const email=user.email;
        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP code for password reset is ${otp}`
        };

        console.log(`Sending OTP to: ${email}`); // Log the recipient's email
        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                return console.error('Error sending email:', error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });

        res.status(200).json({ message: 'OTP sent to email for password reset' });
    } catch (error) {
        console.error('Error initiating password reset: ', error);
        res.status(500).json({ error: error.message || 'An error occurred while initiating password reset' });
    }
};

exports.verifyPasswordResetOtp = async (req, res) => {
    try {
        const { otp, newPassword } = req.body;
        const userId = req.userId;  // Assuming authenticateUser middleware sets req.userId
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        if (user.otpExpiration < new Date()) {
            return res.status(400).json({ error: 'OTP expired' });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword.toString(), 10);

        // Update user password and clear OTP
        user.password = hashedPassword;
        user.otp = undefined;
        user.otpExpiration = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error verifying OTP and resetting password: ', error);
        res.status(500).json({ error: error.message || 'An error occurred while verifying OTP and resetting password' });
    }
};


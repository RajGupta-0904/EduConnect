const Master= require('../models/Master.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const otpGenerator=require('otp-generator')
const nodemailer = require('nodemailer');
const {masterSchema}=require('../validationSchema/masterSchema.js');
require('dotenv').config();

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


exports.masterRegister = async (req, res) => {
    try {
        // Validate request data using zod
        const validationResult = masterSchema.safeParse(req.body);

        if (!validationResult.success) {
            // return res.status(400).json({ error: validationResult.error.errors });
            const errorMessages = validationResult.error.errors.map(err => err.message);
            return res.status(400).json({ errors: errorMessages });
        }

        const { name, email, password, mobile } = validationResult.data;

        const existingMaster = await Master.findOne({ email });
        if (existingMaster) {
            return res.status(400).json({ error: 'Master already exists' });
        }

        const hashedPassword = await bcrypt.hash(password.toString(), 10);
        const otp = generateNumericOTP(6);
        console.log(otp);

        const otpExpiration = new Date(new Date().getTime() + 2 * 60000); // OTP valid for 30 minutes

        const newMaster = new Master({ name, email, password: hashedPassword, otp, otpExpiration, mobile });
        await newMaster.save();

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Your OTP Code',
            text: `Hello ${name}, your one-time password (OTP) for verifying your account on EduConnect is ${otp}. This code is valid for the next 30 minutes.`
        };

        console.log(`Sending OTP to: ${email}`);

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
        console.error('Error registering master: ', error);
        res.status(500).json({ error: error.message || 'An error occurred while registering master' });
    }
};
const mongoose = require('mongoose');


// Define the schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        match: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/ // Email validation regex
    },
    password: {
        type: String,
        required: true,
        minlength: 6 
    },
    otp: {
        type: String,
        required: false
    },
    otpExpiration: {
        type: Date,
        required: false
    },

    // mobile: {
    //     type: String,
    //     required: true,
    //     unique: true,
    //     // match: /^\d{10}$/ // Mobile number validation regex (assuming 10 digit numbers)
    // },
    
});

// Create the model
const User = mongoose.model('User', userSchema);

module.exports = User;

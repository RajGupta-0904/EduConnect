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
    img:{
        type:String,
        required:false

    }

    
});

// Create the model
const User = mongoose.model('User', userSchema);

module.exports = User;

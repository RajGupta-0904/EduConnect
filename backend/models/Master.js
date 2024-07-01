const mongoose = require('mongoose');


// Define the schema
const MasterSchema = new mongoose.Schema({
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
        minlength:6,
    },
    otp: {
        type: String,
        required: false
    },
    otpExpiration: {
        type: Date,
        required: false
    },
    mobile:{
        type:String,
        unique:true,
        maxlength:10
    }

    
},{timestamps:true});

// Create the model
const Master = mongoose.model('Master', MasterSchema);

module.exports = Master;

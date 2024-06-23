const express = require('express');
// const userRoutes = require('./routes/userRoutes');
const userRoutes=require('./routes/userRoutes')

const router = express.Router();

//Mounting routes
router.use(userRoutes);

module.exports = router;
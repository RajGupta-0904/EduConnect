const express = require('express');
const masterRoutes=require('./routes/masterRoutes');
const userRoutes=require('./routes/userRoutes')

const router = express.Router();

//Mounting routes
router.use(userRoutes);
router.use(masterRoutes);

module.exports = router;
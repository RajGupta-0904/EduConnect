const express=require("express");
const router=express.Router();
const masterController=require('../controllers/masterController');

router.post('/masterregister',masterController.masterRegister);

module.exports=router;

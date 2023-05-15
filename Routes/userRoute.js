const router = require('express').Router();
const userController=require('./../Controllers/userController')
const asyncErrorHandler= require('./../Utils/asyncErrorHandler')

router.route('/signup').post(asyncErrorHandler(userController.signup));
router.route('/login').post(asyncErrorHandler(userController.login));

module.exports=router;
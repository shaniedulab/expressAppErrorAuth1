const router = require('express').Router();
const movieController = require('../Controllers/movieController');
const asyncErrorHandler= require('./../Utils/asyncErrorHandler');
const userController = require('./../Controllers/userController');


router.get('/allUsers',asyncErrorHandler(userController.protect), asyncErrorHandler(movieController.getAllUser));

router.get('/oneUsers/:id', asyncErrorHandler(movieController.getOneUser));

router.post('/createUser', asyncErrorHandler(movieController.createUser));

router.put('/updateUser', asyncErrorHandler(movieController.updateUser));

router.delete('/deleteUser', asyncErrorHandler(movieController.deleteUser));

module.exports = router;
const { error } = require('console');
const userModel=require('./../Models/userModel');
const CustomError=require('./../Utils/CustomError');
const jwtToken= require('./../Utils/jwtToken');
const jwt=require('jsonwebtoken');
const util = require('util')

class userController{
    static async signup(req,res,next){
        const newUser=await userModel.create(req.body);

        const token= jwtToken(newUser.id)

        res.status(201).json({
            status:'success',
            token,
            data:newUser
        })
    }

    static async login(req,res,next){
        const email=req.body.email;
        const password=req.body.password;
        // const {email,password}=req.body;
        //check email & password is present in request body.
        if(!email || !password){
            const error=new CustomError('Please provide email Id & password for login in!',400)
            return next(error);
        }

        //check if user exits with given email.
        const user=await userModel.findOne({where:{email}});

        // const isMatch=await userModel.comparePasswordInDb(password,user.password);

        //check user exit and password matchs.
        if(!user || !(await userModel.comparePasswordInDb(password,user.password))){
            console.log("user",await userModel.comparePasswordInDb(password,user.password))
            const error=new CustomError('Incorrect email or Password',400);
            return next(error);
        }

        const token= jwtToken(user.id)

        res.json({
            status:'success',
            token
        })
    }

    static async protect(req,res,next){
        //1. read the token & check if it exits
        const testToken=req.headers.authorization;
        // console.log(req.headers);
        // console.log();
        let token;
        if(testToken && testToken.startsWith("Bearer")){
            token=testToken.split(' ')[1];
        }
        // console.log(token);
        if(!token){
            return next(new CustomError('You are not logged in!',401));
        }
        //2. validate the token 
        const decodedtoken=await util.promisify(jwt.verify)(token,process.env.SECRET_STR);
        // console.log("de",decodedtoken);

        //3. if the usre exits 
        const user=await userModel.findOne({where:{id:decodedtoken.id}});
        // console.log("useruser",user);
        if(!user){
            const err=new CustomError('The user with given Token does not exist',401);
            return next(err);
        }
        //4. if the user changed password ofter the token was issued

        const beforChangedPassword=await userModel.isPasswordChaned(decodedtoken.iat,user.passwordChanedAt);
        if(beforChangedPassword){
            const err = new CustomError('The password has been changed recently. Please login again',401);
            return next(err)
        }
        //5.allow user to access route.
        next();
    }
}


module.exports=userController;
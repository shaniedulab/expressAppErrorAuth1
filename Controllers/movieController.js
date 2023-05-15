const movieModel = require('../Models/movieModel')
const CustomError = require('./../Utils/CustomError')

class movieController{
    static async getAllUser(req,res){
        const user=await movieModel.findAll();
        if(!user){
            const err=new CustomError('User Not Found',404)
            return next(err);
        }
        
        res.json({
            status: 200,
            message:"All User Get Successfully",
            user
        })
    }

    static async getOneUser(req,res,next){
        // console.log(x);
        const user=await movieModel.findOne({
            where:{
                id:req.params.id
            }
        })
        if(!user){
            const err=new CustomError('User with that ID is not found!',404)
            return next(err);
        }

        res.json({
            status: 200,
            message:"One User Get Successfully",
            user
        })
    }

    static async createUser(req,res,next){
        const user = await movieModel.create(req.body);
        res.json({
            status: 201,
            message:"User Created Successfully",
            user
        })
    }

    static async updateUser(req,res,next){
        const user = await movieModel.update(req.body,{
            where:{
                id:req.query.id,
            }
        });
        console.log(user);
        if(!user[0]){
            const err=new CustomError('User with that ID is not found!',404)
            return next(err);
        }
        
        res.json({
            status: 200,
            message:"User Updated Successfully",
            user
        })
    }

    static async deleteUser(req,res,next){
        const user = await movieModel.destroy({
            where:{
                id:req.query.id,
            }
        });
        if(!user){
            const err=new CustomError('User with that ID is not found!',404)
            return next(err);
        }
        
        res.json({
            status: 200,
            message:"User Deleted Successfully",
            user
        })
    }
}

module.exports=movieController;

const jwt=require('jsonwebtoken')

module.exports=(id)=>{
    return jwt.sign({id},process.env.SECRET_STR,{expiresIn:process.env.LOGIN_EXPIRES});
}
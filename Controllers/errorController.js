const CustomError = require('./../Utils/CustomError')

const devError=(res,error)=>{
  res.status(error.statusCode).json({
    status:error.status,
    message:error.message,
    stackTrace: error.stack,
    error:error
  })
}

const prodError=(res,error)=>{
  if(error.isOperational){
    res.status(error.statusCode).json({
      status:error.status,
      message:error.message,
    })
  }else{
    res.status(500).json({
      status: 'error',
      message: 'Something went wrong! Please try again later.'
    })
  }
}

const sequelizeErrorHandler=(error)=>{
  const msg=`Invalid value for filed!`;
  return new CustomError(msg,400)
}

const duplicateKeyErrorHandler=(error)=>{
  const msg=`there is already exit this name`;
  return new CustomError(msg,400)
}

const SequelizeValidationError=(error)=>{
  const errors= Object.values(error.errors.map(val => val.message));
  const errorMessages=errors.join('. ');
  const msg= `Invalid input data ${errorMessages}`
  return new CustomError(msg,400);
}

const handleExpiredJWT=(error)=>{
  return new CustomError('JWT has expired. Please login angin!',401);
}

const handleJWTError=(error)=>{
  return new CustomError('Invalid Token. Please login again!',401);
}

module.exports=(error,req,res,next)=>{
  error.statusCode=error.statusCode || 500;
  error.status=error.status || 'error';

  if(process.env.NODE_ENV=='development'){
    devError(res,error);
  }else if(process.env.NODE_ENV=='production'){
    // let err={...error}
    // if(err.name=='SequelizeValidationError') err = sequelizeErrorHandler(err);
    if(error.name=='SequelizeUniqueConstraintError') error = duplicateKeyErrorHandler(error);
    if(error.name=='SequelizeValidationError') error = SequelizeValidationError(error);
    if(error.name=='TokenExpiredError') error = handleExpiredJWT(error);
    if(error.name==='JsonWebTokenError') error = handleJWTError(error);

    prodError(res,error);
  }
}
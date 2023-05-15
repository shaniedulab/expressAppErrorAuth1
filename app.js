const express = require('express')
const {sequelize} = require('./sequelize')
const movieRoute= require('./Routes/movieRoute')
const userRouter= require('./Routes/userRoute')
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const CustomError = require('./Utils/CustomError')
const globalErrorHandler = require('./Controllers/errorController')
// const swaggerJSDoc = require('swagger-jsdoc');

//swagger setup
// const swaggerDefinition = {
//   openapi: '3.0.0',
//   info: {
//     title: 'Api Documentation',
//     version: '1.0.0',
//     description: 'Documented API for testing.'
//   }
// };

// const options = {
//   swaggerDefinition,
//   apis: ['./Routes/*.js']
// };

// const swaggerSpec = swaggerJSDoc(options);


const app = express()

app.use(express.json())
app.use('/movie',movieRoute)
app.use('/user',userRouter)


sequelize.sync().then(()=>{
  console.log("table created");
}).catch((err)=>{
  console.log("error while creating table");
})

const swaggerDocument = YAML.load('./swagger3.yaml');
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

app.get('/', (req, res) => {
  res.send('Hello World!')
})

//Default Route for Handle Unone Url(end-point)
app.all('*',(req,res,next)=>{
  // res.status(404).json({
  //   status:'fail',
  //   message:`Can't find ${req.originalUrl} on the server!`
  // })
  // const err=new Error(`Can't find ${req.originalUrl} on the server!`);
  // err.status='fail';
  // err.statusCode=404;
  // console.log("err*",err);
  const err=new CustomError(`Can't find ${req.originalUrl} on the server!`,404)
  next(err)
})

//globle error handling meddlelware
app.use(globalErrorHandler);

module.exports=app;
require('dotenv').config({path:'./config.env'})

process.on('uncaughtException',(err)=>{
  console.log(err.name,err.message);
  console.log('Uncaught Exception occured! Shutting down...');
  // server.close(()=>{
    process.exit(1)
  // });
})
const app=require('./app')

const port = process.env.PORT || 9000

const server=app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

process.on('unhandledRejection',(err)=>{
  console.log('Unhandled rejection occured! Shutting down...');
  server.close(()=>{
    process.exit(1);
  })
})




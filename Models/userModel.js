const { parse } = require('yamljs');
const userController = require('../Controllers/userController');
const {sequelize,DataTypes} = require('../sequelize')
const bcryptjs=require('bcryptjs')

const user = sequelize.define('Users', {
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      // unique: true
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
        notNull: {
          msg: 'Please enter your email'
        },
      },
      set(val) {
        this.setDataValue('email', val.toLowerCase());
      }
    },
    photo:{
      type:DataTypes.STRING,
    },
    password:{
      type: DataTypes.STRING,
      allowNull: false,
      validate:{
        isMinLength(value) {
          if (value.length<8) {
            throw new Error('Minimun 8 character allow');
          }
        } 
      } 
    },
    confirmpassword:{
      type: DataTypes.STRING,
      allowNull: false,
      validate:{
        isMatchPassword(value){
          if(value != this.password){
            throw new Error('Password & Confirm Password does not match!');
          }
        }
      }
    },
    passwordChanedAt:{
      type: DataTypes.DATE,
    }
  }, {
    // Other model options go here
  });

  //hash password before hash password //hooks
  user.beforeCreate(async (user, options) => {
    const hashedPassword = await bcryptjs.hash(user.password,12);
    user.password = hashedPassword;
    user.confirmpassword = hashedPassword;
  });
  
  //comparing password 
  user.comparePasswordInDb= async function(pass,passDb){
    return await bcryptjs.compare(pass,passDb);
  }

  user.isPasswordChaned= async function(jwtTime,changTime){
    const pswdChangedTimestemp=parseInt(changTime.getTime()/1000,10);
    // console.log(jwtTime<pswdChangedTimestemp);
    if(jwtTime<pswdChangedTimestemp){
      return true;
    }
    return false;
  }

module.exports= user

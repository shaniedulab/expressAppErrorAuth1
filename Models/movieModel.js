const {sequelize,DataTypes} = require('../sequelize')

const movie = sequelize.define('Movies', {
    firstName: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true
    },
    lastName: {
      type: DataTypes.STRING,
      validate: {
        isEmail: true,
      }
    }
  }, {
    // Other model options go here
  });

module.exports= movie

const {Sequelize,DataTypes} = require('sequelize');
 
const sequelize = new Sequelize('kajal', 'root', 'kajal', {
    host: 'localhost',
    dialect:'mysql',
});

sequelize.authenticate().then(() => {
    console.log('Connection has been established successfully.');
})

module.exports = {sequelize,DataTypes}
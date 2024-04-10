'use strict';

require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

let secret = process.env.SERVER_SECRET

const userSchema = (sequelize, DataTypes) => {
  const model = sequelize.define('User', {
    username: { 
      type: DataTypes.STRING, 
      allowNull: false, 
      unique: true },
    password: { 
      type: DataTypes.STRING, 
      allowNull: false, },
    token: {
      type: DataTypes.VIRTUAL,
      get() {
        return jwt.sign({ username: this.username }, secret);
      }
    }
  });

  model.beforeCreate(async (user) => {
    let hashedPass = await bcrypt.hash(user.password, 10);
    user.password = hashedPass;
  });

  // Basic AUTH: Validating strings (username, password) 
  model.authenticateBasic = async function (username_param, password) {
    const user = await this.findOne({ where: { username: username_param } });
    console.log(user);
    const valid = await bcrypt.compare(password, user.password)
    if (valid) { return user; }
    throw new Error('Invalid User');
  }

  // Bearer AUTH: Validating a token
  model.authenticateToken = async function (token) {
    try {
      const parsedToken = jwt.verify(token, secret);
      const user = await this.findOne({ where: {username: parsedToken.username} })
      if (user) { return user; }
      throw new Error("User Not Found");
    } catch (e) {
      throw new Error(e.message)
    }
  }

  return model;
}

module.exports = userSchema;

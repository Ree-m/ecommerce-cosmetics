const express=require("express")
const app=express()
const passport = require("passport")
const validator = require("validator")
const User = require('../models/User')
const bcrypt = require("bcryptjs")
const localStrategy = require("passport-local").Strategy
const jwt = require("jsonwebtoken")
const cookieParser= require("cookie-parser")


// To hash a password
const saltRounds = 10
const salt = bcrypt.genSaltSync(saltRounds)
const secret = "kj06d8eg4dbklpo3ie3u2x86k047gfbc7ny" //this secret is called a salt!!



app.use(cookieParser())



exports.postLogin = async (req, res, next) => {

  // passport.authenticate("local", (err, user, info) => {
  //   if (err) throw err;
  //   if (!user) res.send("No User Exists");
  //   else {
  //     req.logIn(user, (err) => {
  //       if (err) throw err
  //       res.send("Successfully Authenticated")
  //       console.log(req.user)

  
  //         jwt.sign({ username: req.user.username, email: req.user.email, id: req.user._id }, secret, {}, (err, token) => {
  //           if (err) throw err
  //           res.cookie("token", token).json({  //"token" is set to token fro the parameter
  //             id: req.user._id,
  //             username: req.user.username,
  //             email: req.user.email,
  //           })
  //         })
        

  //     })
  //   }
  // })(req, res, next)
const{username,email,password}=req.body
const userInfo = await User.findOne({username,email})
const passOk= bcrypt.compareSync(password,userInfo.password)

if (passOk) {
  // logged in
  jwt.sign({ username, id: userInfo._id }, secret, {}, (err, token) => { //this token gets used in /profile
      if (err) throw err
      res.cookie("token", token).json({
          id: userInfo._id,
          username,
          email
      })  //'token' is set to token from the parameter
  })
} else {
  // not logged in
  res.status(400).json("wrong credentials")
}

}

exports.postSignup = async (req, res) => {
  // User.findOne({ username: req.body.username }, async (err, doc) => {
  //   if (err) throw err;
  //   if (doc) res.send("User Already Exists")

  //   if (!doc) {
  //     const hashedPassword = await bcrypt.hash(req.body.password, 10);
  //     const { username, email } = req.body
  //     const newUser = new User({
  //       username: username,
  //       password: hashedPassword,
  //       email: email
  //     })
  //     await newUser.save();
  //     res.send("User Created");
  //   }
  // })
  const { username, email,password } = req.body

  const userInfo = new User({
      username: username,
      email:email,
      password: bcrypt.hashSync(password, salt)
  })
  try {
      const userInfoToSave = await userInfo.save()
      res.status(200).json(userInfoToSave);

  } catch (error) {
      console.log(error)
      res.status(400).json({ message: error })
  }
}
exports.getProfile = (req, res) => {
  jwt.verify(req.cookies.token, secret, {}, (error, userInfo) => {
    if (error) throw error
    res.json(userInfo)
  })
}

exports.postLogout = (res, req) => {
  res.cookie("token", "").json("ok") //sets "token" to empty/invalid
}












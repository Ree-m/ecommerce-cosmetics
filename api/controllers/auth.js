const passport = require("passport")
const validator = require("validator")
const User = require('../models/User')
const bcrypt = require("bcryptjs")
const localStrategy = require("passport-local").Strategy


// // To hash a password
// const saltRounds = 10
// const salt = bcrypt.genSaltSync(saltRounds)
// const secret = "kj06d8eg4dbklpo3ie3u2x86k047gfbc7ny" //this secret is called a salt!!

exports.postLogin=async(req,res,next)=>{

  passport.authenticate("local", (err, user, info) => {
    if (err) throw err;
    if (!user) res.send("No User Exists");
    else {
      req.logIn(user, (err) => {
        if (err) throw err
        res.send("Successfully Authenticated")
        console.log(req.user)
      })
    }
  })(req, res, next)

}



exports.postSignup = async (req, res) => {
  User.findOne({ username: req.body.username }, async (err, doc) => {
    if (err) throw err;
    if (doc) res.send("User Already Exists")
    
    if (!doc) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const { username, email} = req.body
      const newUser = new User({
        username: username,
        password: hashedPassword,
        email: email
      })
      await newUser.save();
      res.send("User Created");
    }
  })
}












const express = require("express")
const app = express()
const passport = require("passport")
const localStrategy = require("passport-local").Strategy
const User = require('../models/User')
const jwt = require("jsonwebtoken")
const validator = require("validator")
const bcrypt = require("bcryptjs")
const cookieParser = require("cookie-parser")


// To hash a password
const saltRounds = 10
const salt = bcrypt.genSaltSync(saltRounds)
const secret = "kj06d8eg4dbklpo3ie3u2x86k047gfbc7ny" //this secret is called a salt!!



app.use(cookieParser())

exports.postSignup = async (req, res) => {

  const { username, email, password } = req.body

  const userInfo = new User({
    username: username,
    email: email,
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

exports.postLogin = async (req, res) => {


  const { username, email, password } = req.body
  const userInfo = await User.findOne({ username})
  console.log(userInfo)
  const passOk = bcrypt.compareSync(password, userInfo.password)

  if (passOk) {
    // logged in
    jwt.sign({ username, email,id: userInfo._id }, secret, {}, (err, token) => { //this token gets used in /profile
      if (err) throw err
      res.cookie('token', token).json({
        id: userInfo._id,
        username,
        email
      })  //'token' is set to token from the parameter
    })
    redirect("/")
  }
  else {
    // not logged in
    res.status(400).json("wrong credentials")
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




// exports.signup=
//   passport.authenticate('signup', { session: false }),
//   async (req, res, next) => {
//     res.json({
//       message: 'Signup successful',
//       user: req.user
//     });
//   }


// exports.postLogin= async (req, res, next) => {
//     passport.authenticate(
//       'login',
//       async (err, user, info) => {
//         try {
//           if (err || !user) {
//             const error = new Error('An error occurred.');

//             return next(error);
//           }

//           req.login(
//             user,
//             { session: false },
//             async (error) => {
//               if (error) return next(error);

//               const body = { _id: user._id, email: user.email };
//               const token = jwt.sign({ user: body }, 'TOP_SECRET');

//               return res.json({ token });
//             }
//           );
//         } catch (error) {
//           return next(error);
//         }
//       }
//     )(req, res, next);
//   }

  // exports.getProfile=(req, res, next) => {
  //     res.json({
  //       message: 'You made it to the secure route',
  //       user: req.user,
  //       token: req.query.secret_token
  //     })
  //   }


// exports.login= passport.authenticate('local', {
//   successRedirect: '/',
//   failureRedirect: '/login',
//   failureFlash: true
// })


// exports.signup=async (req, res) => {
  
//     // const hashedPassword = await bcrypt.hash(req.body.password, 10)
//     const userInfo = new User({
//           username: req.body.username,
//           email:req.body.email,
//           password: bcrypt.hashSync(req.body.password, 10)
//         })
//         try {
//           const userInfoToSave = await userInfo.save()
//           res.status(200).json(userInfoToSave);
//           res.redirect('/login')

      
//         } catch (error) {
//           console.log(error)
//           res.status(400).json({ message: error })
//           res.redirect('/signup')

//         }
      
    
// }


// exports.checkAuthenticated=(req, res, next)=> {
//   if (req.isAuthenticated()) {
//     return next()
//   }

//   res.redirect('/login')
// }

// exports.checkNotAuthenticated=(req, res, next) =>{
//   if (req.isAuthenticated()) {
//     return res.redirect('/')
//   }
//   next()
// }


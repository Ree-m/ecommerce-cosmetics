// const User = require("../models/User");
// const passport = require('passport');
// const bcrypt = require("bcryptjs");
// const localStrategy = require("passport-local").Strategy;
// const JWTstrategy = require('passport-jwt').Strategy;
// const ExtractJWT = require('passport-jwt').ExtractJwt;

// passport.use(
//   'signup',
//   new localStrategy(
//     {
//       usernameField: 'email',
//       passwordField: 'password'
//     },
//     async (email, password, done) => {
//       try {
//         const user = await User.create({ email, password });

//         return done(null, user);
//       } catch (error) {
//         done(error);
//       }
//     }
//   )
// )

// passport.use(
//   'login',
//   new localStrategy(
//     {
//       usernameField: 'email',
//       passwordField: 'password'
//     },
//     async (email, password, done) => {
//       try {
//         const user = await User.findOne({ email });

//         if (!user) {
//           return done(null, false, { message: 'User not found' });
//         }

//         const validate = await user.isValidPassword(password);

//         if (!validate) {
//           return done(null, false, { message: 'Wrong Password' });
//         }

//         return done(null, user, { message: 'Logged in Successfully' });
//       } catch (error) {
//         return done(error);
//       }
//     }
//   )
// );

// passport.use(
//   new JWTstrategy(
//     {
//       secretOrKey: 'TOP_SECRET',
//       jwtFromRequest: ExtractJWT.fromUrlQueryParameter('secret_token')
//     },
//     async (token, done) => {
//       try {
//         return done(null, token.user);
//       } catch (error) {
//         done(error);
//       }
//     }
//   )
// );












// // module.exports = function (passport) {
// //   passport.use(
// //     new localStrategy((username, password, done) => {
// //       User.findOne({ username: username }, (err, user) => {
// //         if (err) throw err;
// //         if (!user) return done(null, false);
// //         bcrypt.compare(password, user.password, (err, result) => {
// //           if (err) throw err;
// //           if (result === true) {
// //             return done(null, user);
// //           } else {
// //             return done(null, false);
// //           }
// //         });
// //       });
// //     })
// //   );

// //   passport.serializeUser((user, cb) => {
// //     cb(null, user.id);
// //   });
// //   passport.deserializeUser((id, cb) => {
// //     User.findOne({ _id: id }, (err, user) => {
// //       const userInformation = {
// //         username: user.username,
// //       };
// //       cb(err, userInformation);
// //     });
// //   });
// // };

// const JwtStrategy = require('passport-jwt').Strategy
// const ExtractJwt = require('passport-jwt').ExtractJwt;
// const fs = require('fs')
// const path = require('path')
// const User = require("../models/User");


// const pathToKey = path.join(__dirname, '..', 'id_rsa_pub.pem');
// const PUB_KEY = fs.readFileSync(pathToKey, 'utf8');

// // At a minimum, you must pass the `jwtFromRequest` and `secretOrKey` properties
// const options = {
//   jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
//   secretOrKey: PUB_KEY,
//   algorithms: ['RS256']
// };

// // app.js will pass the global passport object here, and this function will configure it
// module.exports = (passport) => {
//     // The JWT payload is passed into the verify callback
//     passport.use(new JwtStrategy(options, function(jwt_payload, done) {

//         console.log(jwt_payload);
        
//         // We will assign the `sub` property on the JWT to the database ID of user
//         User.findOne({_id: jwt_payload.sub}, function(err, user) {
            
//             // This flow look familiar?  It is the same as when we implemented
//             // the `passport-local` strategy
//             if (err) {
//                 return done(err, false);
//             }
//             if (user) {
//                 return done(null, user);
//             } else {
//                 return done(null, false);
//             }
            
//         });
        
//     }));
// }

const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcryptjs')

function initialize(passport, getUserByEmail, getUserById) {
  const authenticateUser = async (email, password, done) => {
    const user = getUserByEmail(email)
    if (user == null) {
      return done(null, false, { message: 'No user with that email' })
    }

    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user)
      } else {
        return done(null, false, { message: 'Password incorrect' })
      }
    } catch (e) {
      return done(e)
    }
  }

  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
  passport.serializeUser((user, done) => done(null, user.id))
  passport.deserializeUser((id, done) => {
    return done(null, getUserById(id))
  })
}

module.exports = initialize
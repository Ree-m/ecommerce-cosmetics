const express = require("express")
const app = express()
const cors = require("cors")
const cookieParser= require("cookie-parser")
const bodyParser = require("body-parser")
const passport = require("passport")
const session = require("express-session");
const passportLocal = require("passport-local").Strategy;
const mongoose = require("mongoose")
const MongoStore = require("connect-mongo")
const bcrypt = require("bcryptjs")
const flash = require("express-flash");//if password is short,email is invalid,or not confirmed,flash gives us an error message
const logger = require('morgan')
const jwt = require("jsonwebtoken")
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });





// routes
const mainRoutes=require("./routes/main")
const cartRoutes=require("./routes/cart")



// models
const User = require("./models/User")

//Use .env file in config folder
require("dotenv").config({ path: "./config/.env" });

app.use("/uploads", express.static(__dirname + "/uploads"))


const initializePassport = require('./config/passportConfig')
initializePassport(
  passport,
  email => users.find(user => user.email === email),
  id => users.find(user => user.id === id)
)
const users=[]

app.use(cors({ credentials: true, origin: 'http://localhost:5173' }));


// Connect to DataBase 
mongoose.connect(process.env.DB_STRING,console.log("DB is connected"))

// Body Parsing,get data from req.body
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// app.use(express.static(path.join(__dirname, 'public')));


// Setup Sessions - stored in MongoDB
app.use(
    session({
        secret: "keyboard cat",
        resave: false,  // dont save session if unmodified
        saveUninitialized: false,  //dont  create session until something stored
        
    })
)

app.use(cookieParser("secretcode"))

//Passport middleware
app.use(passport.initialize())
app.use(passport.session())
app.use(flash()) //for errors


// Setup Routes
app.use("/",mainRoutes)
app.use("/cart",cartRoutes)

// Plug in the JWT strategy as a middleware so only verified users can access this route.
// app.use('/user', passport.authenticate('jwt', { session: false }), secureRoute);


app.listen(process.env.PORT || 9000,()=>{
    console.log("Server has started")
})


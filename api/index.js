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
// const SQLiteStore = require('connect-sqlite3')(session);




// routes
const mainRoutes=require("./routes/main")
// models
const User = require("./models/User")




//Use .env file in config folder
require("dotenv").config({ path: "./config/.env" });

app.use(cors({ credentials: true, origin: 'http://localhost:5173' }));


// Connect to DataBase 
mongoose.connect(process.env.DB_STRING,console.log("DB is connected"))

// Body Parsing,get data from req.body
// app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// app.use(express.static(path.join(__dirname, 'public')));


// Setup Sessions - stored in MongoDB
app.use(
    session({
        secret: "keyboard cat",
        resave: true,  // save session if unmodified
        saveUninitialized: true,  //  create session until something stored
        
    })
)

app.use(cookieParser("secretcode"))

//Passport middleware
app.use(passport.initialize())
app.use(passport.session())
require("./config/passportConfig")(passport)
app.use(flash()) //for errors


// Setup Routes
app.use("/",mainRoutes)

app.listen(process.env.PORT || 9000,()=>{
    console.log("Server has started")
})


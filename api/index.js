const express = require("express")
const app = express()
const cors = require("cors")
// db
const mongoose = require("mongoose")
// const connectDB = require("../config/database.js")
// const session = require('express-session')
// const MongoStore = require("connect-mongo");
// routes
const mainRoutes=require("./routes/main")
// models
const User = require("./models/User")




//Use .env file in config folder
require("dotenv").config({ path: "../config/.env" });

app.use(cors({ credentials: true, origin: 'http://localhost:5173' }));


// Connect to DataBase 
mongoose.connect(process.env.DB_STRING)

// Body Parsing,get data from req.body
app.use(express.json());

// Setup Sessions - stored in MongoDB
// app.use(
//     session({
//         secret: "keyboard cat",
//         resave: false,  //don't save session if unmodified
//         saveUninitialized: false,  // don't create session until something stored
//         store: MongoStore.create({
//             mongoUrl: process.env.DB_STRING,

//         }),
//     })
// );

// Setup Routes 
app.use("/",mainRoutes)

app.post("/register", async (req, res) => {
    
})


app.listen(9000)
const express =require("express")
const router =express.Router()
const authContoller =require("../controllers/auth")
const passport=require("passport")

router.post("/signup",authContoller.postSignup)
router.post("/login",authContoller.postLogin)



module.exports=router
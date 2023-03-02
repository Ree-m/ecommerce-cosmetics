const express =require("express")
const router =express.Router()
const authContoller =require("../controllers/auth")
const productContoller =require("../controllers/product")
const passport=require("passport")

router.post("/signup",authContoller.postSignup)
router.post("/login",authContoller.postLogin)
router.get("/profile",authContoller.getProfile)
router.post("/logout",authContoller.postLogout)

router.post("/add",productContoller.postAdd)
router.get("/allProducts",productContoller.getAllProducts)
router.get("/product/:id",productContoller.getProduct)



module.exports=router
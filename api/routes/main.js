const express =require("express")
const app=express()
const router =express.Router()
const authContoller =require("../controllers/auth")
const productContoller =require("../controllers/product")
const passport=require("passport")
const multer = require('multer')
const uploadMiddleware = multer({ dest: 'uploads/',limits:{fieldSize:25* 1024 * 1024} })
const fs = require("fs");


app.use("/uploads", express.static(__dirname + "/uploads"))



router.post("/signup",authContoller.postSignup)
router.post("/login",authContoller.postLogin)
router.get("/profile",authContoller.getProfile)
router.post("/logout",authContoller.postLogout)


router.post("/add", uploadMiddleware.single("file"),productContoller.postAdd)
router.get("/allProducts",productContoller.getAllProducts)
router.get("/product/:id",productContoller.getProduct)
router.put("/edit/:id",productContoller.editProduct)
router.delete("/deleteProduct/:id",productContoller.deleteProduct)






module.exports=router
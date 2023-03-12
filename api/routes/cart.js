const express =require("express")
const router =express.Router()
const cartController=require("../controllers/cart")

router.post("/add",cartController.addToCart)
router.delete("/:userId/:productId",cartController.deleteCartItem)

module.exports=router
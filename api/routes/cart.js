const express =require("express")
const router =express.Router()
const cartController=require("../controllers/cart")


router.get("/:userId",cartController.getCart)
router.post("/add",cartController.addToCart)
router.put("/edit/:productId",cartController.editCartItem)
router.delete("/:userId/:productId",cartController.deleteCartItem)

module.exports=router
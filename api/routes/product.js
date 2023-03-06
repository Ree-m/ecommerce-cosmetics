const express =require("express")
const router =express.Router()
const productContoller =require("../controllers/product")

router.post("/add",productContoller.postAdd)
router.get("/allProducts",productContoller.getAllProducts)
router.get("/:id",productContoller.getProduct)
router.put("/edit/:id",productContoller.editProduct)
router.delete("/deleteProduct/:id",productContoller.deleteProduct)





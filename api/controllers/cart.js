const express = require("express")
const app = express()
const Cart = require("../models/Cart")
const Product = require("../models/Product")

// exports.addToCart = async (req, res) => {
//     const userId = req.params.id
//     const { productId, quantity } = req.body

//     try {
//         let cart = await Cart.findOne({ userId });
//         let product = await Product.findOne({ _id: productId })
//         if (!item) {
//             res.status(404).send('Item not found!')
//         }
//         const price = product.price
//         const name = product.name

//         if (cart) {
//             // if cart exists for the user
//             let productIndex = cart.products.findIndex(p => p.productId == productId)

//             // Check if product exists or not
//             if (productIndex > -1) {
//                 let productItem = cart.products[productIndex]
//                 productItem.quantity += quantity
//                 cart.products[productIndex] = productItem
//             }
//             else {
//                 cart.products.push({ productId, name, quantity, price })
//             }
//             cart.bill += quantity * price
//             cart = await cart.save()
//             return res.status(201).send(cart)
//         }
//         else {
//             // no cart exists, create one
//             const newCart = await Cart.create({
//                 userId,
//                 products: [{ productId, name, quantity, price }],
//                 bill: quantity * price
//             });
//             return res.status(201).send(newCart)
//         }
//     }
//     catch (err) {
//         console.log(err)
//         res.status(500).send("Something went wrong")
//     }

// }

// exports.getCart=async(req,res)=>{
//     const userId = req.params.id;
//     try{
//         let cart = await Cart.findOne({userId});
//         if(cart && cart.items.length>0){
//             res.send(cart);
//         }
//         else{
//             res.send(null);
//         }
//     }
//     catch(err){
//         console.log(err);
//         res.status(500).send("Something went wrong");
//     }

// }


const express = require("express")
const CartItem = require("../models/Cart")
const Product = require("../models/Product")


// exports.addToCart = async (req, res) => {
//     const { id } = req.params

//     const {productId} = req.body;
//     const quantity = Number.parseInt(req.body.quantity);
//     try {
//         let carts = await Cart.find().populate({
//             path: "items.productId",
//             select: "name price total"
//         })
//         let cart=carts[0]
//         let productDetails = await Product.findById(productId)
//         if (!productDetails) {
//             return res.status(500).json({
//                 type: "Not Found",
//                 msg: "Invalid request"
//             })
//         }
//         //--If Cart Exists ----
//         if (cart) {
//             //---- Check if index exists ----
//             const indexFound = cart.items.findIndex(item => item.productId.id == productId);
//             //------This removes an item from the the cart if the quantity is set to zero, We can use this method to remove an item from the list  -------
//             if (indexFound !== -1 && quantity <= 0) {
//                 cart.items.splice(indexFound, 1);
//                 if (cart.items.length == 0) {
//                     cart.subTotal = 0;
//                 } else {
//                     cart.subTotal = cart.items.map(item => item.total).reduce((acc, next) => acc + next);
//                 }
//             }
//             //----------Check if product exist, just add the previous quantity with the new quantity and update the total price-------
//             else if (indexFound !== -1) {
//                 cart.items[indexFound].quantity = cart.items[indexFound].quantity + quantity;
//                 cart.items[indexFound].total = cart.items[indexFound].quantity * productDetails.price;
//                 cart.items[indexFound].price = productDetails.price
//                 cart.subTotal = cart.items.map(item => item.total).reduce((acc, next) => acc + next);
//             }
//             //----Check if quantity is greater than 0 then add item to items array ----
//             else if (quantity > 0) {
//                 cart.items.push({
//                     productId: productId,
//                     quantity: quantity,
//                     price: productDetails.price,
//                     total: parseInt(productDetails.price * quantity)
//                 })
//                 cart.subTotal = cart.items.map(item => item.total).reduce((acc, next) => acc + next);
//             }
//             //----If quantity of price is 0 throw the error -------
//             else {
//                 return res.status(400).json({
//                     type: "Invalid",
//                     msg: "Invalid request"
//                 })
//             }
//             let data = await cart.save();
//             res.status(200).json({
//                 type: "success",
//                 mgs: "Process successful",
//                 data: data
//             })
//         }
//         //------------ This creates a new cart and then adds the item to the cart that has been created------------
//         else {
//             const cartData = {
//                 items: [{
//                     productId: productId,
//                     quantity: quantity,
//                     total: parseInt(productDetails.price * quantity),
//                     price: productDetails.price
//                 }],
//                 subTotal: parseInt(productDetails.price * quantity)

//             }
//             // cart = await cartRepository.addItem(cartData)
//             cart= await Cart.create(cartData)
//             // let data = await cart.save();
//             res.json(cart);
//         }
//     } catch (err) {
//         console.log(err)
//         res.status(400).json({
//             type: "Invalid",
//             msg: "Something went wrong",
//             err: err
//         })
//     }
// }





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
exports.getCart = async (req, res) => {
    // Retrieve the cart items for the current user
    const userId = req.body.userId;
    const items = await CartItem.find({ userId });
    res.json(items);
};


// Add an item to the cart
exports.addToCart = (req, res) => {
    // Retrieve the user ID and product ID from the request body
    const userId = req.body.userId;
    const productId = req.body.productId;

    // Check if the item already exists in the cart
    CartItem.findOne({ userId, productId }, (err, cartItem) => {
        if (err) {
            console.error(err);
            res.status(500).send('Internal server error');
        } else if (cartItem) {
            // If the item already exists, increment the quantity
            cartItem.quantity++;
            cartItem.save();
            res.send(cartItem);
        } else {
            // If the item doesn't exist, create a new cart item
            const cartItem = new CartItem({
                userId,
                productId,
                quantity: 1,
            });
            cartItem.save();
            res.send(cartItem);
        }
    });
};



// Remove an item from the cart
exports.deleteCartItem = async (req, res) => {
    const userId = req.params.userId;
    const productId = req.params.productId;

    await CartItem.deleteOne({ userId, productId })
    res.send("cart item deleted")
}


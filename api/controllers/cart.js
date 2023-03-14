const express = require("express")
const CartItem = require("../models/Cart")
const Product = require("../models/Product")


exports.getCart = async (req, res) => {
    // Retrieve the cart items for the current user
    const userId = req.body.userId;
    const items = await CartItem.find({ userId });
    res.json(items);
};


// Add an item to the cart
exports.addToCart = async (req, res) => {
    // Retrieve the user ID and product ID from the request body
    const userId = req.body.userId;
    const productId = req.body.productId;

    console.log(req.body, "this is reqbody")

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
                products: [{
                    productId,
                    name: product.name,
                    price: product.price
                }]
            })
            cartItem.save();
            res.send(cartItem);
    }
    });
    };

//     try {
//         const { userId, productId, quantity } = req.body

//         const product = await Product.findById(productId)

//         // Convert quantity to number using parseInt()
//         const parsedQuantity = parseInt(quantity)

//         if (!product) {
//             return res.status(404).json({ message: "Product not found" })
//         }

//         const cart = await CartItem.findOne({ userId, productId })
//         console.log(cart,"this is cart");

//         if (!cart) {
//             const newCart = new CartItem({
//                 userId,
//                 products: [{
//                     productId,
//                     quantity,
//                     name: product.name,
//                     price: product.price,
//                 }],
//             });

//             await newCart.save();
//             return res.json(newCart);
//         }

//         const existingProduct = cart.products.find((p) => p.productId.equals(productId));
//         if (existingProduct) {
//             // If the cart item already exists, update the quantity

//             cart.products[0].quantity += parsedQuantity;
//         } else {
//             cart.products.push({
//                 productId,
//                 products: [{
//                         productId: productId,
//                         name: product.name,
//                         price: product.price,
//                         quantity: parsedQuantity
//                     }]
//             });
//         }
//         await cart.save();
//         return res.json(cart);
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ message: "Server Error" });
//     }
// };
// try {
//     const { productId, quantity } = req.body;
//     const product = await Product.findById(productId);

//     if (!product) {
//       return res.status(404).json({ message: 'Product not found' });
//     }

//     // Check if the user already has a cart, if not, create a new one
//     let cart = await CartItem.findOne({ userId: req.user._id });

//     if (!cart) {
//       cart = new CartItem({
//         userId: req.user._id,
//         products: [],
//       });
//     }

//     // Check if the product already exists in the cart, if not, add it
//     const productIndex = cart.products.findIndex(
//       (item) => item.productId.toString() === productId
//     );

//     if (productIndex === -1) {
//       cart.products.push({
//         productId,
//         quantity,
//         name: product.name,
//         price: product.price,
//       });
//     } else {
//       cart.products[productIndex].quantity += quantity;
//     }

//     // Save the updated cart
//     await cart.save();

//     res.status(200).json(cart);
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: 'Server error' });
//   }
// }







// try {
//     const { userId, productId, quantity } = req.body;
//     console.log(req.body)

//     // Convert quantity to number using parseInt()
//     const parsedQuantity = parseInt(quantity);

//     const product = await Product.findById(productId);

//     if (!product) {
//         return res.status(404).send('Product not found');
// }

// const cartItem = await CartItem.findOne({ userId, productId });

// if (cartItem) {
//     // If the cart item already exists, update the quantity
//     cartItem.products[0].quantity += parsedQuantity;
// } else {
//     // If the cart item doesn't exist, create a new one
//     const newCartItem = new CartItem({
//         userId,
//         products: [
//             {
//                 productId: productId,
//                 nameOfProduct: product.name,
//                 price: product.price,
//                 quantity: parsedQuantity
//             }
// ]
// });

//         await newCartItem.save();
//         res.json(newCartItem)

//     }
//     res.send('Product added to cart');
// } catch (error) {
//     console.error(error);
//     res.status(500).send('Server error');
// }
//   };








// Edit cart item
exports.editCartItem = async (req, res) => {

    const { productId, quantity } = req.body
    const { userId } = req.params
    const item = await CartItem.findOne({ userId, productId })
    await item.update({
        quantity: quantity
    })
    await item.save()
    res.json(item)
    res.send("cart item edited")
}



// Remove an item from the cart
exports.deleteCartItem = async (req, res) => {
    const userId = req.body.userId;
    const productId = req.body.productId;

    await CartItem.deleteMany({ userId, productId })
    res.send("cart item deleted")
}


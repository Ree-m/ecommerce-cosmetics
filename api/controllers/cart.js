const express = require("express")
const CartItem = require("../models/Cart")
const Product = require("../models/Product")


exports.getCart = async (req, res) => {
  // // Retrieve the cart items for the current user
  const userId = req.body.userId;
  const items = await CartItem.find({ userId });
  res.json(items);

  
};


// Add an item to the cart
exports.addToCart = async (req, res) => {
  try {
    const { userId, productId, quantity, name, price } = req.body;

    // Check if the cart item already exists for this user and product
    const cartItem = await CartItem.findOne({ userId, 'products.productId': productId });

    if (cartItem) {
      // If the cart item exists, update the quantity
      await CartItem.updateOne(
        { _id: cartItem._id, 'products.productId': productId },
        { $inc: { 'products.$.quantity': quantity } }
      );
    } else {
      // If the cart item doesn't exist, create a new one
      const newCartItem = new CartItem({
        userId,
        products: [{ productId, quantity, name, price }],
      });
      await newCartItem.save();
      res.json(newCartItem)

    }
    res.status(200).json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
}










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


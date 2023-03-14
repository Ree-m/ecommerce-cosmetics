const mongoose = require('mongoose');

// const cartItemSchema = new mongoose.Schema({
   

//     userId: {
//         type: String, 
//         required: true
//     },
//     productId: {
//         type: String, 
//         required: true
//     },
//     quantity: {
//         type: Number, 
//         required: true, 
//         min: 1
//     },
// });

// module.exports = mongoose.model('CartItem', cartItemSchema);

const cartItemSchema = new mongoose.Schema({
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    products: [{
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Product",
        required: true,
      },
      quantity: {
        type: Number,
        required: true,
      },
      name: {
        type: String,
        required: true,
      },
      price: {
        type: Number,
        required: true,
      },
    }],
  });
  
  module.exports = mongoose.model('CartItem', cartItemSchema);

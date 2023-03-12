const mongoose = require('mongoose');

const cartItemSchema = new mongoose.Schema({
    userId: {
        type: String, 
        required: true
    },
    productId: {
        type: String, 
        // required: true
    },
    quantity: {
        type: Number, 
        required: true, 
        min: 1
    },
});

module.exports = mongoose.model('CartItem', cartItemSchema);
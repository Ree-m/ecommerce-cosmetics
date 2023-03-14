const mongoose = require("mongoose")


const ProductSchema = new mongoose.Schema({
    // _id: {
    //     type: mongoose.Types.ObjectId,
    //     default: mongoose.Types.ObjectId
    // },
    name: {
        type: String,
        required: true,

    },
    brand: {
        type: String,
        required: true,

    },
    price: {
        type: Number,
        required: true,
    },
    image: {
        type: String,
        required: true
    }
}, {
    timestamps: true
})




module.exports = mongoose.model("Product", ProductSchema)
const mongoose =require("mongoose")

const ProductSchema = new mongoose.Schema({
    name:{
        type:String
    },
    brand:{
        type:String
    },
    price:{
        type:Number
    }
})
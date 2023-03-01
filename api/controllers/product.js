const express = require("express")
const app = express()
const Product = require("../models/Product")
const jwt = require("jsonwebtoken")
const bodyParser = require("body-parser")



exports.postAdd = async (req, res) => {

    const newProduct = await Product.create({
        name: req.body.name,
        brand: req.body.brand,
        price: req.body.price
    })
    res.json(newProduct)



}
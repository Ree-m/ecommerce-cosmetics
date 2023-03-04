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

exports.getAllProducts = async (req, res) => {
    const products = await Product.find()
    res.json(products)
}

exports.getProduct = async (req, res) => {
    const { id } = req.params
    const product = await Product.findById(id)
    console.log(req.params.id)
    res.json(product)

}

exports.editProduct=async(req,res)=>{
    const product = await Product.findById({ _id: req.params.id })
    await product.update({
        name:req.body.name,
        brand:req.body.brand,
        price:req.body.price
    })
    res.json(product)
    

}

exports.deleteProduct = async (req, res) => {
    const product = await Product.findById({ _id: req.params.id })
    await Product.remove({ _id: req.params.id })
    console.log("Product deleted")
    res.redirect("/")

}
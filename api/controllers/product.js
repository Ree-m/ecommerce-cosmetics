const express = require("express")
const app = express()
const Product = require("../models/Product")
const jwt = require("jsonwebtoken")
const bodyParser = require("body-parser")
const fs = require("fs");




exports.postAdd = async (req, res) => {
    const { originalname, path } = req.file

     // In the the uploads folder,i need the images to upload from client side form.
    // For that,the uploaded file (in upload folder) needs the extension,ie,png/jpg/.. etc
    // So i need to grab the extension from req.file.originalname

    const splitFileName = originalname.split(".")  //makes an array of two objects,one is the fle name and the other is the extension name 
    const extension = splitFileName[splitFileName.length - 1]  //gets onlt the extension
    const newPath = path + "." + extension
    fs.renameSync(path, newPath)  //the path ofthe image now has an extension and works.ie.its uploaded in the upload folder and is viewable
    // res.json(extension)  like console.log but in network


    const newProduct = await Product.create({
        name: req.body.name,
        brand: req.body.brand,
        price: req.body.price,
        image:newPath
    })
    newProduct.save()
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
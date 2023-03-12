import { useState } from 'react';
import { Link } from "react-router-dom";

const Product = ({ product, _id, name, brand, price, handleClick }) => {

    async function addToCart(id, quantity) {
        try {
            const response = fetch(`http://localhost:9000/cart/${_id}`, {
                method: "POST",
                body: JSON.stringify({
                    productId: id,
                    quantity: quantity
                }),
                headers: { "Content-Type": "application/json" },
            })
            let data = await response.json()
            alert("Product added to cart")
            console.log(data)

        } catch (error) {
            alert("something went wrong")
            console.log(error)
        }
    }
    return (
        <div className="product">
            <div className="product-title">
                <Link to={`/product/${_id}`}>
                    <h1>{name} from {brand}</h1>
                </Link>
            </div>

            <div className="product-details">
                <span>{price}</span>
            </div>

            <button onClick={() => addToCart(_id, 1)}>Add to cart</button>

        </div>
    );
}

export default Product;
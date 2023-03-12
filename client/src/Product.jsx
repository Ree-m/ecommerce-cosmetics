import {useState} from 'react';
import { Link } from "react-router-dom";

const Product = ({ product,_id,name, brand, price,handleClick }) => {

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

            <button onClick={()=>handleClick(product)}>Add to cart</button>

        </div>
    );
}

export default Product;
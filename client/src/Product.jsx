import { useState } from 'react';
import { Link } from "react-router-dom";

const Product = ({ product, _id, name, brand, price,image }) => {


    return (
        <div className="product">

            <div className="product-image">
                <Link to={`/product/${_id}`}>
                    <img src={`http://localhost:9000/${image}`} alt="Image of this product" />
                </Link>
            </div>
            <div className="product-title">
                <Link to={`/product/${_id}`}>
                    <h1>{name} from {brand}</h1>
                </Link>
            </div>

            <div className="product-details">
                <span>{price}</span>

            </div>


        </div>
    );
}

export default Product;
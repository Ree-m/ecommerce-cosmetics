
import { Link } from "react-router-dom";

const Product = ({ _id, name, brand, price }) => {
// function delete(e){
//     e.preventDefault()

// }
    return (
        <div className="product">
            <div className="product-title">
                <Link to={`/product/${_id}`}>
                    <h1>{name} from {brand}</h1>

                </Link>

            </div>
            <div className="product-details">
                <span>{price}</span>
                <button>delete</button>

            </div>

        </div>
    );
}

export default Product;
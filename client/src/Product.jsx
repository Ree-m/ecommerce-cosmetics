
import { Link } from "react-router-dom";
import { useCart } from "react-use-cart";

const Product = ({ _id, product, name, brand, price }) => {
    const { addItem } = useCart()
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


            </div>
            {/* <div key={_id}>
                <button onClick={() => addItem(product)}>Add to cart</button>
            </div> */}

        </div>
    );
}

export default Product;
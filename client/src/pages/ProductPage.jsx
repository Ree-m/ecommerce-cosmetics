import { useState } from 'react';
import { Navigate, useParams } from 'react-router';
import { useContext } from 'react';
import { UserContext } from '../UserContext';
import { useEffect } from 'react';
import { Link } from 'react-router-dom';

const ProductPage = () => {
    const [product, setProduct] = useState("")
    const [redirect, setRedirect] = useState(false)
    const { id } = useParams()
    const { userInfo } = useContext(UserContext)

    useEffect(() => {
        fetch(`http://localhost:9000/product/${id}`).then(res => {
            res.json().then(product => {
                setProduct(product)
            })
        })
    }, [])
    async function deleteProduct(e) {
        e.preventDefault()

        const response = fetch(`http://localhost:9000/deleteProduct/${id}`, {
            method: "DELETE"
        })
        setRedirect(true)
        console.log(response)

    }
    if (redirect) {
        return <Navigate to={"/"} />
    }
    if (!product) return ""

    return (
        <div className="product-page">
            <div className="product-title">
                <h1>{product.name} from {product.brand}</h1>
            </div>

            <div className="product-details">
                <span>{product.price}</span>
            </div>

            {userInfo && userInfo.username === "reemreem" && (
                <button onClick={deleteProduct}>delete</button>

            )}
            {userInfo && userInfo.username === "reemreem" && (
                <div className="edit-row">
                    <Link className="edit-btn" to={`/edit/${product._id}`}>
                        {/* <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                        </svg> */}

                        Edit this product
                    </Link>

                </div>

            )}

        </div>
    );
}

export default ProductPage;
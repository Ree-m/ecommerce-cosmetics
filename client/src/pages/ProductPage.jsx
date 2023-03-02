
import { useState } from 'react';
import { useParams } from 'react-router';
import { useContext } from 'react';
import { UserContext } from '../UserContext';
import { useEffect } from 'react';

const ProductPage = () => {
    const [product,setProduct]=useState("")
    const {id}=useParams()
    const {userInfo} =useContext(UserContext)

    useEffect(()=>{
        fetch(`http://localhost:9000/product/${id}`).then(res=>{
            res.json().then(product=>{
                setProduct(product)
            })
        })
    },[])
    return ( 
        <div className="product-page">
            <div className="product-title">
            <h1>{product.name} from {product.brand}</h1>
            </div>

            <div className="product-details">
                <span>{product.price}</span>
            </div>

        </div>
     );
}
 
export default ProductPage;

import { useState } from 'react';
import { Navigate, useParams } from 'react-router';
import { useContext } from 'react';
import { UserContext } from '../UserContext';
import { useEffect } from 'react';

const ProductPage = () => {
    const [product,setProduct]=useState("")
    const [redirect,setRedirect]=useState(false)
    const {id}=useParams()
    const {userInfo} =useContext(UserContext)

    useEffect(()=>{
        fetch(`http://localhost:9000/product/${id}`).then(res=>{
            res.json().then(product=>{
                setProduct(product)
            })
        })
    },[])
   async function deleteProduct(e){
        e.preventDefault()
        
        const response=fetch(`http://localhost:9000/deleteProduct/${id}`,{
            method:"DELETE"
        })
        setRedirect(true)
        console.log(response)

    }
    if(redirect){
        return <Navigate to={"/"} />
    }
    return ( 
        <div className="product-page">
            <div className="product-title">
            <h1>{product.name} from {product.brand}</h1>
            </div>

            <div className="product-details">
                <span>{product.price}</span>
            </div>

            <button onClick={deleteProduct}>delete</button>

        </div>
     );
}
 
export default ProductPage;
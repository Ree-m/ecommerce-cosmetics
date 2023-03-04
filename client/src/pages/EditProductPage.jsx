import { useState,useEffect } from "react"
import { Navigate, useParams } from "react-router"

const EditProduct = () => {
    const {id}=useParams()
    const [name,setName]=useState("")
    const [brand, setBrand] = useState("")
    const [price, setPrice] = useState("")
    const [redirect,setRedirect]=useState(false)
// useEffect(()=>{
//     fetch(`http://localhost:9000/product/${id}`).then(res=>{
//         res.json()
//         .then(product=>{
//             setName(product.name)
//             setBrand(product.brand)
//             setPrice(product.price)
//         })
//     })
// })

    async function updateProduct(e){
        e.preventDefault()
      const response= fetch(`http://localhost:9000/edit/${id}`,{
            method:"PUT",
            body:JSON.stringify({name,brand,price}),
            headers:{"Content-Type":"application/json"},
            credentials:"include"
        })
        if((await response).ok){
            setRedirect(true)
        }
    }
    if(redirect){
        return <Navigate to={`/product/${id}`} />
    }

    return (
        <div className="edit-product">
            <h1>Edit Product</h1>
            <form onSubmit={updateProduct}>
                <input type="text"
                    placeholder="name"
                    vaue={name}
                    onChange={(e) => setName(e.target.value)} />

                <input type="text"
                    placeholder="brand"
                    vaue={brand}
                    onChange={(e) => setBrand(e.target.value)} />

                <input type="number"
                    placeholder="price"
                    vaue={price}
                    onChange={(e) => setPrice(e.target.value)} />

                    <button>Edit product</button>
            </form>
        </div>
    );
}

export default EditProduct;
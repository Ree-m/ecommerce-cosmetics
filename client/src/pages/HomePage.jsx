import { useState, useEffect } from "react"
import Product from "../Product"


const HomePage = ({handleClick}) => {
    const [products, setProducts] = useState([])


    useEffect(() => {
        fetch("http://localhost:9000/allProducts")
            .then(res => {
                res.json()
                    .then(products => {
                        setProducts(products)
                    })
            })
    }, [])


// function handleClick(product){
//     setCart([...cart,product])
//     console.log(cart)

// }


    return (
        <div className="home-page">
            {products && products.length > 0 && products.map(product => (
                <div key={product._id}>
                    <Product product={product} {...product} handleClick={handleClick}/>
                </div>
            ))
            }
        </div >


    );
}

export default HomePage;
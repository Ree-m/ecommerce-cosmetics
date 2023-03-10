import { useState, useEffect } from "react"
import Product from "../Product"


const HomePage = () => {
    const [products, setProducts] = useState([])

    useEffect(() => {
        fetch("http://localhost:9000/allProducts")
            .then(res => {
                res.json()
                    .then(products => {
                        setProducts(products)
                        // console.log("this is products",products)
                    })
            })
    }, [])





    return (
        <div className="home-page">
            {products && products.length > 0 && products.map(product => (
                <div key={product._id}>
                    <Product  {...product} />
                </div>
            ))
            }
        </div >


    );
}

export default HomePage;
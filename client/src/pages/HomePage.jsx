import { useState ,useEffect} from "react"
import Product from "../Product"


const HomePage = () => {
    const [products,setProducts]=useState([])

    useEffect(()=>{
        fetch("http://localhost:9000/product/allProducts")
        .then(res=>{
            res.json()
            .then(products=>{
                setProducts(products)
                // console.log("this is products",products)
            })
        })
    },[])
    
    



    return ( 
        <div className="home-page">
            {products && products.length > 0 &&  products.map(product=>(
                <Product {...product}/>
            ))}
        </div>
        

     );
}
 
export default HomePage;
import { useState } from "react"

const AddPage = () => {
    const [name, setName] = useState("")
    const [brand, setBrand] = useState("")
    const [price, setPrice] = useState("")
    function addProduct(e) {
        e.preventDefault()
        console.log("add")
        const data = new FormData()
        data.set("name",name)
        data.set("brand",brand)
        data.set("price",price)
        const response =fetch("http://localhost:9000/add",{
            method:"POST",
            body:data,
            credentials:"include",

        })
        console.log(response)
    }


    return (
        <div>
            <h1>Add new product</h1>

            <form onSubmit={addProduct}>
                <input type="text"
                    placeholder="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)} />

                <input type="text"
                    placeholder="brand"
                    value={brand}
                    onChange={(e) => setBrand(e.target.value)} />

                <input type="number"
                    placeholder="price"
                    value={price}
                    onChange={(e) => setPrice(e.target.value)} />

                <button className="btn">Add product</button>

            </form>

        </div>

    );
}

export default AddPage;